#!/usr/bin/env python3
"""
CaumeDSE compliance audit dashboard sample.

Parses structured CaumeDSE AuditJSON service-log lines and optional
live-api-coverage.csv verifier artifacts, then produces redacted JSON or a
static HTML report. Uses only Python's standard library.
"""

import argparse
import csv
import html
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path


SAMPLE_DIR = Path(__file__).resolve().parent
DEFAULT_AUDIT_LOG = SAMPLE_DIR / "fixtures" / "audit.log"
DEFAULT_COVERAGE = SAMPLE_DIR / "fixtures" / "live-api-coverage.csv"
AUDIT_PREFIX = "CaumeDSE AuditJSON: "
SENSITIVE_KEYS = {
    "orgKey",
    "newOrgKey",
    "authorization",
    "certificate",
    "privateKey",
    "clientKey",
    "accessPassword",
    "oauthConsumerSecret",
}
SECRET_PATTERNS = [
    (re.compile(r"(?i)(orgKey|newOrgKey|accessPassword|oauthConsumerSecret)=([^&\s\"]+)"), r"\1=<redacted>"),
    (re.compile(r"(?i)Authorization:\s*Bearer\s+[A-Za-z0-9._~-]+"), "Authorization: Bearer <redacted>"),
    (re.compile(r"[^\"'\s]+/(?:[^\"'\s/]+/)*[^\"'\s]+\.(?:key|pem|p12|srl|req|cnf)"), "<redacted-cert-path>"),
]
BROAD_READ_FEATURE_HINTS = ("content", "contentRows", "document_content", "db_table")
BROAD_READ_ROUTE_HINTS = ("/content?", "/contentRows", "/dbNames/")


class DashboardError(Exception):
    pass


def redact_value(value):
    if isinstance(value, dict):
        return {key: ("<redacted>" if key in SENSITIVE_KEYS else redact_value(val)) for key, val in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if not isinstance(value, str):
        return value
    text = value
    for pattern, replacement in SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def iter_audit_events(path):
    with Path(path).open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, 1):
            if AUDIT_PREFIX not in line:
                continue
            payload = line.split(AUDIT_PREFIX, 1)[1].strip()
            if not payload.startswith("{"):
                continue
            try:
                event, _ = json.JSONDecoder().raw_decode(payload)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            if event.get("auditSchemaVersion") != 1 or event.get("safeForAgent") is not True:
                continue
            event = redact_value(event)
            event["_source"] = str(path)
            event["_line"] = line_no
            yield event


def load_coverage(path):
    if not path:
        return []
    path = Path(path)
    if not path.exists():
        return []
    rows = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            rows.append(redact_value(dict(row)))
    return rows


def event_key(event):
    return {
        "requestId": event.get("requestId"),
        "category": event.get("category", "unknown"),
        "event": event.get("event", "unknown"),
        "outcome": event.get("outcome", "unknown"),
        "userId": event.get("userId"),
        "orgId": event.get("orgId"),
        "storageId": event.get("storageId"),
        "documentId": event.get("documentId"),
        "parserScriptId": event.get("parserScriptId"),
        "method": event.get("method"),
        "route": event.get("route"),
        "result": event.get("result"),
        "reason": event.get("reason"),
    }


def is_denied(event):
    return str(event.get("outcome", "")).lower() in {"deny", "denied", "fail"} or str(event.get("event", "")).endswith("-deny")


def is_cleanup_failure(event):
    return event.get("category") == "cleanup" and (is_denied(event) or "fail" in str(event.get("event", "")).lower())


def is_broad_read_event(event):
    route = str(event.get("route", ""))
    method = str(event.get("method", "")).upper()
    if method and method != "GET":
        return False
    return any(hint in route for hint in BROAD_READ_ROUTE_HINTS)


def is_broad_read_coverage(row):
    feature = str(row.get("feature", ""))
    method = str(row.get("method", "")).upper()
    if method and method != "GET":
        return False
    return any(hint in feature for hint in BROAD_READ_FEATURE_HINTS)


def summarize(events, coverage_rows):
    categories = Counter(str(event.get("category", "unknown")) for event in events)
    outcomes = Counter(str(event.get("outcome", "unknown")) for event in events)
    by_user = Counter(str(event.get("userId", "unknown")) for event in events)
    by_request = defaultdict(list)
    for event in events:
        request_id = event.get("requestId") or "<none>"
        by_request[request_id].append(event_key(event))

    denied = [event_key(event) for event in events if is_denied(event)]
    parser_policy_denials = [
        event_key(event) for event in events if event.get("category") == "parserPolicy" and is_denied(event)
    ]
    parser_execution_issues = [
        event_key(event) for event in events if event.get("category") == "parserExecution" and is_denied(event)
    ]
    cleanup_failures = [event_key(event) for event in events if is_cleanup_failure(event)]
    broad_reads = [event_key(event) for event in events if is_broad_read_event(event)]
    failed_coverage = [row for row in coverage_rows if str(row.get("status", "")).upper() == "FAIL"]
    broad_read_coverage = [row for row in coverage_rows if is_broad_read_coverage(row)]

    return {
        "schemaVersion": 1,
        "safeForAgent": True,
        "eventCount": len(events),
        "coverageCount": len(coverage_rows),
        "categories": dict(sorted(categories.items())),
        "outcomes": dict(sorted(outcomes.items())),
        "users": dict(sorted(by_user.items())),
        "requestGroups": {key: value for key, value in sorted(by_request.items())},
        "findings": {
            "deniedEvents": denied,
            "parserPolicyDenials": parser_policy_denials,
            "parserExecutionIssues": parser_execution_issues,
            "cleanupFailures": cleanup_failures,
            "broadReadEvents": broad_reads,
            "failedCoverage": failed_coverage,
            "broadReadCoverage": broad_read_coverage,
        },
    }


def assert_no_secret_markers(data):
    text = json.dumps(data, sort_keys=True)
    forbidden = ("Authorization: Bearer ", "orgKey=", "newOrgKey=", "PRIVATE KEY", ".pem", ".key")
    leaks = [marker for marker in forbidden if marker in text]
    if leaks:
        raise DashboardError(f"redacted output still contains sensitive markers: {', '.join(leaks)}")


def render_table(rows, columns):
    if not rows:
        return "<p>None</p>"
    header = "".join(f"<th>{html.escape(column)}</th>" for column in columns)
    body = []
    for row in rows:
        body.append(
            "<tr>"
            + "".join(f"<td>{html.escape(str(row.get(column, '')))}</td>" for column in columns)
            + "</tr>"
        )
    return f"<table><thead><tr>{header}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def render_html(report):
    findings = report["findings"]
    cards = [
        ("Events", report["eventCount"]),
        ("Coverage Rows", report["coverageCount"]),
        ("Denied Events", len(findings["deniedEvents"])),
        ("Parser Policy Denials", len(findings["parserPolicyDenials"])),
        ("Cleanup Failures", len(findings["cleanupFailures"])),
        ("Failed Coverage", len(findings["failedCoverage"])),
    ]
    card_html = "".join(
        f"<section class='card'><h2>{html.escape(label)}</h2><strong>{count}</strong></section>"
        for label, count in cards
    )
    event_columns = ["category", "event", "outcome", "reason", "requestId", "userId", "documentId", "parserScriptId"]
    coverage_columns = ["protocol", "feature", "method", "expected_status", "actual_status", "status", "marker"]
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>CaumeDSE Audit Dashboard</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #17202a; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: .75rem; }}
    .card {{ border: 1px solid #ccd4dd; border-radius: 6px; padding: .75rem; }}
    .card h2 {{ font-size: .9rem; margin: 0 0 .5rem; }}
    .card strong {{ font-size: 1.6rem; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0 2rem; }}
    th, td {{ border: 1px solid #d9dee5; padding: .4rem; text-align: left; vertical-align: top; }}
    th {{ background: #eef2f6; }}
    pre {{ background: #f5f7f9; padding: 1rem; overflow: auto; }}
  </style>
</head>
<body>
  <h1>CaumeDSE Audit Dashboard</h1>
  <div class="cards">{card_html}</div>
  <h2>Denied Events</h2>
  {render_table(findings["deniedEvents"], event_columns)}
  <h2>Parser Policy Denials</h2>
  {render_table(findings["parserPolicyDenials"], event_columns)}
  <h2>Parser Execution Issues</h2>
  {render_table(findings["parserExecutionIssues"], event_columns)}
  <h2>Cleanup Failures</h2>
  {render_table(findings["cleanupFailures"], event_columns)}
  <h2>Failed Coverage</h2>
  {render_table(findings["failedCoverage"], coverage_columns)}
  <h2>Category Counts</h2>
  <pre>{html.escape(json.dumps(report["categories"], indent=2, sort_keys=True))}</pre>
</body>
</html>"""


def build_report(args):
    events = []
    for path in args.audit_log:
        events.extend(iter_audit_events(Path(path)))
    coverage_rows = load_coverage(args.coverage)
    report = summarize(events, coverage_rows)
    assert_no_secret_markers(report)
    return report


def self_test(_args):
    class Args:
        audit_log = [DEFAULT_AUDIT_LOG]
        coverage = DEFAULT_COVERAGE

    report = build_report(Args)
    findings = report["findings"]
    if report["eventCount"] != 6:
        raise DashboardError("unexpected audit fixture event count")
    if len(findings["parserPolicyDenials"]) != 1:
        raise DashboardError("parser policy denial was not detected")
    if len(findings["parserExecutionIssues"]) != 1:
        raise DashboardError("parser execution issue was not detected")
    if len(findings["cleanupFailures"]) != 1:
        raise DashboardError("cleanup failure was not detected")
    if len(findings["failedCoverage"]) != 1:
        raise DashboardError("failed coverage row was not detected")
    html_report = render_html(report)
    if "CaumeDSE Audit Dashboard" not in html_report:
        raise DashboardError("HTML report did not render expected title")
    print("PASS audit dashboard self-test")


def build_parser():
    parser = argparse.ArgumentParser(description="CaumeDSE audit dashboard sample")
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ("json", "html"):
        cmd = sub.add_parser(name, help=f"Render {name} report.")
        cmd.add_argument("audit_log", nargs="+", type=Path)
        cmd.add_argument("--coverage", type=Path)
        cmd.add_argument("--output", type=Path)

    sub.add_parser("self-test", help="Run fixture-based parser/report checks.")
    return parser


def write_output(text, output):
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
    else:
        print(text)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "self-test":
            self_test(args)
            return 0
        report = build_report(args)
        if args.command == "json":
            write_output(json.dumps(report, indent=2, sort_keys=True), args.output)
        elif args.command == "html":
            write_output(render_html(report), args.output)
    except DashboardError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
