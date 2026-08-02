#!/usr/bin/env python3
"""
CaumeDSE secure document review workspace sample.

This sample keeps CaumeDSE credentials in environment variables while exposing
only bounded document review, parser preview, approve/reject, audit export, and
cleanup actions. It uses only Python's standard library.
"""

import argparse
import csv
import html
import json
import mimetypes
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


SAMPLE_DIR = Path(__file__).resolve().parent
DEFAULT_CSV = SAMPLE_DIR / "fixtures" / "review-data.csv"
DEFAULT_SAFE_PARSER = SAMPLE_DIR / "fixtures" / "safe_parser.py"
DEFAULT_UNSAFE_PARSER = SAMPLE_DIR / "fixtures" / "unsafe_parser.py"
DEFAULT_STATE = Path(os.environ.get("CDSE_REVIEW_STATE", "/tmp/caumedse-review-workspace-state.json"))
MAX_PREVIEW_ROWS = 5
FORBIDDEN_SCRIPT_PATTERNS = {
    "environment access": r"\bos\.environ\b|\bgetenv\s*\(",
    "shell execution": r"\bsubprocess\b|\bos\.system\s*\(|\bpopen\s*\(",
    "network access": r"\bsocket\b|\burllib\b|\brequests\b|\bhttp\.client\b",
    "dynamic code": r"\beval\s*\(|\bexec\s*\(|\b__import__\s*\(",
    "arbitrary file write": r"\bopen\s*\([^,\n]+,\s*['\"][wa+]",
}


class ReviewError(Exception):
    pass


class Config:
    def __init__(self):
        run_id = os.environ.get("CDSE_REVIEW_RUN_ID") or str(int(time.time()))
        self.base_url = os.environ.get("CDSE_REVIEW_BASE_URL", "http://localhost:18080").rstrip("/")
        self.org = os.environ.get("CDSE_REVIEW_ORG", f"ReviewOrg{run_id}")
        self.user = os.environ.get("CDSE_REVIEW_USER", f"ReviewUser{run_id}")
        self.storage = os.environ.get("CDSE_REVIEW_STORAGE", f"ReviewStorage{run_id}")
        self.storage_path = os.environ.get("CDSE_REVIEW_STORAGE_PATH", f"/tmp/caumedse-review-storage-{run_id}")
        self.org_key = os.environ.get("CDSE_REVIEW_ORG_KEY")
        self.csv_doc = os.environ.get("CDSE_REVIEW_CSV_DOC", f"review-{run_id}.csv")
        self.parser_doc = os.environ.get("CDSE_REVIEW_PARSER_DOC", f"review-parser-{run_id}.py")
        self.ca_cert = os.environ.get("CDSE_REVIEW_CA_CERT")
        self.client_cert = os.environ.get("CDSE_REVIEW_CLIENT_CERT")
        self.client_key = os.environ.get("CDSE_REVIEW_CLIENT_KEY")

    def auth_params(self, include_new_key=True):
        if not self.org_key:
            raise ReviewError("Set CDSE_REVIEW_ORG_KEY in the environment for live mode.")
        params = {"userId": self.user, "orgId": self.org, "orgKey": self.org_key}
        if include_new_key:
            params["newOrgKey"] = self.org_key
        return params


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def quote_path(value):
    return urllib.parse.quote(str(value), safe="")


def encode_query(params):
    return urllib.parse.urlencode(params, doseq=True, safe="*[]")


def redact_url(url):
    parsed = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    redacted = []
    for key, value in pairs:
        if key in {"orgKey", "newOrgKey", "*accessPassword", "*oauthConsumerSecret"}:
            value = "<redacted>"
        redacted.append((key, value))
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(redacted), parsed.fragment)
    )


def ssl_context(cfg):
    if not cfg.base_url.startswith("https://"):
        return None
    context = ssl.create_default_context(cafile=cfg.ca_cert) if cfg.ca_cert else ssl.create_default_context()
    if cfg.client_cert and cfg.client_key:
        context.load_cert_chain(cfg.client_cert, cfg.client_key)
    return context


def request(cfg, method, path, params=None, body=None, headers=None, expected=(200,)):
    query = encode_query(params or {})
    url = f"{cfg.base_url}{path}"
    if query:
        url = f"{url}?{query}"
    print(f"{method:<6} {redact_url(url)}", file=sys.stderr)
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, context=ssl_context(cfg), timeout=30) as response:
            payload = response.read()
            status = response.status
            response_headers = dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        status = exc.code
        response_headers = dict(exc.headers.items())
    if status not in expected:
        text = payload.decode("utf-8", errors="replace")
        raise ReviewError(f"{method} {path} returned {status}, expected {expected}: {text[:500]}")
    return status, response_headers, payload


def json_request(cfg, path, params, limit=1, offset=0):
    query = dict(params)
    query["outputType"] = "json"
    query["limit"] = str(limit)
    query["offset"] = str(offset)
    _, headers, payload = request(cfg, "GET", path, params=query)
    return headers, json.loads(payload.decode("utf-8"))


def multipart_body(fields, file_path):
    boundary = f"cdse-review-{int(time.time() * 1000)}"
    chunks = []
    for name, value in fields.items():
        chunks.append(f"--{boundary}\r\n")
        chunks.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n')
        chunks.append(f"{value}\r\n")
    mime_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
    chunks.append(f"--{boundary}\r\n")
    chunks.append(f'Content-Disposition: form-data; name="file"; filename="{file_path.name}"\r\n')
    chunks.append(f"Content-Type: {mime_type}\r\n\r\n")
    body = "".join(chunks).encode("utf-8") + file_path.read_bytes()
    body += f"\r\n--{boundary}--\r\n".encode("utf-8")
    return body, {"Content-Type": f"multipart/form-data; boundary={boundary}"}


def base_document_path(cfg, doc_type, doc_name):
    return (
        f"/organizations/{quote_path(cfg.org)}"
        f"/storage/{quote_path(cfg.storage)}"
        f"/documentTypes/{quote_path(doc_type)}"
        f"/documents/{quote_path(doc_name)}"
    )


def load_state(path=DEFAULT_STATE):
    if not Path(path).exists() or Path(path).stat().st_size == 0:
        return {"schemaVersion": 1, "workspace": {}, "reviews": [], "audit": []}
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def save_state(state, path=DEFAULT_STATE):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with Path(path).open("w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.chmod(path, 0o600)


def add_audit(state, category, action, result, **fields):
    event = {
        "time": now_iso(),
        "category": category,
        "action": action,
        "result": result,
        **fields,
    }
    state.setdefault("audit", []).append(event)
    return event


def read_csv_preview(path, limit=MAX_PREVIEW_ROWS):
    rows = []
    with Path(path).open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        columns = reader.fieldnames or []
        for row in reader:
            rows.append({column: row.get(column, "") for column in columns})
            if len(rows) >= limit:
                break
    return {"columns": columns, "rows": rows, "rowPreviewCount": len(rows)}


def static_script_review(path):
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    findings = []
    for label, pattern in FORBIDDEN_SCRIPT_PATTERNS.items():
        if re.search(pattern, text):
            findings.append(label)
    return {
        "safeForPreview": not findings,
        "findings": findings,
        "checkedPatterns": sorted(FORBIDDEN_SCRIPT_PATTERNS),
    }


def review_metadata(status, reviewer, notes=None):
    status = status.lower()
    if status == "approved":
        return (
            "reviewed workspace parser parser.reviewStatus:reviewed "
            "parser.reviewed:true "
            f"parser.reviewer:{reviewer} parser.reviewTime:{now_iso()} "
            "parser.interpreter:/usr/bin/python3 parser.timeout:10 parser.isolation:none"
        )
    if status == "rejected":
        note = re.sub(r"\s+", "-", (notes or "not-approved").strip())[:80]
        return (
            "rejected workspace parser parser.reviewStatus:rejected "
            "parser.reviewed:false "
            f"parser.reviewer:{reviewer} parser.reviewTime:{now_iso()} "
            f"parser.rejectReason:{note} parser.interpreter:/usr/bin/python3 "
            "parser.timeout:10 parser.isolation:none"
        )
    return (
        "generated workspace parser parser.reviewStatus:pending parser.generated:true "
        "parser.generator:review-workspace parser.promptHash:sha256-demo "
        "parser.interpreter:/usr/bin/python3 parser.timeout:10 parser.isolation:none"
    )


def approve_or_reject(state, parser_path, reviewer, action, notes=""):
    action = action.lower()
    if action not in {"approve", "reject"}:
        raise ReviewError("action must be approve or reject")
    static = static_script_review(parser_path)
    if action == "approve" and not static["safeForPreview"]:
        result = "denied"
        status = "rejected"
        metadata = review_metadata("rejected", reviewer, "static-check-failed")
    else:
        result = "allowed"
        status = "approved" if action == "approve" else "rejected"
        metadata = review_metadata(status, reviewer, notes)
    review = {
        "parser": str(parser_path),
        "action": action,
        "status": status,
        "result": result,
        "reviewer": reviewer,
        "metadata": metadata,
        "staticReview": static,
        "notes": notes,
        "time": now_iso(),
    }
    state.setdefault("reviews", []).append(review)
    add_audit(state, "parserReview", action, result, parser=Path(parser_path).name, status=status)
    return review


def redacted_audit_export(state):
    safe_events = []
    for event in state.get("audit", []):
        safe = {}
        for key, value in event.items():
            if key in {"orgKey", "newOrgKey", "authorization", "certificate", "privateKey"}:
                safe[key] = "<redacted>"
            else:
                safe[key] = value
        safe_events.append(safe)
    return {
        "schemaVersion": 1,
        "safeForAgent": True,
        "eventCount": len(safe_events),
        "events": safe_events,
    }


def create_workspace(_args):
    cfg = Config()
    auth = cfg.auth_params()
    Path(cfg.storage_path).mkdir(parents=True, exist_ok=True)
    request(
        cfg,
        "POST",
        f"/organizations/{quote_path(cfg.org)}",
        {
            **auth,
            "*resourceInfo": "review workspace organization",
            "*certificate": "undefined",
            "*publicKey": "undefined",
        },
        expected=(201, 409),
    )
    request(
        cfg,
        "POST",
        f"/organizations/{quote_path(cfg.org)}/storage/{quote_path(cfg.storage)}",
        {
            **auth,
            "*resourceInfo": "review workspace storage",
            "*location": "localhost",
            "*type": "local",
            "*accessPath": cfg.storage_path,
            "*accessUser": "undefined",
            "*accessPassword": "undefined",
        },
        expected=(201, 409),
    )
    request(
        cfg,
        "POST",
        f"/organizations/{quote_path(cfg.org)}/users/{quote_path(cfg.user)}",
        {
            **auth,
            "*resourceInfo": "review workspace reviewer",
            "*certificate": "undefined",
            "*publicKey": "undefined",
            "*basicAuthPwdHash": "undefined",
            "*oauthConsumerKey": "undefined",
            "*oauthConsumerSecret": "undefined",
        },
        expected=(201, 409),
    )
    return {"organization": cfg.org, "storage": cfg.storage, "user": cfg.user}


def upload_document(doc_type, doc_name, file_path, resource_info):
    cfg = Config()
    path = Path(file_path)
    if not path.is_file():
        raise ReviewError(f"File not found: {path}")
    body, headers = multipart_body({**cfg.auth_params(), "*resourceInfo": resource_info}, path)
    request(cfg, "POST", base_document_path(cfg, doc_type, doc_name), body=body, headers=headers, expected=(201, 409))
    return {"documentType": doc_type, "document": doc_name, "uploadedOrAlreadyPresent": True}


def upload_csv(args):
    cfg = Config()
    return upload_document("file.csv", args.document or cfg.csv_doc, args.file, "review workspace CSV")


def upload_candidate(args):
    cfg = Config()
    return upload_document("script.python", args.document or cfg.parser_doc, args.file, review_metadata("pending", args.reviewer))


def live_schema(args):
    cfg = Config()
    doc = args.document or cfg.csv_doc
    headers, schema = json_request(cfg, f"{base_document_path(cfg, 'file.csv', doc)}/schema", cfg.auth_params(), limit=1)
    return {"requestId": headers.get("X-Request-Id"), "schema": schema}


def live_preview(args):
    cfg = Config()
    csv_doc = args.csv_document or cfg.csv_doc
    parser_doc = args.parser_document or cfg.parser_doc
    params = {**cfg.auth_params(), "previewOnly": "1", "previewRows": str(max(1, min(args.preview_rows, MAX_PREVIEW_ROWS)))}
    path = f"{base_document_path(cfg, 'file.csv', csv_doc)}/parserScripts/{quote_path(parser_doc)}"
    headers, result = json_request(cfg, path, params, limit=max(1, min(args.limit, MAX_PREVIEW_ROWS)))
    return {"requestId": headers.get("X-Request-Id"), "previewOnly": True, "result": result}


def live_review_update(args, action):
    cfg = Config()
    state = load_state(args.state)
    review = approve_or_reject(state, args.file, args.reviewer, action, args.notes)
    metadata = review["metadata"]
    request(
        cfg,
        "PUT",
        base_document_path(cfg, "script.python", args.document or cfg.parser_doc),
        params={**cfg.auth_params(), "*resourceInfo": metadata},
    )
    save_state(state, args.state)
    return review


def live_run_reviewed(args):
    cfg = Config()
    csv_doc = args.csv_document or cfg.csv_doc
    parser_doc = args.parser_document or cfg.parser_doc
    path = f"{base_document_path(cfg, 'file.csv', csv_doc)}/parserScripts/{quote_path(parser_doc)}"
    headers, result = json_request(cfg, path, cfg.auth_params(), limit=max(1, min(args.limit, MAX_PREVIEW_ROWS)))
    return {"requestId": headers.get("X-Request-Id"), "result": result}


def cleanup(args):
    cfg = Config()
    auth = cfg.auth_params()
    csv_doc = args.csv_document or cfg.csv_doc
    parser_doc = args.parser_document or cfg.parser_doc
    resources = [
        ("parser", base_document_path(cfg, "script.python", parser_doc)),
        ("csv", base_document_path(cfg, "file.csv", csv_doc)),
        ("storage", f"/organizations/{quote_path(cfg.org)}/storage/{quote_path(cfg.storage)}"),
        ("user", f"/organizations/{quote_path(cfg.org)}/users/{quote_path(cfg.user)}"),
    ]
    deleted = []
    for label, path in resources:
        status, _, _ = request(cfg, "DELETE", path, params=auth, expected=(200, 404))
        deleted.append({"resource": label, "status": status})
    return {"cleanup": deleted}


def state_snapshot(state):
    return {
        "workspace": state.get("workspace", {}),
        "reviews": state.get("reviews", [])[-10:],
        "audit": redacted_audit_export(state),
    }


def html_page(state):
    latest = state.get("reviews", [])[-1] if state.get("reviews") else {}
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>CaumeDSE Review Workspace</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; max-width: 980px; }}
    textarea, input, select {{ width: 100%; box-sizing: border-box; margin: .25rem 0 .75rem; }}
    button {{ padding: .45rem .8rem; }}
    pre {{ background: #f4f4f4; padding: 1rem; overflow: auto; }}
  </style>
</head>
<body>
  <h1>CaumeDSE Review Workspace</h1>
  <form method="post" action="/review">
    <label>Parser path <input name="parser" value="{html.escape(str(DEFAULT_SAFE_PARSER))}"></label>
    <label>Reviewer <input name="reviewer" value="human-reviewer"></label>
    <label>Action <select name="action"><option>approve</option><option>reject</option></select></label>
    <label>Notes <textarea name="notes"></textarea></label>
    <button type="submit">Submit review</button>
  </form>
  <h2>Latest Review</h2>
  <pre>{html.escape(json.dumps(latest, indent=2, sort_keys=True))}</pre>
  <p><a href="/api/state">State JSON</a> <a href="/api/audit">Redacted audit JSON</a></p>
</body>
</html>"""


class ReviewHandler(BaseHTTPRequestHandler):
    state_path = DEFAULT_STATE

    def send_json(self, data, status=200):
        payload = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        state = load_state(self.state_path)
        if self.path == "/api/state":
            self.send_json(state_snapshot(state))
            return
        if self.path == "/api/audit":
            self.send_json(redacted_audit_export(state))
            return
        payload = html_page(state).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        if self.path != "/review":
            self.send_json({"error": "not_found"}, status=404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))
        state = load_state(self.state_path)
        try:
            review = approve_or_reject(
                state,
                form.get("parser", [str(DEFAULT_SAFE_PARSER)])[0],
                form.get("reviewer", ["human-reviewer"])[0],
                form.get("action", ["approve"])[0],
                form.get("notes", [""])[0],
            )
            save_state(state, self.state_path)
            self.send_json(review)
        except ReviewError as exc:
            self.send_json({"error": str(exc)}, status=400)


def serve(args):
    ReviewHandler.state_path = Path(args.state)
    server = ThreadingHTTPServer((args.host, args.port), ReviewHandler)
    print(f"Review workspace listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


def self_test(_args):
    state = {"schemaVersion": 1, "workspace": {}, "reviews": [], "audit": []}
    preview = read_csv_preview(DEFAULT_CSV, limit=2)
    if preview["columns"][:2] != ["name", "lastName"]:
        raise ReviewError("CSV preview did not parse expected columns")
    approved = approve_or_reject(state, DEFAULT_SAFE_PARSER, "human-reviewer", "approve", "reviewed source")
    rejected = approve_or_reject(state, DEFAULT_UNSAFE_PARSER, "human-reviewer", "approve", "should fail")
    explicit_reject = approve_or_reject(state, DEFAULT_SAFE_PARSER, "human-reviewer", "reject", "not needed")
    audit = redacted_audit_export(state)
    text = json.dumps({"approved": approved, "rejected": rejected, "audit": audit}, sort_keys=True)
    if approved["status"] != "approved" or rejected["result"] != "denied" or explicit_reject["status"] != "rejected":
        raise ReviewError("review state machine did not enforce approve/reject policy")
    if "orgKey" in text or "newOrgKey" in text or "os.environ" in text:
        raise ReviewError("self-test output leaked a credential or unsafe source marker")
    print("PASS review workspace self-test")


def print_json(data):
    print(json.dumps(data, indent=2, sort_keys=True))


def build_parser():
    parser = argparse.ArgumentParser(description="CaumeDSE secure document review workspace sample")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("self-test", help="Run offline review workflow checks.")

    serve_parser = sub.add_parser("serve", help="Run the local review web service.")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8091)
    serve_parser.add_argument("--state", default=DEFAULT_STATE)

    preview_parser = sub.add_parser("offline-preview", help="Preview the committed CSV fixture.")
    preview_parser.add_argument("--file", default=DEFAULT_CSV)
    preview_parser.add_argument("--limit", type=int, default=MAX_PREVIEW_ROWS)

    review_parser = sub.add_parser("offline-review", help="Approve or reject a parser using local checks.")
    review_parser.add_argument("--file", default=DEFAULT_SAFE_PARSER)
    review_parser.add_argument("--action", choices=("approve", "reject"), required=True)
    review_parser.add_argument("--reviewer", default="human-reviewer")
    review_parser.add_argument("--notes", default="")
    review_parser.add_argument("--state", default=DEFAULT_STATE)

    sub.add_parser("create-workspace", help="Create live CaumeDSE organization, storage, and user.")

    upload_csv_parser = sub.add_parser("upload-csv", help="Upload a CSV document for review.")
    upload_csv_parser.add_argument("--file", default=DEFAULT_CSV)
    upload_csv_parser.add_argument("--document")

    upload_parser = sub.add_parser("upload-candidate", help="Upload a pending parser candidate.")
    upload_parser.add_argument("--file", default=DEFAULT_SAFE_PARSER)
    upload_parser.add_argument("--document")
    upload_parser.add_argument("--reviewer", default="agent-generator")

    schema_parser = sub.add_parser("schema", help="Read live CSV schema metadata.")
    schema_parser.add_argument("--document")

    live_preview_parser = sub.add_parser("preview-candidate", help="Run live preview-only parser execution.")
    live_preview_parser.add_argument("--csv-document")
    live_preview_parser.add_argument("--parser-document")
    live_preview_parser.add_argument("--preview-rows", type=int, default=1)
    live_preview_parser.add_argument("--limit", type=int, default=1)

    for name in ("approve-candidate", "reject-candidate"):
        p = sub.add_parser(name, help=f"{name.replace('-', ' ')} metadata on live parser document.")
        p.add_argument("--file", default=DEFAULT_SAFE_PARSER)
        p.add_argument("--document")
        p.add_argument("--reviewer", default="human-reviewer")
        p.add_argument("--notes", default="")
        p.add_argument("--state", default=DEFAULT_STATE)

    run_parser = sub.add_parser("run-reviewed", help="Run reviewed parser against live CSV.")
    run_parser.add_argument("--csv-document")
    run_parser.add_argument("--parser-document")
    run_parser.add_argument("--limit", type=int, default=1)

    cleanup_parser = sub.add_parser("cleanup", help="Delete live review workspace resources.")
    cleanup_parser.add_argument("--csv-document")
    cleanup_parser.add_argument("--parser-document")

    export_parser = sub.add_parser("export-audit", help="Print redacted local review audit JSON.")
    export_parser.add_argument("--state", default=DEFAULT_STATE)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "self-test":
            self_test(args)
        elif args.command == "serve":
            serve(args)
        elif args.command == "offline-preview":
            print_json(read_csv_preview(args.file, args.limit))
        elif args.command == "offline-review":
            state = load_state(args.state)
            result = approve_or_reject(state, args.file, args.reviewer, args.action, args.notes)
            save_state(state, args.state)
            print_json(result)
        elif args.command == "create-workspace":
            print_json(create_workspace(args))
        elif args.command == "upload-csv":
            print_json(upload_csv(args))
        elif args.command == "upload-candidate":
            print_json(upload_candidate(args))
        elif args.command == "schema":
            print_json(live_schema(args))
        elif args.command == "preview-candidate":
            print_json(live_preview(args))
        elif args.command == "approve-candidate":
            print_json(live_review_update(args, "approve"))
        elif args.command == "reject-candidate":
            print_json(live_review_update(args, "reject"))
        elif args.command == "run-reviewed":
            print_json(live_run_reviewed(args))
        elif args.command == "cleanup":
            print_json(cleanup(args))
        elif args.command == "export-audit":
            print_json(redacted_audit_export(load_state(args.state)))
    except (ReviewError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
