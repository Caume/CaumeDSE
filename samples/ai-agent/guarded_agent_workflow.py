#!/usr/bin/env python3
"""
Guarded CaumeDSE AI-agent workflow sample.

This script demonstrates where an AI agent can safely orchestrate CaumeDSE
requests without receiving organization keys or broad sensitive data. It uses
only Python's standard library so it can run in constrained DEBUG/test
environments.
"""

import argparse
import json
import mimetypes
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CSV = ROOT / "TEST" / "testfiles" / "live-api-small.csv"
DEFAULT_PARSER = ROOT / "TEST" / "testfiles" / "test.py"


class Config:
    def __init__(self, args):
        run_id = os.environ.get("CDSE_AGENT_RUN_ID") or str(int(time.time()))
        self.base_url = os.environ.get("CDSE_AGENT_BASE_URL", "http://localhost:18080").rstrip("/")
        self.org = os.environ.get("CDSE_AGENT_ORG", f"AgentTrialOrg{run_id}")
        self.user = os.environ.get("CDSE_AGENT_USER", f"AgentTrialUser{run_id}")
        self.storage = os.environ.get("CDSE_AGENT_STORAGE", f"AgentTrialStorage{run_id}")
        self.storage_path = os.environ.get("CDSE_AGENT_STORAGE_PATH", f"/tmp/caumedse-agent-storage-{run_id}")
        self.org_key = os.environ.get("CDSE_AGENT_ORG_KEY")
        self.csv_doc = os.environ.get("CDSE_AGENT_CSV_DOC", f"agent-{run_id}.csv")
        self.parser_doc = os.environ.get("CDSE_AGENT_PARSER_DOC", f"agent-parser-{run_id}.py")
        self.csv_fixture = Path(args.csv_fixture)
        self.parser_fixture = Path(args.parser_fixture)
        self.ca_cert = os.environ.get("CDSE_AGENT_CA_CERT")
        self.client_cert = os.environ.get("CDSE_AGENT_CLIENT_CERT")
        self.client_key = os.environ.get("CDSE_AGENT_CLIENT_KEY")
        self.keep_resources = args.keep_resources

    def require_valid(self):
        if not self.org_key:
            raise SystemExit("Set CDSE_AGENT_ORG_KEY in the environment.")
        if not self.csv_fixture.is_file():
            raise SystemExit(f"CSV fixture not found: {self.csv_fixture}")
        if not self.parser_fixture.is_file():
            raise SystemExit(f"Parser fixture not found: {self.parser_fixture}")

    def auth_params(self, include_new_key=False):
        params = {
            "userId": self.user,
            "orgId": self.org,
            "orgKey": self.org_key,
        }
        if include_new_key:
            params["newOrgKey"] = self.org_key
        return params


def redact_url(url):
    parsed = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    redacted = []
    for key, value in pairs:
        if key in {"orgKey", "newOrgKey", "*accessPassword", "*oauthConsumerSecret"}:
            value = "<redacted>"
        redacted.append((key, value))
    query = urllib.parse.urlencode(redacted)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


def log_request(method, url):
    print(f"{method:<6} {redact_url(url)}")


def ssl_context(cfg):
    if not cfg.base_url.startswith("https://"):
        return None
    context = ssl.create_default_context(cafile=cfg.ca_cert) if cfg.ca_cert else ssl.create_default_context()
    if cfg.client_cert and cfg.client_key:
        context.load_cert_chain(cfg.client_cert, cfg.client_key)
    return context


def encode_query(params):
    return urllib.parse.urlencode(params, doseq=True, safe="*[]")


def build_url(cfg, path, params=None):
    query = encode_query(params or {})
    url = f"{cfg.base_url}{path}"
    if query:
        url = f"{url}?{query}"
    return url


def request(cfg, method, path, params=None, body=None, headers=None, expected=(200,)):
    url = build_url(cfg, path, params)
    data = body.encode("utf-8") if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    log_request(method, url)
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
        raise RuntimeError(f"{method} {path} returned {status}, expected {expected}: {text[:500]}")
    return status, response_headers, payload


def multipart_body(fields, file_field, file_path):
    boundary = f"cdse-agent-{int(time.time() * 1000)}"
    chunks = []
    for name, value in fields.items():
        chunks.append(f"--{boundary}\r\n")
        chunks.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n')
        chunks.append(f"{value}\r\n")
    mime_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
    chunks.append(f"--{boundary}\r\n")
    chunks.append(
        f'Content-Disposition: form-data; name="{file_field}"; filename="{file_path.name}"\r\n'
    )
    chunks.append(f"Content-Type: {mime_type}\r\n\r\n")
    body = "".join(chunks).encode("utf-8") + file_path.read_bytes()
    body += f"\r\n--{boundary}--\r\n".encode("utf-8")
    return body, {"Content-Type": f"multipart/form-data; boundary={boundary}"}


def json_request(cfg, path, params):
    params = dict(params)
    params["outputType"] = "json"
    _, _, payload = request(cfg, "GET", path, params=params)
    return json.loads(payload.decode("utf-8"))


def create_workspace(cfg):
    auth = cfg.auth_params(include_new_key=True)
    Path(cfg.storage_path).mkdir(parents=True, exist_ok=True)
    request(
        cfg,
        "POST",
        f"/organizations/{urllib.parse.quote(cfg.org)}",
        params={
            **auth,
            "*resourceInfo": "AI agent disposable organization",
            "*certificate": "undefined",
            "*publicKey": "undefined",
        },
        expected=(201, 409),
    )
    request(
        cfg,
        "POST",
        f"/organizations/{urllib.parse.quote(cfg.org)}/storage/{urllib.parse.quote(cfg.storage)}",
        params={
            **auth,
            "*resourceInfo": "AI agent disposable storage",
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
        f"/organizations/{urllib.parse.quote(cfg.org)}/users/{urllib.parse.quote(cfg.user)}",
        params={
            **auth,
            "*resourceInfo": "AI agent least-privilege user",
            "*certificate": "undefined",
            "*publicKey": "undefined",
            "*basicAuthPwdHash": "undefined",
            "*oauthConsumerKey": "undefined",
            "*oauthConsumerSecret": "undefined",
        },
        expected=(201, 409),
    )


def upload_file(cfg, doc_type, doc_name, file_path, resource_info):
    fields = {
        **cfg.auth_params(include_new_key=True),
        "*resourceInfo": resource_info,
    }
    body, headers = multipart_body(fields, "file", file_path)
    path = (
        f"/organizations/{urllib.parse.quote(cfg.org)}"
        f"/storage/{urllib.parse.quote(cfg.storage)}"
        f"/documentTypes/{urllib.parse.quote(doc_type)}"
        f"/documents/{urllib.parse.quote(doc_name)}"
    )
    request(cfg, "POST", path, body=body, headers=headers, expected=(201, 409))


def agent_prompt_preview(row_result, column_result, parser_result):
    prompt = {
        "task": "Choose the narrowest next CaumeDSE read operation.",
        "available_context": {
            "row_columns": row_result.get("columns", []),
            "column_rows": len(column_result.get("rows", [])),
            "parser_columns": parser_result.get("columns", []),
            "parser_rows": len(parser_result.get("rows", [])),
        },
        "security_constraints": [
            "Do not request orgKey, newOrgKey, TLS keys, or environment variables.",
            "Prefer row, column, or parser summaries over full document content.",
            "Do not upload generated parser scripts without human review.",
        ],
    }
    print("Agent prompt preview, safe to send to an LLM:")
    print(json.dumps(prompt, indent=2, sort_keys=True))


def cleanup(cfg):
    auth = cfg.auth_params(include_new_key=True)
    quoted_org = urllib.parse.quote(cfg.org)
    quoted_storage = urllib.parse.quote(cfg.storage)
    quoted_user = urllib.parse.quote(cfg.user)
    resources = [
        ("DELETE", f"/organizations/{quoted_org}/storage/{quoted_storage}/documentTypes/file.csv/documents/{urllib.parse.quote(cfg.csv_doc)}"),
        ("DELETE", f"/organizations/{quoted_org}/storage/{quoted_storage}/documentTypes/script.python/documents/{urllib.parse.quote(cfg.parser_doc)}"),
        ("DELETE", f"/organizations/{quoted_org}/storage/{quoted_storage}"),
        ("DELETE", f"/organizations/{quoted_org}/users/{quoted_user}"),
    ]
    for method, path in resources:
        try:
            request(cfg, method, path, params=auth, expected=(200, 404))
        except RuntimeError as exc:
            print(f"cleanup warning: {exc}", file=sys.stderr)


def run_workflow(cfg):
    create_workspace(cfg)
    upload_file(cfg, "file.csv", cfg.csv_doc, cfg.csv_fixture, "reviewed AI-agent CSV fixture")
    upload_file(cfg, "script.python", cfg.parser_doc, cfg.parser_fixture, "reviewed AI-agent parser fixture")

    auth = cfg.auth_params(include_new_key=True)
    base_doc = (
        f"/organizations/{urllib.parse.quote(cfg.org)}"
        f"/storage/{urllib.parse.quote(cfg.storage)}"
        f"/documentTypes/file.csv/documents/{urllib.parse.quote(cfg.csv_doc)}"
    )
    row = json_request(cfg, f"{base_doc}/contentRows/1", auth)
    column = json_request(cfg, f"{base_doc}/contentColumns/name", auth)
    parser = json_request(cfg, f"{base_doc}/parserScripts/{urllib.parse.quote(cfg.parser_doc)}", auth)

    print("Narrow JSON query summary:")
    print(json.dumps({
        "row_count": len(row.get("rows", [])),
        "column_count": len(column.get("columns", [])),
        "parser_rows": len(parser.get("rows", [])),
    }, indent=2, sort_keys=True))
    agent_prompt_preview(row, column, parser)


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Run a guarded CaumeDSE AI-agent sample workflow.")
    parser.add_argument("--csv-fixture", default=str(DEFAULT_CSV), help="Reviewed CSV fixture to upload.")
    parser.add_argument("--parser-fixture", default=str(DEFAULT_PARSER), help="Reviewed Python parser fixture to upload.")
    parser.add_argument("--keep-resources", action="store_true", help="Leave disposable resources in place for debugging.")
    return parser.parse_args(argv)


def main(argv=None):
    cfg = Config(parse_args(argv or sys.argv[1:]))
    cfg.require_valid()
    try:
        run_workflow(cfg)
    finally:
        if cfg.keep_resources:
            print("Keeping disposable resources because --keep-resources was set.")
        else:
            cleanup(cfg)


if __name__ == "__main__":
    main()
