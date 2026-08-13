#!/usr/bin/env python3
"""
Model Context Protocol server for guarded CaumeDSE inspection.

The server speaks JSON-RPC over stdio, implements a stable MCP tool surface,
and calls the CaumeDSE REST API with credentials sourced only from environment
variables. It intentionally uses Python's standard library so the sample can
run in constrained DEBUG/test environments.
"""

import argparse
import base64
import fnmatch
import hashlib
import hmac
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
SERVER_NAME = "caumedse-mcp-readonly"
SERVER_VERSION = "0.2.0"
PROTOCOL_VERSION = "2024-11-05"
MAX_LIMIT = 10
MAX_TEXT_BYTES = 12000
WRITE_CONFIRMATION = "confirm-caumedse-mcp-write"


class ToolError(Exception):
    pass


class Config:
    def __init__(self):
        run_id = os.environ.get("CDSE_MCP_RUN_ID") or str(int(time.time()))
        self.base_url = os.environ.get("CDSE_MCP_BASE_URL", "http://localhost:18080").rstrip("/")
        self.org = os.environ.get("CDSE_MCP_ORG", f"McpTrialOrg{run_id}")
        self.user = os.environ.get("CDSE_MCP_USER", f"McpTrialUser{run_id}")
        self.storage = os.environ.get("CDSE_MCP_STORAGE", f"McpTrialStorage{run_id}")
        self.storage_path = os.environ.get("CDSE_MCP_STORAGE_PATH", f"/tmp/caumedse-mcp-storage-{run_id}")
        self.org_key = os.environ.get("CDSE_MCP_ORG_KEY")
        self.csv_doc = os.environ.get("CDSE_MCP_CSV_DOC", f"mcp-{run_id}.csv")
        self.parser_doc = os.environ.get("CDSE_MCP_PARSER_DOC", f"mcp-parser-{run_id}.py")
        self.pending_parser_doc = os.environ.get("CDSE_MCP_PENDING_PARSER_DOC", f"mcp-parser-pending-{run_id}.py")
        self.ca_cert = os.environ.get("CDSE_MCP_CA_CERT")
        self.client_cert = os.environ.get("CDSE_MCP_CLIENT_CERT")
        self.client_key = os.environ.get("CDSE_MCP_CLIENT_KEY")
        self.delegated_token = os.environ.get("CDSE_MCP_DELEGATED_TOKEN")
        self.delegated_token_secret = os.environ.get("CDSE_MCP_DELEGATED_TOKEN_SECRET")
        self.write_tools_requested = os.environ.get("CDSE_MCP_ENABLE_WRITE_TOOLS", "").lower() in {"1", "true", "yes", "on"}
        self.enable_write_tools = self.write_tools_requested and bool(self.delegated_token)

    def require_key(self):
        if not self.org_key:
            raise ToolError("Set CDSE_MCP_ORG_KEY in the environment before calling CaumeDSE tools.")

    def auth_params(self, include_new_key=False):
        self.require_key()
        params = {
            "userId": self.user,
            "orgId": self.org,
            "orgKey": self.org_key,
        }
        if include_new_key:
            params["newOrgKey"] = self.org_key
        return params


def quote_path(value):
    return urllib.parse.quote(str(value), safe="")


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
    print(f"{method:<6} {redact_url(url)}", file=sys.stderr)


def ssl_context(cfg):
    if not cfg.base_url.startswith("https://"):
        return None
    context = ssl.create_default_context(cafile=cfg.ca_cert) if cfg.ca_cert else ssl.create_default_context()
    if cfg.client_cert and cfg.client_key:
        context.load_cert_chain(cfg.client_cert, cfg.client_key)
    return context


def encode_query(params):
    return urllib.parse.urlencode(params, doseq=True, safe="*[]")


def b64url_decode(text):
    padding = "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode((text + padding).encode("ascii"))


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def verify_delegated_token(cfg, required_scope):
    if not cfg.delegated_token:
        raise ToolError("Write tools require CDSE_MCP_DELEGATED_TOKEN in the server environment.")
    if not cfg.delegated_token_secret:
        return {"verified": False, "reason": "CDSE_MCP_DELEGATED_TOKEN_SECRET not configured"}
    try:
        payload, signature = cfg.delegated_token.split(".", 1)
        expected = b64url_encode(hmac.new(
            cfg.delegated_token_secret.encode("utf-8"),
            payload.encode("ascii"),
            hashlib.sha256,
        ).digest())
        if not hmac.compare_digest(signature, expected):
            raise ToolError("Delegated token signature verification failed.")
        claims = json.loads(b64url_decode(payload).decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ToolError("Delegated token is malformed.") from exc
    now = int(time.time())
    if int(claims.get("exp", 0)) <= now:
        raise ToolError("Delegated token is expired.")
    cdse = claims.get("cdse", {})
    if cdse.get("orgId") != cfg.org or cdse.get("userId") != cfg.user:
        raise ToolError("Delegated token is not bound to the configured organization/user.")
    scopes = claims.get("scope", [])
    if not any(fnmatch.fnmatchcase(required_scope, scope) for scope in scopes):
        raise ToolError(f"Delegated token is missing scope: {required_scope}")
    return {
        "verified": True,
        "subject": claims.get("sub"),
        "expiresAt": claims.get("exp"),
        "scope": required_scope,
    }


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
        raise ToolError(f"{method} {path} returned {status}, expected {expected}: {text[:500]}")
    return status, response_headers, payload


def multipart_body(fields, file_field, file_path):
    boundary = f"cdse-mcp-{int(time.time() * 1000)}"
    chunks = []
    for name, value in fields.items():
        chunks.append(f"--{boundary}\r\n")
        chunks.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n')
        chunks.append(f"{value}\r\n")
    mime_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
    chunks.append(f"--{boundary}\r\n")
    chunks.append(f'Content-Disposition: form-data; name="{file_field}"; filename="{file_path.name}"\r\n')
    chunks.append(f"Content-Type: {mime_type}\r\n\r\n")
    body = "".join(chunks).encode("utf-8") + file_path.read_bytes()
    body += f"\r\n--{boundary}--\r\n".encode("utf-8")
    return body, {"Content-Type": f"multipart/form-data; boundary={boundary}"}


def json_request(cfg, path, params, limit=10, offset=0):
    params = dict(params)
    params["outputType"] = "json"
    params["limit"] = str(limit)
    params["offset"] = str(offset)
    _, _, payload = request(cfg, "GET", path, params=params)
    return json.loads(payload.decode("utf-8"))


def resolve_file(path_value, default_path):
    path = Path(path_value or default_path).expanduser()
    if not path.is_file():
        raise ToolError(f"Reviewed local file not found: {path}")
    return path


def write_scope(action, cfg, document=None):
    scopes = {
        "create_workspace": f"workspace:{cfg.org}:{cfg.storage}:{cfg.user}",
        "upload_csv": f"document:file.csv:{document}",
        "upload_parser": f"document:script.python:{document}",
        "upload_parser_candidate": f"document:script.python.pending:{document}",
        "promote_parser_review": f"document:script.python.reviewed:{document}",
        "delete_document": f"document:delete:{document}",
        "cleanup_workspace": f"cleanup:{cfg.org}:{cfg.storage}:{cfg.user}",
    }
    return scopes[action]


def require_write_guard(cfg, args, action, allowed_statuses, document=None):
    required = ("organization", "storage", "user", "scope", "expected_status", "idempotency_key", "confirm")
    missing = [name for name in required if args.get(name) in (None, "")]
    if missing:
        raise ToolError(f"Write tool guard rejected {action}: missing required arguments: {', '.join(missing)}")
    if args["organization"] != cfg.org or args["storage"] != cfg.storage or args["user"] != cfg.user:
        raise ToolError("Write tool guard rejected request: organization, storage, and user must match server configuration.")
    expected_scope = write_scope(action, cfg, document)
    scope = str(args["scope"])
    if scope != expected_scope or scope.lower() in {"*", "all", "organization", "storage"}:
        raise ToolError(f"Write tool guard rejected request: scope must be exactly {expected_scope}.")
    try:
        expected_status = int(args["expected_status"])
    except (TypeError, ValueError) as exc:
        raise ToolError("Write tool guard rejected request: expected_status must be an integer.") from exc
    if expected_status not in allowed_statuses:
        raise ToolError(f"Write tool guard rejected request: expected_status must be one of {sorted(allowed_statuses)}.")
    idempotency_key = str(args["idempotency_key"])
    if len(idempotency_key) < 12 or any(ch.isspace() for ch in idempotency_key):
        raise ToolError("Write tool guard rejected request: idempotency_key must be at least 12 non-space characters.")
    if args["confirm"] != WRITE_CONFIRMATION:
        raise ToolError(f"Write tool guard rejected request: confirm must be {WRITE_CONFIRMATION}.")
    token = verify_delegated_token(cfg, scope)
    return {
        "action": action,
        "scope": scope,
        "expectedStatus": expected_status,
        "idempotencyKey": idempotency_key,
        "dryRun": bool(args.get("dry_run")),
        "delegatedTokenConfigured": True,
        "delegatedToken": token,
    }


def request_audit(method, path, status, headers):
    return {
        "method": method,
        "path": path,
        "status": status,
        "requestId": headers.get("X-Request-Id") or headers.get("X-Request-ID"),
        "safeForAgent": True,
    }


def get_agent_capabilities(cfg, _args):
    _, _, payload = request(cfg, "GET", "/agentCapabilities")
    return json.loads(payload.decode("utf-8"))


def clamp_limit(value, default=3, maximum=MAX_LIMIT):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(1, min(parsed, maximum))


def summarize_table(result, limit):
    if not isinstance(result, dict):
        raise ToolError("CaumeDSE returned a non-object JSON response.")
    if "error" in result:
        raise ToolError(json.dumps(result["error"], sort_keys=True))
    rows = result.get("rows", [])
    columns = result.get("columns", [])
    pagination = result.get("pagination", {})
    if not isinstance(rows, list) or not isinstance(columns, list) or not isinstance(pagination, dict):
        raise ToolError("CaumeDSE JSON table response is missing rows, columns, or pagination.")
    return {
        "columns": columns[:MAX_LIMIT],
        "rowCount": pagination.get("totalRows", len(rows)),
        "pagination": pagination,
        "rows": rows[:limit],
        "truncated": bool(pagination.get("hasMore", len(rows) > limit) or len(columns) > MAX_LIMIT),
    }


def base_document_path(cfg, doc_type, doc_name):
    return (
        f"/organizations/{quote_path(cfg.org)}"
        f"/storage/{quote_path(cfg.storage)}"
        f"/documentTypes/{quote_path(doc_type)}"
        f"/documents/{quote_path(doc_name)}"
    )


def create_workspace(cfg, _args):
    guard = require_write_guard(cfg, _args, "create_workspace", {201, 409})
    if guard["dryRun"]:
        return {"guard": guard, "wouldCreate": {"organization": cfg.org, "storage": cfg.storage, "user": cfg.user}}
    auth = cfg.auth_params(include_new_key=True)
    Path(cfg.storage_path).mkdir(parents=True, exist_ok=True)
    request(
        cfg,
        "POST",
        f"/organizations/{quote_path(cfg.org)}",
        params={
            **auth,
            "*resourceInfo": "MCP disposable organization",
            "*certificate": "undefined",
            "*publicKey": "undefined",
        },
        expected=(201, 409),
    )
    request(
        cfg,
        "POST",
        f"/organizations/{quote_path(cfg.org)}/storage/{quote_path(cfg.storage)}",
        params={
            **auth,
            "*resourceInfo": "MCP disposable storage",
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
        params={
            **auth,
            "*resourceInfo": "MCP least-privilege user",
            "*certificate": "undefined",
            "*publicKey": "undefined",
            "*basicAuthPwdHash": "undefined",
            "*oauthConsumerKey": "undefined",
            "*oauthConsumerSecret": "undefined",
        },
        expected=(201, 409),
    )
    return {"guard": guard, "organization": cfg.org, "storage": cfg.storage, "user": cfg.user, "createdOrAlreadyPresent": True}


def list_document_types(cfg, _args):
    path = f"/organizations/{quote_path(cfg.org)}/storage/{quote_path(cfg.storage)}/documentTypes"
    result = json_request(cfg, path, cfg.auth_params(include_new_key=True), limit=10)
    return summarize_table(result, 10)


def upload_document(cfg, doc_type, doc_name, file_path, resource_info):
    fields = {
        **cfg.auth_params(include_new_key=True),
        "*resourceInfo": resource_info,
    }
    body, headers = multipart_body(fields, "file", file_path)
    request(
        cfg,
        "POST",
        base_document_path(cfg, doc_type, doc_name),
        body=body,
        headers=headers,
        expected=(201, 409),
    )
    return {
        "documentType": doc_type,
        "document": doc_name,
        "fileName": file_path.name,
        "uploadedOrAlreadyPresent": True,
    }


def upload_csv(cfg, args):
    doc_name = args.get("document") or cfg.csv_doc
    guard = require_write_guard(cfg, args, "upload_csv", {201, 409}, doc_name)
    if guard["dryRun"]:
        return {"guard": guard, "wouldUpload": {"documentType": "file.csv", "document": doc_name}}
    file_path = resolve_file(args.get("csv_path"), DEFAULT_CSV)
    resource_info = args.get("resource_info") or "reviewed MCP CSV fixture"
    result = upload_document(cfg, "file.csv", doc_name, file_path, resource_info)
    result["guard"] = guard
    return result


def upload_parser(cfg, args):
    doc_name = args.get("document") or cfg.parser_doc
    guard = require_write_guard(cfg, args, "upload_parser", {201, 409}, doc_name)
    if guard["dryRun"]:
        return {"guard": guard, "wouldUpload": {"documentType": "script.python", "document": doc_name}}
    file_path = resolve_file(args.get("parser_path"), DEFAULT_PARSER)
    resource_info = args.get("resource_info") or (
        "reviewed MCP parser fixture parser.reviewStatus:reviewed parser.reviewed:true "
        "parser.reviewer:human-reviewer parser.reviewTime:2026-07-30T00:00:00Z "
        "parser.interpreter:/usr/bin/python3 parser.timeout:10 parser.isolation:none"
    )
    result = upload_document(cfg, "script.python", doc_name, file_path, resource_info)
    result["guard"] = guard
    return result


def upload_parser_candidate(cfg, args):
    doc_name = args.get("document") or cfg.pending_parser_doc
    guard = require_write_guard(cfg, args, "upload_parser_candidate", {201, 409}, doc_name)
    if guard["dryRun"]:
        return {"guard": guard, "wouldUpload": {"documentType": "script.python", "document": doc_name, "reviewStatus": "pending"}}
    file_path = resolve_file(args.get("parser_path"), DEFAULT_PARSER)
    resource_info = args.get("resource_info") or (
        "generated MCP parser candidate parser.reviewStatus:pending parser.generated:true "
        "parser.generator:mcp-client parser.promptHash:sha256-demo "
        "parser.interpreter:/usr/bin/python3 parser.timeout:10 parser.isolation:none"
    )
    result = upload_document(cfg, "script.python", doc_name, file_path, resource_info)
    result["guard"] = guard
    return result


def promote_parser_review(cfg, args):
    doc_name = args.get("document") or cfg.pending_parser_doc
    guard = require_write_guard(cfg, args, "promote_parser_review", {200, 404}, doc_name)
    reviewer = args.get("reviewer") or cfg.user
    review_time = args.get("review_time") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    resource_info = args.get("resource_info") or (
        "reviewed MCP parser candidate parser.reviewStatus:reviewed parser.reviewed:true "
        f"parser.reviewer:{reviewer} parser.reviewTime:{review_time} "
        "parser.interpreter:/usr/bin/python3 parser.timeout:10 parser.isolation:none"
    )
    plan = {
        "documentType": "script.python",
        "document": doc_name,
        "reviewStatus": "reviewed",
        "reviewer": reviewer,
    }
    if guard["dryRun"]:
        return {"guard": guard, "wouldUpdate": plan}
    path = base_document_path(cfg, "script.python", doc_name)
    status, headers, _ = request(
        cfg,
        "PUT",
        path,
        params={**cfg.auth_params(include_new_key=True), "*resourceInfo": resource_info},
        expected=(guard["expectedStatus"],),
    )
    return {"guard": guard, "updated": plan, "audit": request_audit("PUT", path, status, headers)}


def delete_document(cfg, args):
    doc_name = args.get("document")
    doc_type = args.get("document_type") or "file.csv"
    if not doc_name:
        raise ToolError("delete_document requires an exact document name.")
    if doc_type not in {"file.csv", "script.python"}:
        raise ToolError("delete_document only allows file.csv or script.python document_type.")
    guard = require_write_guard(cfg, args, "delete_document", {200, 404}, f"{doc_type}:{doc_name}")
    plan = {"documentType": doc_type, "document": doc_name}
    if guard["dryRun"]:
        return {"guard": guard, "wouldDelete": plan}
    path = base_document_path(cfg, doc_type, doc_name)
    status, headers, _ = request(
        cfg,
        "DELETE",
        path,
        params=cfg.auth_params(include_new_key=True),
        expected=(guard["expectedStatus"],),
    )
    return {"guard": guard, "deleted": plan, "audit": request_audit("DELETE", path, status, headers)}


def discover_schema(cfg, args):
    doc_name = args.get("document") or cfg.csv_doc
    path = f"{base_document_path(cfg, 'file.csv', doc_name)}/schema"
    schema = json_request(cfg, path, cfg.auth_params(include_new_key=True), limit=1)
    validate_schema(schema, "document")
    return schema


def validate_schema(schema, expected_resource=None):
    if not isinstance(schema, dict):
        raise ToolError("CaumeDSE schema response is not a JSON object.")
    if schema.get("safeForAgent") is not True:
        raise ToolError("CaumeDSE schema response is not marked safeForAgent.")
    if expected_resource and schema.get("resource") != expected_resource:
        raise ToolError(f"Unexpected schema resource: {schema.get('resource')}")
    if not isinstance(schema.get("columns"), list):
        raise ToolError("CaumeDSE schema response is missing columns.")
    if not isinstance(schema.get("pagination"), dict):
        raise ToolError("CaumeDSE schema response is missing pagination metadata.")
    return schema


def query_column(cfg, args):
    doc_name = args.get("document") or cfg.csv_doc
    column = args.get("column") or "name"
    limit = clamp_limit(args.get("limit"))
    schema = discover_schema(cfg, {"document": doc_name})
    if column not in {entry.get("name") for entry in schema.get("columns", [])}:
        raise ToolError(f"Column not found in document schema: {column}")
    path = f"{base_document_path(cfg, 'file.csv', doc_name)}/contentColumns/{quote_path(column)}"
    summary = summarize_table(json_request(cfg, path, cfg.auth_params(include_new_key=True), limit=limit), limit)
    summary["schema"] = {"rowCount": schema.get("rowCount"), "columnCount": schema.get("columnCount")}
    return summary


def discover_db_table_schema(cfg, args):
    db_name = args.get("db_name") or cfg.csv_doc
    table = args.get("table") or "data"
    path = (
        f"/organizations/{quote_path(cfg.org)}"
        f"/storage/{quote_path(cfg.storage)}"
        f"/dbNames/{quote_path(db_name)}"
        f"/dbTables/{quote_path(table)}"
        f"/schema"
    )
    schema = json_request(cfg, path, cfg.auth_params(include_new_key=True), limit=1)
    validate_schema(schema, "dbTable")
    return schema


def query_db_table_column(cfg, args):
    db_name = args.get("db_name") or cfg.csv_doc
    table = args.get("table") or "data"
    column = args.get("column") or "name"
    limit = clamp_limit(args.get("limit"))
    schema = discover_db_table_schema(cfg, {"db_name": db_name, "table": table})
    if column not in {entry.get("name") for entry in schema.get("columns", [])}:
        raise ToolError(f"Column not found in table schema: {column}")
    path = (
        f"/organizations/{quote_path(cfg.org)}"
        f"/storage/{quote_path(cfg.storage)}"
        f"/dbNames/{quote_path(db_name)}"
        f"/dbTables/{quote_path(table)}"
        f"/tableColumns/{quote_path(column)}"
    )
    summary = summarize_table(json_request(cfg, path, cfg.auth_params(include_new_key=True), limit=limit), limit)
    summary["schema"] = {"rowCount": schema.get("rowCount"), "columnCount": schema.get("columnCount")}
    return summary


def run_parser(cfg, args):
    doc_name = args.get("document") or cfg.csv_doc
    parser_name = args.get("parser") or cfg.parser_doc
    limit = clamp_limit(args.get("limit"))
    schema = discover_schema(cfg, {"document": doc_name})
    path = f"{base_document_path(cfg, 'file.csv', doc_name)}/parserScripts/{quote_path(parser_name)}"
    summary = summarize_table(json_request(cfg, path, cfg.auth_params(include_new_key=True), limit=limit), limit)
    summary["schema"] = {"rowCount": schema.get("rowCount"), "columnCount": schema.get("columnCount")}
    return summary


def preview_parser_candidate(cfg, args):
    doc_name = args.get("document") or cfg.csv_doc
    parser_name = args.get("parser") or cfg.pending_parser_doc
    limit = clamp_limit(args.get("limit"), default=1)
    preview_rows = clamp_limit(args.get("preview_rows"), default=1)
    schema = discover_schema(cfg, {"document": doc_name})
    path = f"{base_document_path(cfg, 'file.csv', doc_name)}/parserScripts/{quote_path(parser_name)}"
    params = {**cfg.auth_params(include_new_key=True), "previewOnly": "1", "previewRows": str(preview_rows)}
    summary = summarize_table(json_request(cfg, path, params, limit=limit), limit)
    summary["schema"] = {"rowCount": schema.get("rowCount"), "columnCount": schema.get("columnCount")}
    summary["previewOnly"] = True
    return summary


def cleanup_workspace(cfg, args):
    guard = require_write_guard(cfg, args, "cleanup_workspace", {200, 404})
    if guard["dryRun"]:
        return {"guard": guard, "wouldDelete": ["csv", "pending_parser", "parser", "storage", "user"]}
    auth = cfg.auth_params(include_new_key=True)
    csv_doc = args.get("csv_document") or cfg.csv_doc
    parser_doc = args.get("parser_document") or cfg.parser_doc
    resources = [
        ("csv", "DELETE", base_document_path(cfg, "file.csv", csv_doc)),
        ("pending_parser", "DELETE", base_document_path(cfg, "script.python", cfg.pending_parser_doc)),
        ("parser", "DELETE", base_document_path(cfg, "script.python", parser_doc)),
        ("storage", "DELETE", f"/organizations/{quote_path(cfg.org)}/storage/{quote_path(cfg.storage)}"),
        ("user", "DELETE", f"/organizations/{quote_path(cfg.org)}/users/{quote_path(cfg.user)}"),
    ]
    deleted = []
    for label, method, path in resources:
        status, _, _ = request(cfg, method, path, params=auth, expected=(200, 404))
        deleted.append({"resource": label, "status": status})
    return {"guard": guard, "cleanup": deleted}


READ_ONLY_TOOLS = {
    "agentCapabilities_read": get_agent_capabilities,
    "documentTypes_list": list_document_types,
    "documentSchema_read": discover_schema,
    "contentColumns_read": query_column,
    "parserScripts_run": run_parser,
    "parserScripts_preview": preview_parser_candidate,
    "dbTableSchema_read": discover_db_table_schema,
    "dbTableColumns_read": query_db_table_column,
}

WRITE_TOOLS = {
    "create_workspace": create_workspace,
    "upload_csv": upload_csv,
    "upload_parser": upload_parser,
    "upload_parser_candidate": upload_parser_candidate,
    "promote_parser_review": promote_parser_review,
    "delete_document": delete_document,
    "cleanup_workspace": cleanup_workspace,
}

COMMON_WRITE_GUARD_PROPERTIES = {
    "organization": {"type": "string"},
    "storage": {"type": "string"},
    "user": {"type": "string"},
    "scope": {"type": "string"},
    "expected_status": {"type": "integer"},
    "idempotency_key": {"type": "string", "minLength": 12},
    "confirm": {"type": "string", "const": WRITE_CONFIRMATION},
    "dry_run": {"type": "boolean"},
}
COMMON_WRITE_GUARD_REQUIRED = [
    "organization",
    "storage",
    "user",
    "scope",
    "expected_status",
    "idempotency_key",
    "confirm",
]


def write_schema(properties, required=None):
    merged = dict(COMMON_WRITE_GUARD_PROPERTIES)
    merged.update(properties)
    return {
        "type": "object",
        "properties": merged,
        "required": COMMON_WRITE_GUARD_REQUIRED + list(required or []),
        "additionalProperties": False,
    }


READ_ONLY_TOOL_SCHEMAS = [
    {
        "name": "agentCapabilities_read",
        "description": "Read the public CaumeDSE AI-agent capability manifest without credentials.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "documentTypes_list",
        "description": "List document types in the configured storage as a bounded JSON summary.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "documentSchema_read",
        "description": "Read document schema metadata before row, column, or parser reads.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "document": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "contentColumns_read",
        "description": "Validate one CSV column against schema and return a bounded row preview.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "document": {"type": "string"},
                "column": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "parserScripts_run",
        "description": "Run an already uploaded reviewed parser and return a bounded row preview.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "document": {"type": "string"},
                "parser": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "parserScripts_preview",
        "description": "Run a pending parser candidate in preview-only mode against capped sample rows.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "document": {"type": "string"},
                "parser": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT},
                "preview_rows": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "dbTableSchema_read",
        "description": "Read schema metadata for one exposed secure CSV table.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "db_name": {"type": "string"},
                "table": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "dbTableColumns_read",
        "description": "Validate one exposed table column against schema and return a bounded row preview.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "db_name": {"type": "string"},
                "table": {"type": "string"},
                "column": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT},
            },
            "additionalProperties": False,
        },
    },
]

WRITE_TOOL_SCHEMAS = [
    {
        "name": "create_workspace",
        "description": "Local DEBUG helper: create the configured disposable organization, storage, and user.",
        "inputSchema": write_schema({}),
    },
    {
        "name": "upload_csv",
        "description": "Local DEBUG helper: upload a reviewed local CSV fixture to the configured storage.",
        "inputSchema": {
            **write_schema({
                "document": {"type": "string"},
                "csv_path": {"type": "string"},
                "resource_info": {"type": "string"},
            }),
        },
    },
    {
        "name": "upload_parser",
        "description": "Local DEBUG helper: upload a reviewed local Python parser fixture with review metadata.",
        "inputSchema": {
            **write_schema({
                "document": {"type": "string"},
                "parser_path": {"type": "string"},
                "resource_info": {"type": "string"},
            }),
        },
    },
    {
        "name": "upload_parser_candidate",
        "description": "Local DEBUG helper: upload a generated parser candidate as pending review metadata.",
        "inputSchema": {
            **write_schema({
                "document": {"type": "string"},
                "parser_path": {"type": "string"},
                "resource_info": {"type": "string"},
            }),
        },
    },
    {
        "name": "promote_parser_review",
        "description": "Local DEBUG helper: update one pending Python parser document with reviewed metadata.",
        "inputSchema": {
            **write_schema({
                "document": {"type": "string"},
                "reviewer": {"type": "string"},
                "review_time": {"type": "string"},
                "resource_info": {"type": "string"},
            }),
        },
    },
    {
        "name": "delete_document",
        "description": "Local DEBUG helper: delete one exact file.csv or script.python document.",
        "inputSchema": {
            **write_schema({
                "document_type": {"type": "string", "enum": ["file.csv", "script.python"]},
                "document": {"type": "string"},
            }, required=["document"]),
        },
    },
    {
        "name": "cleanup_workspace",
        "description": "Local DEBUG helper: delete the configured sample documents, storage, and user.",
        "inputSchema": {
            **write_schema({
                "csv_document": {"type": "string"},
                "parser_document": {"type": "string"},
            }),
        },
    },
]


def available_tools(cfg):
    tools = dict(READ_ONLY_TOOLS)
    if cfg.enable_write_tools:
        tools.update(WRITE_TOOLS)
    return tools


def available_tool_schemas(cfg):
    schemas = list(READ_ONLY_TOOL_SCHEMAS)
    if cfg.enable_write_tools:
        schemas.extend(WRITE_TOOL_SCHEMAS)
    return schemas


def tool_result(data, is_error=False):
    text = json.dumps(data, indent=2, sort_keys=True)
    truncated = False
    encoded = text.encode("utf-8")
    if len(encoded) > MAX_TEXT_BYTES:
        text = encoded[:MAX_TEXT_BYTES].decode("utf-8", errors="ignore")
        text += "\n...<truncated>"
        truncated = True
    return {
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
        "structuredContent": {"truncated": truncated},
    }


def handle_request(cfg, request_obj):
    method = request_obj.get("method")
    params = request_obj.get("params") or {}
    if method == "initialize":
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        }
    if method == "tools/list":
        return {"tools": available_tool_schemas(cfg)}
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        tools = available_tools(cfg)
        if name not in tools:
            raise ToolError(f"Unknown tool: {name}")
        if not isinstance(arguments, dict):
            raise ToolError("Tool arguments must be an object.")
        try:
            return tool_result(tools[name](cfg, arguments))
        except ToolError as exc:
            return tool_result({"error": str(exc)}, is_error=True)
    if method and method.startswith("notifications/"):
        return None
    raise KeyError(method)


def json_rpc_error(code, message):
    return {"code": code, "message": message}


def write_response(response):
    sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def scoped_guard_args(cfg, action, document=None, expected_status=201):
    return {
        "organization": cfg.org,
        "storage": cfg.storage,
        "user": cfg.user,
        "scope": write_scope(action, cfg, document),
        "expected_status": expected_status,
        "idempotency_key": f"selftest-{action}-0001",
        "confirm": WRITE_CONFIRMATION,
        "dry_run": True,
    }


def self_test_token(cfg, scopes, secret="self-test-secret"):
    claims = {
        "iss": "caumedse-delegated-token-broker-sample",
        "sub": "mcp-self-test-agent",
        "iat": 1000,
        "exp": int(time.time()) + 600,
        "jti": "mcp-self-test-jti",
        "scope": sorted(set(scopes)),
        "cdse": {
            "orgId": cfg.org,
            "userId": cfg.user,
        },
    }
    payload = b64url_encode(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = b64url_encode(hmac.new(secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256).digest())
    return f"{payload}.{signature}"


def self_test():
    saved_env = {key: os.environ.get(key) for key in (
        "CDSE_MCP_ENABLE_WRITE_TOOLS",
        "CDSE_MCP_DELEGATED_TOKEN",
        "CDSE_MCP_DELEGATED_TOKEN_SECRET",
        "CDSE_MCP_ORG",
        "CDSE_MCP_STORAGE",
        "CDSE_MCP_USER",
    )}
    try:
        os.environ.pop("CDSE_MCP_ENABLE_WRITE_TOOLS", None)
        os.environ.pop("CDSE_MCP_DELEGATED_TOKEN", None)
        cfg = Config()
        if any(name in available_tools(cfg) for name in WRITE_TOOLS):
            raise AssertionError("write tools exposed by default")

        os.environ["CDSE_MCP_ENABLE_WRITE_TOOLS"] = "1"
        cfg = Config()
        if any(name in available_tools(cfg) for name in WRITE_TOOLS):
            raise AssertionError("write tools exposed without delegated-token configuration")

        os.environ["CDSE_MCP_DELEGATED_TOKEN"] = "self-test-delegated-token"
        os.environ["CDSE_MCP_ORG"] = "SelfTestOrg"
        os.environ["CDSE_MCP_STORAGE"] = "SelfTestStorage"
        os.environ["CDSE_MCP_USER"] = "SelfTestUser"
        cfg = Config()
        os.environ["CDSE_MCP_DELEGATED_TOKEN_SECRET"] = "self-test-secret"
        os.environ["CDSE_MCP_DELEGATED_TOKEN"] = self_test_token(cfg, [
            write_scope("create_workspace", cfg),
            write_scope("upload_csv", cfg, cfg.csv_doc),
            write_scope("promote_parser_review", cfg, cfg.pending_parser_doc),
            write_scope("delete_document", cfg, f"file.csv:{cfg.csv_doc}"),
        ])
        cfg = Config()
        tools = available_tools(cfg)
        for name in WRITE_TOOLS:
            if name not in tools:
                raise AssertionError(f"guarded write tool missing when explicitly enabled: {name}")

        args = scoped_guard_args(cfg, "create_workspace")
        result = create_workspace(cfg, args)
        if not result.get("guard", {}).get("dryRun"):
            raise AssertionError("guarded dry-run create_workspace did not return dryRun guard metadata")

        bad_args = dict(args)
        bad_args["scope"] = "*"
        try:
            create_workspace(cfg, bad_args)
            raise AssertionError("broad write scope was accepted")
        except ToolError:
            pass

        upload_args = scoped_guard_args(cfg, "upload_csv", cfg.csv_doc, expected_status=201)
        upload_result = upload_csv(cfg, upload_args)
        if upload_result.get("wouldUpload", {}).get("documentType") != "file.csv":
            raise AssertionError("guarded dry-run upload_csv did not report target document")

        promote_args = scoped_guard_args(cfg, "promote_parser_review", cfg.pending_parser_doc, expected_status=200)
        promote_result = promote_parser_review(cfg, promote_args)
        if promote_result.get("wouldUpdate", {}).get("reviewStatus") != "reviewed":
            raise AssertionError("guarded dry-run promote_parser_review did not report reviewed metadata")

        delete_args = scoped_guard_args(cfg, "delete_document", f"file.csv:{cfg.csv_doc}", expected_status=200)
        delete_args["document_type"] = "file.csv"
        delete_args["document"] = cfg.csv_doc
        delete_result = delete_document(cfg, delete_args)
        if delete_result.get("wouldDelete", {}).get("document") != cfg.csv_doc:
            raise AssertionError("guarded dry-run delete_document did not report exact target")

        broad_delete_args = dict(delete_args)
        broad_delete_args["scope"] = "document:delete:*"
        try:
            delete_document(cfg, broad_delete_args)
            raise AssertionError("broad delete scope was accepted")
        except ToolError:
            pass

        bad_type_args = dict(delete_args)
        bad_type_args["document_type"] = "file.raw"
        try:
            delete_document(cfg, bad_type_args)
            raise AssertionError("unsupported delete document_type was accepted")
        except ToolError:
            pass

        os.environ["CDSE_MCP_DELEGATED_TOKEN"] = self_test_token(cfg, ["document:read:*"])
        cfg = Config()
        try:
            create_workspace(cfg, args)
            raise AssertionError("delegated token missing write scope was accepted")
        except ToolError:
            pass
    finally:
        for key, value in saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    print("PASS MCP write guard self-test")


def serve():
    cfg = Config()
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            request_obj = json.loads(line)
        except json.JSONDecodeError as exc:
            write_response({"jsonrpc": "2.0", "id": None, "error": json_rpc_error(-32700, str(exc))})
            continue
        request_id = request_obj.get("id")
        try:
            result = handle_request(cfg, request_obj)
        except KeyError as exc:
            if request_id is not None:
                write_response({"jsonrpc": "2.0", "id": request_id, "error": json_rpc_error(-32601, str(exc))})
            continue
        except Exception as exc:
            if request_id is not None:
                write_response({"jsonrpc": "2.0", "id": request_id, "error": json_rpc_error(-32603, str(exc))})
            continue
        if request_id is not None and result is not None:
            write_response({"jsonrpc": "2.0", "id": request_id, "result": result})


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Run the CaumeDSE MCP stdio prototype server.")
    parser.add_argument("--version", action="version", version=f"{SERVER_NAME} {SERVER_VERSION}")
    parser.add_argument("command", nargs="?", choices=["serve", "self-test"], default="serve")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    if args.command == "self-test":
        self_test()
        return
    serve()


if __name__ == "__main__":
    main()
