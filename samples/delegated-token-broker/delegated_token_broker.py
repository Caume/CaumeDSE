#!/usr/bin/env python3
"""
Delegated scoped-token broker sample for CaumeDSE.

CaumeDSE does not validate bearer tokens internally. This sample shows the
external-manager pattern: validate an opaque short-lived token in the broker,
then forward the request to CaumeDSE with broker-held delegated credentials.
"""

import argparse
import base64
import fnmatch
import hashlib
import hmac
import json
import os
import secrets
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


DEFAULT_TOKEN_TTL = 900
DEFAULT_REVOKED_STORE = Path("/tmp/caumedse-delegated-revoked.json")
READ_ONLY_SCOPES = (
    "agentCapabilities:read",
    "documentTypes:read",
    "documents:read",
    "contentRows:read",
    "contentColumns:read",
    "dbBrowse:read",
    "parserScripts:run",
)


class BrokerError(Exception):
    pass


class Config:
    def __init__(self, args):
        run_id = os.environ.get("CDSE_BROKER_RUN_ID") or str(int(time.time()))
        self.base_url = os.environ.get("CDSE_BROKER_BASE_URL", "http://localhost:18080").rstrip("/")
        self.admin_org = os.environ.get("CDSE_BROKER_ADMIN_ORG", f"BrokerAdminOrg{run_id}")
        self.admin_user = os.environ.get("CDSE_BROKER_ADMIN_USER", f"BrokerAdminUser{run_id}")
        self.admin_key = os.environ.get("CDSE_BROKER_ADMIN_ORG_KEY")
        self.delegated_org = os.environ.get("CDSE_BROKER_DELEGATED_ORG", self.admin_org)
        self.delegated_user = os.environ.get("CDSE_BROKER_DELEGATED_USER", f"BrokerAgentUser{run_id}")
        self.delegated_key = os.environ.get("CDSE_BROKER_DELEGATED_ORG_KEY", self.admin_key)
        self.storage = os.environ.get("CDSE_BROKER_STORAGE", f"BrokerAgentStorage{run_id}")
        self.storage_path = os.environ.get("CDSE_BROKER_STORAGE_PATH", f"/tmp/caumedse-broker-storage-{run_id}")
        self.signing_secret = os.environ.get("CDSE_BROKER_SIGNING_SECRET")
        self.revoked_store = Path(os.environ.get("CDSE_BROKER_REVOKED_STORE", str(DEFAULT_REVOKED_STORE)))
        self.ca_cert = os.environ.get("CDSE_BROKER_CA_CERT")
        self.client_cert = os.environ.get("CDSE_BROKER_CLIENT_CERT")
        self.client_key = os.environ.get("CDSE_BROKER_CLIENT_KEY")
        self.now = args.now or int(time.time())

    def require_signing_secret(self):
        if not self.signing_secret:
            raise SystemExit("Set CDSE_BROKER_SIGNING_SECRET before minting or validating tokens.")

    def require_admin_credentials(self):
        if not self.admin_key:
            raise SystemExit("Set CDSE_BROKER_ADMIN_ORG_KEY before provisioning delegated CaumeDSE resources.")

    def admin_auth(self):
        return {
            "userId": self.admin_user,
            "orgId": self.admin_org,
            "orgKey": self.admin_key,
            "newOrgKey": self.admin_key,
        }

    def delegated_auth(self):
        return {
            "userId": self.delegated_user,
            "orgId": self.delegated_org,
            "orgKey": self.delegated_key,
        }


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text):
    padding = "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode((text + padding).encode("ascii"))


def sign_payload(payload, secret):
    return hmac.new(secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256).digest()


def mint_token(cfg, subject, scopes, ttl):
    issued_at = cfg.now
    claims = {
        "iss": "caumedse-delegated-token-broker-sample",
        "sub": subject,
        "iat": issued_at,
        "exp": issued_at + ttl,
        "jti": secrets.token_urlsafe(16),
        "scope": sorted(set(scopes)),
        "cdse": {
            "orgId": cfg.delegated_org,
            "userId": cfg.delegated_user,
        },
    }
    payload = b64url_encode(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = b64url_encode(sign_payload(payload, cfg.signing_secret))
    return f"{payload}.{signature}"


def load_revoked(path):
    if not path.exists():
        return set()
    return set(json.loads(path.read_text(encoding="utf-8")))


def save_revoked(path, revoked):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sorted(revoked), indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def verify_token(cfg, token, required_scope):
    try:
        payload, signature = token.split(".", 1)
        expected = b64url_encode(sign_payload(payload, cfg.signing_secret))
        if not hmac.compare_digest(signature, expected):
            raise BrokerError("bad signature")
        claims = json.loads(b64url_decode(payload).decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise BrokerError("malformed token") from exc

    if int(claims.get("exp", 0)) <= cfg.now:
        raise BrokerError("expired token")
    if claims.get("jti") in load_revoked(cfg.revoked_store):
        raise BrokerError("revoked token")
    scopes = claims.get("scope", [])
    if required_scope != "*" and not any(fnmatch.fnmatchcase(required_scope, scope) for scope in scopes):
        raise BrokerError(f"missing scope: {required_scope}")
    cdse = claims.get("cdse", {})
    if cdse.get("orgId") != cfg.delegated_org or cdse.get("userId") != cfg.delegated_user:
        raise BrokerError("token is not bound to the configured delegated CaumeDSE user")
    return claims


def revoke_token(cfg, token):
    claims = verify_token(cfg, token, "*")
    revoked = load_revoked(cfg.revoked_store)
    revoked.add(claims["jti"])
    save_revoked(cfg.revoked_store, revoked)
    return claims["jti"]


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


def request(cfg, method, path, params=None, expected=(200,)):
    url = build_url(cfg, path, params)
    print(f"{method:<6} {redact_url(url)}", file=sys.stderr)
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, context=ssl_context(cfg), timeout=30) as response:
            payload = response.read()
            status = response.status
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        status = exc.code
    if status not in expected:
        text = payload.decode("utf-8", errors="replace")
        raise BrokerError(f"{method} {path} returned {status}, expected {expected}: {text[:500]}")
    return status, payload


def provision_read_only_scope(cfg):
    cfg.require_admin_credentials()
    Path(cfg.storage_path).mkdir(parents=True, exist_ok=True)
    auth = cfg.admin_auth()
    request(
        cfg,
        "POST",
        f"/organizations/{urllib.parse.quote(cfg.admin_org)}",
        {
            **auth,
            "*resourceInfo": "delegated token broker manager organization",
            "*certificate": "undefined",
            "*publicKey": "undefined",
        },
        expected=(201, 409),
    )
    request(
        cfg,
        "POST",
        f"/organizations/{urllib.parse.quote(cfg.admin_org)}/storage/{urllib.parse.quote(cfg.storage)}",
        {
            **auth,
            "*resourceInfo": "delegated token broker storage",
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
        f"/organizations/{urllib.parse.quote(cfg.delegated_org)}/users/{urllib.parse.quote(cfg.delegated_user)}",
        {
            **auth,
            "*resourceInfo": "short-lived delegated agent user",
            "*certificate": "undefined",
            "*publicKey": "undefined",
            "*basicAuthPwdHash": "undefined",
            "*oauthConsumerKey": "external-broker",
            "*oauthConsumerSecret": "undefined",
        },
        expected=(201, 409),
    )
    for table in ("documentTypes", "documents", "data", "meta"):
        request(
            cfg,
            "POST",
            (
                f"/organizations/{urllib.parse.quote(cfg.delegated_org)}"
                f"/users/{urllib.parse.quote(cfg.delegated_user)}/roleTables/{urllib.parse.quote(table)}"
            ),
            {
                **auth,
                "*_get": "1",
                "*_post": "0",
                "*_put": "0",
                "*_delete": "0",
                "*_head": "1",
                "*_options": "1",
            },
            expected=(201, 409),
        )
    request(
        cfg,
        "POST",
        (
            f"/organizations/{urllib.parse.quote(cfg.delegated_org)}"
            f"/users/{urllib.parse.quote(cfg.delegated_user)}/filterWhitelist/{urllib.parse.quote(cfg.delegated_user)}"
        ),
        {
            **auth,
            "*_get": "1",
            "*_post": "0",
            "*_put": "0",
            "*_delete": "0",
            "*_head": "1",
            "*_options": "1",
        },
        expected=(201, 409),
    )


def delegated_request_preview(cfg, token, required_scope):
    claims = verify_token(cfg, token, required_scope)
    return {
        "subject": claims["sub"],
        "scope": required_scope,
        "expiresAt": claims["exp"],
        "caumedseAuth": {
            "userId": cfg.delegated_user,
            "orgId": cfg.delegated_org,
            "orgKey": "<held by broker>",
        },
    }


def run_self_test():
    old_env = os.environ.copy()
    try:
        os.environ["CDSE_BROKER_SIGNING_SECRET"] = "self-test-secret"
        os.environ["CDSE_BROKER_ADMIN_ORG_KEY"] = "self-test-org-key"
        os.environ["CDSE_BROKER_REVOKED_STORE"] = "/tmp/caumedse-delegated-token-self-test-revoked.json"
        cfg = Config(argparse.Namespace(now=1000))
        if cfg.revoked_store.exists():
            cfg.revoked_store.unlink()
        token = mint_token(cfg, "agent-a", ["documents:read", "contentRows:read"], 60)
        verify_token(cfg, token, "documents:read")
        try:
            verify_token(cfg, token, "documents:delete")
        except BrokerError:
            pass
        else:
            raise AssertionError("write scope was incorrectly allowed")
        expired_cfg = Config(argparse.Namespace(now=2000))
        try:
            verify_token(expired_cfg, token, "documents:read")
        except BrokerError:
            pass
        else:
            raise AssertionError("expired token was incorrectly allowed")
        revoke_token(cfg, token)
        try:
            verify_token(cfg, token, "documents:read")
        except BrokerError:
            pass
        else:
            raise AssertionError("revoked token was incorrectly allowed")
    finally:
        os.environ.clear()
        os.environ.update(old_env)
    print("PASS delegated token broker self-test")


def parse_scopes(value):
    scopes = [scope.strip() for scope in value.split(",") if scope.strip()]
    if not scopes:
        raise SystemExit("At least one scope is required.")
    return scopes


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Mint and validate delegated CaumeDSE agent tokens.")
    parser.add_argument("--now", type=int, help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command", required=True)

    mint = sub.add_parser("mint", help="Mint a short-lived opaque token.")
    mint.add_argument("--subject", required=True)
    mint.add_argument("--scopes", default=",".join(READ_ONLY_SCOPES))
    mint.add_argument("--ttl", type=int, default=DEFAULT_TOKEN_TTL)

    check = sub.add_parser("authorize", help="Validate a token for one requested scope.")
    check.add_argument("--token", required=True)
    check.add_argument("--scope", required=True)

    revoke = sub.add_parser("revoke", help="Revoke a token by jti.")
    revoke.add_argument("--token", required=True)

    sub.add_parser("provision-readonly", help="Create a delegated read-only CaumeDSE user and role/filter rows.")
    sub.add_parser("self-test", help="Run offline allow, deny, expiry, and revocation checks.")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    if args.command == "self-test":
        run_self_test()
        return 0

    cfg = Config(args)
    cfg.require_signing_secret()
    if args.command == "mint":
        print(mint_token(cfg, args.subject, parse_scopes(args.scopes), args.ttl))
    elif args.command == "authorize":
        print(json.dumps(delegated_request_preview(cfg, args.token, args.scope), indent=2, sort_keys=True))
    elif args.command == "revoke":
        print(revoke_token(cfg, args.token))
    elif args.command == "provision-readonly":
        provision_read_only_scope(cfg)
        print("Provisioned delegated read-only scope.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
