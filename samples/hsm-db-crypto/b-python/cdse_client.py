#!/usr/bin/env python3
"""
cdse_client.py — CaumeDSE REST API sample client

CaumeDSE (Caume Data Security Engine) is a REST API that provides an
HSM-like interface for encrypted secrets storage, an encrypted CSV
database engine, and a general cryptographic services layer.

This client supports two usage modes:

  1. Interactive mode (-i / --interactive):
     Prompts for credentials once (org key is hidden via getpass),
     then enters a 'cdse> ' REPL accepting commands with readline
     line-editing support.

  2. One-shot / parameter mode (default):
     Credentials are supplied as CLI flags or environment variables.
     The command and its arguments follow the options positionally.

Environment variables (used when CLI flags are omitted):
  CDSE_SERVER    — host:port  (default: localhost:8443)
  CDSE_USER_ID   — userId
  CDSE_ORG_ID    — orgId
  CDSE_ORG_KEY   — orgKey     (avoid; prefer interactive or --org-key)
  CDSE_STORAGE   — storage bucket name (default: EngineStorage)

Commands:
  info                              — show user/org info
  list-secrets                      — list raw-file documents
  store-secret NAME FILE [INFO]     — upload FILE as encrypted secret NAME
  get-secret NAME [OUTPUT_FILE]     — retrieve secret (prints if no output)
  delete-secret NAME                — delete a secret
  db-list                           — list CSV documents
  db-create NAME col1,col2,...      — create CSV DB with given column headers
  db-insert NAME col=val ...        — append a row
  db-query NAME [ROW]               — show all rows or a specific row N
  db-update NAME ROW col=val ...    — update columns in row N
  db-delete-row NAME ROW            — delete row N
  db-delete NAME                    — delete entire CSV document
  audit-log                         — show the transaction audit log

Usage examples:

  # One-shot — store a secret
  python3 cdse_client.py --server localhost:8443 --user-id alice \\
      --org-id acme --org-key s3cr3t \\
      store-secret mykey /tmp/key.pem "RSA private key"

  # One-shot — retrieve a secret to file
  CDSE_SERVER=localhost:8443 CDSE_USER_ID=alice CDSE_ORG_ID=acme \\
  CDSE_ORG_KEY=s3cr3t python3 cdse_client.py get-secret mykey /tmp/out.pem

  # Interactive session
  python3 cdse_client.py -i --server localhost:8443 --user-id alice \\
      --org-id acme
"""

import argparse
import csv
import getpass
import io
import os
import sys
import textwrap
import warnings

try:
    import readline  # noqa: F401 — imported for side-effect (line editing)
except ImportError:
    pass  # readline not available on all platforms (e.g. Windows)

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
except ImportError:
    sys.exit("Error: the 'requests' library is required.  "
             "Install it with:  pip install requests")

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _make_session(ca_cert=None, insecure=False):
    """Return a configured requests.Session."""
    session = requests.Session()
    if insecure:
        warnings.warn(
            "TLS verification is DISABLED (--insecure).  "
            "This is unsafe outside of development/testing.",
            stacklevel=2,
        )
        session.verify = False
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    elif ca_cert:
        session.verify = ca_cert
    return session


def _base_url(server):
    """Normalise the server string to a full HTTPS base URL."""
    server = server.strip().rstrip("/")
    if not server.startswith("http"):
        server = "https://" + server
    return server


def _auth_params(cfg):
    """Return the mandatory authentication query-parameters dict."""
    return {
        "userId": cfg["user_id"],
        "orgId":  cfg["org_id"],
        "orgKey": cfg["org_key"],
    }


def _check(resp):
    """
    Print a human-readable error and return False if the response is not 2xx.
    Returns True on success.
    """
    if resp.ok:
        return True
    print(f"[ERROR] HTTP {resp.status_code} {resp.reason}")
    body = resp.text.strip()
    if body:
        print(body)
    return False


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------

def cmd_info(session, cfg):
    """GET /organizations/{orgId}/users/{userId}"""
    url = (f"{cfg['base']}/organizations/{cfg['org_id']}"
           f"/users/{cfg['user_id']}")
    resp = session.get(url, params=_auth_params(cfg))
    if _check(resp):
        print(resp.text.strip())


def cmd_list_secrets(session, cfg):
    """List raw-file documents in storage."""
    url = (f"{cfg['base']}/organizations/{cfg['org_id']}"
           f"/storage/{cfg['storage']}"
           f"/documentTypes/file.raw/documents")
    resp = session.get(url, params=_auth_params(cfg))
    if _check(resp):
        print(resp.text.strip())


def cmd_store_secret(session, cfg, name, filepath, info=None):
    """Upload FILE as an AES-encrypted secret stored under NAME."""
    url = (f"{cfg['base']}/organizations/{cfg['org_id']}"
           f"/storage/{cfg['storage']}"
           f"/documentTypes/file.raw/documents/{name}")
    params = dict(_auth_params(cfg))
    if info:
        params["*resourceInfo"] = info
    try:
        with open(filepath, "rb") as fh:
            files = {"file": (os.path.basename(filepath), fh)}
            resp = session.post(url, params=params, files=files)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        return
    if _check(resp):
        print(f"Stored secret '{name}'.")


def cmd_get_secret(session, cfg, name, output_file=None):
    """Retrieve (decrypt) secret NAME; write to OUTPUT_FILE or stdout."""
    url = (f"{cfg['base']}/organizations/{cfg['org_id']}"
           f"/storage/{cfg['storage']}"
           f"/documentTypes/file.raw/documents/{name}/content")
    resp = session.get(url, params=_auth_params(cfg))
    if not _check(resp):
        return
    if output_file:
        try:
            with open(output_file, "wb") as fh:
                fh.write(resp.content)
            print(f"Written to '{output_file}'.")
        except OSError as exc:
            print(f"[ERROR] Could not write output file: {exc}")
    else:
        # Best-effort text decode; fall back to a hex summary for binary data.
        try:
            print(resp.content.decode("utf-8"))
        except UnicodeDecodeError:
            print(f"<binary content, {len(resp.content)} bytes — "
                  "use get-secret NAME OUTPUT_FILE to save>")


def cmd_delete_secret(session, cfg, name):
    """Delete a single raw-file secret."""
    url = (f"{cfg['base']}/organizations/{cfg['org_id']}"
           f"/storage/{cfg['storage']}"
           f"/documentTypes/file.raw/documents/{name}")
    resp = session.delete(url, params=_auth_params(cfg))
    if _check(resp):
        print(f"Deleted secret '{name}'.")


# --- CSV / encrypted-database commands -------------------------------------

def cmd_db_list(session, cfg):
    """List CSV documents in storage."""
    url = (f"{cfg['base']}/organizations/{cfg['org_id']}"
           f"/storage/{cfg['storage']}"
           f"/documentTypes/file.csv/documents")
    resp = session.get(url, params=_auth_params(cfg))
    if _check(resp):
        print(resp.text.strip())


def cmd_db_create(session, cfg, name, columns_str):
    """
    Create a new encrypted CSV document with the given comma-separated
    column headers.  Uploads a header-only CSV file via multipart POST.
    """
    url = (f"{cfg['base']}/organizations/{cfg['org_id']}"
           f"/storage/{cfg['storage']}"
           f"/documentTypes/file.csv/documents/{name}")
    # Build an in-memory CSV containing only the header row.
    header_csv = columns_str.strip() + "\r\n"
    files = {"file": (f"{name}.csv", io.BytesIO(header_csv.encode()), "text/csv")}
    resp = session.post(url, params=_auth_params(cfg), files=files)
    if _check(resp):
        print(f"Created CSV document '{name}' with columns: {columns_str}")


def _count_rows(session, cfg, name):
    """
    Return the number of data rows currently stored in CSV document NAME.
    Fetches all content as CSV and counts non-header lines.
    Returns None on error.
    """
    url = (f"{cfg['base']}/organizations/{cfg['org_id']}"
           f"/storage/{cfg['storage']}"
           f"/documentTypes/file.csv/documents/{name}/content")
    params = dict(_auth_params(cfg))
    params["outputType"] = "csv"
    resp = session.get(url, params=params)
    if not resp.ok:
        return None
    lines = [l for l in resp.text.splitlines() if l.strip()]
    # First line is the header; remaining lines are data rows.
    return max(0, len(lines) - 1)


def cmd_db_insert(session, cfg, name, col_val_pairs):
    """
    Append a row to CSV document NAME.
    col_val_pairs is a list of "col=val" strings.
    Automatically determines the next row index (current count + 1).
    """
    row_count = _count_rows(session, cfg, name)
    if row_count is None:
        print(f"[ERROR] Could not determine row count for '{name}'.")
        return
    next_row = row_count + 1

    url = (f"{cfg['base']}/organizations/{cfg['org_id']}"
           f"/storage/{cfg['storage']}"
           f"/documentTypes/file.csv/documents/{name}"
           f"/contentRows/{next_row}")
    params = dict(_auth_params(cfg))
    for pair in col_val_pairs:
        if "=" not in pair:
            print(f"[ERROR] Expected col=val, got: {pair!r}")
            return
        col, _, val = pair.partition("=")
        params[f"[{col.strip()}]"] = val
    resp = session.post(url, params=params)
    if _check(resp):
        print(f"Inserted row {next_row} into '{name}'.")


def cmd_db_query(session, cfg, name, row=None):
    """
    Show all rows (row=None) or a specific row number from CSV document NAME.
    """
    if row is None:
        url = (f"{cfg['base']}/organizations/{cfg['org_id']}"
               f"/storage/{cfg['storage']}"
               f"/documentTypes/file.csv/documents/{name}/content")
        params = dict(_auth_params(cfg))
        params["outputType"] = "csv"
    else:
        url = (f"{cfg['base']}/organizations/{cfg['org_id']}"
               f"/storage/{cfg['storage']}"
               f"/documentTypes/file.csv/documents/{name}"
               f"/contentRows/{row}")
        params = _auth_params(cfg)
    resp = session.get(url, params=params)
    if _check(resp):
        print(resp.text.strip())


def cmd_db_update(session, cfg, name, row, col_val_pairs):
    """Update columns in row ROW of CSV document NAME."""
    url = (f"{cfg['base']}/organizations/{cfg['org_id']}"
           f"/storage/{cfg['storage']}"
           f"/documentTypes/file.csv/documents/{name}"
           f"/contentRows/{row}")
    params = dict(_auth_params(cfg))
    for pair in col_val_pairs:
        if "=" not in pair:
            print(f"[ERROR] Expected col=val, got: {pair!r}")
            return
        col, _, val = pair.partition("=")
        params[f"[{col.strip()}]"] = val
    resp = session.put(url, params=params)
    if _check(resp):
        print(f"Updated row {row} in '{name}'.")


def cmd_db_delete_row(session, cfg, name, row):
    """Delete row ROW from CSV document NAME."""
    url = (f"{cfg['base']}/organizations/{cfg['org_id']}"
           f"/storage/{cfg['storage']}"
           f"/documentTypes/file.csv/documents/{name}"
           f"/contentRows/{row}")
    resp = session.delete(url, params=_auth_params(cfg))
    if _check(resp):
        print(f"Deleted row {row} from '{name}'.")


def cmd_db_delete(session, cfg, name):
    """Delete an entire CSV document (all rows and the document itself)."""
    url = (f"{cfg['base']}/organizations/{cfg['org_id']}"
           f"/storage/{cfg['storage']}"
           f"/documentTypes/file.csv/documents/{name}")
    resp = session.delete(url, params=_auth_params(cfg))
    if _check(resp):
        print(f"Deleted CSV document '{name}'.")


def cmd_audit_log(session, cfg):
    """Retrieve the transaction audit log as CSV."""
    url = f"{cfg['base']}/transactions"
    params = dict(_auth_params(cfg))
    params["outputType"] = "csv"
    resp = session.get(url, params=params)
    if _check(resp):
        print(resp.text.strip())


# ---------------------------------------------------------------------------
# Command dispatcher
# ---------------------------------------------------------------------------

COMMANDS = {
    "info":           ("info",
                       "Show user/org info."),
    "list-secrets":   ("list-secrets",
                       "List raw-file (secret) documents."),
    "store-secret":   ("store-secret NAME FILE [INFO]",
                       "Upload FILE as encrypted secret NAME."),
    "get-secret":     ("get-secret NAME [OUTPUT_FILE]",
                       "Retrieve and decrypt secret NAME."),
    "delete-secret":  ("delete-secret NAME",
                       "Delete secret NAME."),
    "db-list":        ("db-list",
                       "List CSV documents."),
    "db-create":      ("db-create NAME col1,col2,...",
                       "Create encrypted CSV DB with given column headers."),
    "db-insert":      ("db-insert NAME col=val ...",
                       "Append a row to CSV document NAME."),
    "db-query":       ("db-query NAME [ROW]",
                       "Show all rows, or row ROW, from CSV document NAME."),
    "db-update":      ("db-update NAME ROW col=val ...",
                       "Update columns in row ROW of CSV document NAME."),
    "db-delete-row":  ("db-delete-row NAME ROW",
                       "Delete row ROW from CSV document NAME."),
    "db-delete":      ("db-delete NAME",
                       "Delete entire CSV document NAME."),
    "audit-log":      ("audit-log",
                       "Show the transaction audit log."),
}


def dispatch(session, cfg, args):
    """
    Execute a single command described by the list 'args'.
    Returns False if the command is unrecognised.
    """
    if not args:
        return False
    cmd = args[0].lower()
    rest = args[1:]

    if cmd == "info":
        cmd_info(session, cfg)
    elif cmd == "list-secrets":
        cmd_list_secrets(session, cfg)
    elif cmd == "store-secret":
        if len(rest) < 2:
            print("Usage: store-secret NAME FILE [INFO]")
        else:
            cmd_store_secret(session, cfg, rest[0], rest[1],
                             rest[2] if len(rest) > 2 else None)
    elif cmd == "get-secret":
        if len(rest) < 1:
            print("Usage: get-secret NAME [OUTPUT_FILE]")
        else:
            cmd_get_secret(session, cfg, rest[0],
                           rest[1] if len(rest) > 1 else None)
    elif cmd == "delete-secret":
        if len(rest) < 1:
            print("Usage: delete-secret NAME")
        else:
            cmd_delete_secret(session, cfg, rest[0])
    elif cmd == "db-list":
        cmd_db_list(session, cfg)
    elif cmd == "db-create":
        if len(rest) < 2:
            print("Usage: db-create NAME col1,col2,...")
        else:
            cmd_db_create(session, cfg, rest[0], rest[1])
    elif cmd == "db-insert":
        if len(rest) < 2:
            print("Usage: db-insert NAME col=val ...")
        else:
            cmd_db_insert(session, cfg, rest[0], rest[1:])
    elif cmd == "db-query":
        if len(rest) < 1:
            print("Usage: db-query NAME [ROW]")
        else:
            cmd_db_query(session, cfg, rest[0],
                         rest[1] if len(rest) > 1 else None)
    elif cmd == "db-update":
        if len(rest) < 3:
            print("Usage: db-update NAME ROW col=val ...")
        else:
            cmd_db_update(session, cfg, rest[0], rest[1], rest[2:])
    elif cmd == "db-delete-row":
        if len(rest) < 2:
            print("Usage: db-delete-row NAME ROW")
        else:
            cmd_db_delete_row(session, cfg, rest[0], rest[1])
    elif cmd == "db-delete":
        if len(rest) < 1:
            print("Usage: db-delete NAME")
        else:
            cmd_db_delete(session, cfg, rest[0])
    elif cmd == "audit-log":
        cmd_audit_log(session, cfg)
    else:
        return False  # unrecognised
    return True


def print_help():
    """Print available commands."""
    print("Available commands:")
    for syntax, desc in COMMANDS.values():
        print(f"  {syntax:<36}  {desc}")
    print("  help                                  Show this help.")
    print("  exit / quit                           Leave the interactive session.")


# ---------------------------------------------------------------------------
# Interactive REPL
# ---------------------------------------------------------------------------

def interactive_loop(session, cfg):
    """Run the interactive command prompt."""
    print("CaumeDSE interactive client.  Type 'help' for commands, "
          "'exit' to quit.")
    while True:
        try:
            line = input("cdse> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        tokens = line.split()
        cmd = tokens[0].lower()
        if cmd in ("exit", "quit"):
            break
        if cmd == "help":
            print_help()
            continue
        if not dispatch(session, cfg, tokens):
            print(f"Unknown command: {tokens[0]!r}  (type 'help' for list)")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="cdse_client.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="CaumeDSE REST API client — HSM / encrypted-DB / crypto interface.",
        epilog=textwrap.dedent("""\
            Examples:
              # Interactive session (org key entered securely via prompt)
              python3 cdse_client.py -i --server localhost:8443 \\
                  --user-id alice --org-id acme

              # One-shot: store a secret
              python3 cdse_client.py --user-id alice --org-id acme \\
                  --org-key s3cr3t store-secret api-key /tmp/api.key "API token"

              # One-shot via environment variables
              export CDSE_USER_ID=alice CDSE_ORG_ID=acme CDSE_ORG_KEY=s3cr3t
              python3 cdse_client.py info

              # Create an encrypted CSV database
              python3 cdse_client.py ... db-create payroll name,role,salary

              # Insert a row
              python3 cdse_client.py ... db-insert payroll name=Bob role=Eng salary=90000

              # Query all rows
              python3 cdse_client.py ... db-query payroll

              # Update row 1
              python3 cdse_client.py ... db-update payroll 1 salary=95000

              # Skip TLS verification (development only)
              python3 cdse_client.py -k --user-id alice --org-id acme \\
                  --org-key s3cr3t info
        """),
    )

    # Connection / TLS options
    parser.add_argument(
        "--server", "-s",
        default=os.environ.get("CDSE_SERVER", "localhost:8443"),
        metavar="HOST:PORT",
        help="CaumeDSE server (default: localhost:8443 or $CDSE_SERVER).",
    )
    parser.add_argument(
        "--ca-cert",
        default=None,
        metavar="FILE",
        help="Path to CA certificate bundle for TLS verification.",
    )
    parser.add_argument(
        "--insecure", "-k",
        action="store_true",
        help="Disable TLS certificate verification (unsafe; dev/test only).",
    )

    # Credentials
    parser.add_argument(
        "--user-id", "-u",
        default=os.environ.get("CDSE_USER_ID"),
        metavar="USER_ID",
        help="userId credential (or set $CDSE_USER_ID).",
    )
    parser.add_argument(
        "--org-id", "-o",
        default=os.environ.get("CDSE_ORG_ID"),
        metavar="ORG_ID",
        help="orgId credential (or set $CDSE_ORG_ID).",
    )
    parser.add_argument(
        "--org-key", "-p",
        default=os.environ.get("CDSE_ORG_KEY"),
        metavar="ORG_KEY",
        help="orgKey (organisation encryption key).  Prefer $CDSE_ORG_KEY or "
             "the interactive prompt to avoid exposure in shell history.",
    )
    parser.add_argument(
        "--storage",
        default=os.environ.get("CDSE_STORAGE", "EngineStorage"),
        metavar="STORAGE",
        help="Storage bucket name (default: EngineStorage or $CDSE_STORAGE).",
    )

    # Mode
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Start an interactive command session.",
    )

    # Positional command (one-shot mode)
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        metavar="COMMAND [ARGS...]",
        help="Command to execute (one-shot mode).",
    )

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = build_parser()
    args = parser.parse_args()

    # Validate required credentials.
    missing = []
    if not args.user_id:
        missing.append("--user-id / $CDSE_USER_ID")
    if not args.org_id:
        missing.append("--org-id / $CDSE_ORG_ID")
    if missing:
        parser.error("Missing required credentials: " + ", ".join(missing))

    # Obtain org key: CLI arg > env var > interactive prompt.
    org_key = args.org_key
    if not org_key:
        if args.interactive or not args.command:
            # Prompt securely so the key does not echo to the terminal.
            org_key = getpass.getpass(
                prompt=f"orgKey for org '{args.org_id}': "
            )
        else:
            parser.error(
                "orgKey is required.  Supply --org-key, set $CDSE_ORG_KEY, "
                "or use -i for an interactive session with a secure prompt."
            )

    # Build shared configuration dict.
    cfg = {
        "base":    _base_url(args.server),
        "user_id": args.user_id,
        "org_id":  args.org_id,
        "org_key": org_key,
        "storage": args.storage,
    }

    session = _make_session(ca_cert=args.ca_cert, insecure=args.insecure)

    if args.interactive:
        interactive_loop(session, cfg)
    elif args.command:
        if not dispatch(session, cfg, args.command):
            print(f"Unknown command: {args.command[0]!r}")
            print_help()
            sys.exit(1)
    else:
        # No command given in one-shot mode: show help.
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
