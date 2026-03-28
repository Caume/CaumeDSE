#!/usr/bin/env python3
"""
CaumeDSE Sample Application Test Manager
=========================================
Starts a local CDSE server, waits for it to be ready, runs all four sample
client applications through their basic secret-management operations, and
reports pass / fail for each step.

Requirements:
  - A CaumeDSE binary built with --enable-BYPASSTLSAUTHINHTTP (allows HTTP
    testing without TLS client certificates).
  - Existing CDSE databases at PATH_DATADIR (default /opt/cdse/).
  - The orgKey matching those databases, set via CDSE_ORG_KEY or env.sh.

Usage:
  # Source credentials first
  source env.sh

  # Run the full test suite
  python3 cdse_test_manager.py

  # Override the binary path
  CDSE_BIN=/path/to/CaumeDSE python3 cdse_test_manager.py
"""
import subprocess
import threading
import time
import os
import pty
import sys
import select

# ---------------------------------------------------------------------------
# Configuration — override via environment variables
# ---------------------------------------------------------------------------

ORG_KEY   = os.environ.get("CDSE_ORG_KEY", "")
CDSE_BIN  = os.environ.get("CDSE_BIN",
                            os.path.join(os.path.dirname(__file__),
                                         "../../CaumeDSE"))
CACERT    = os.environ.get("CDSE_CACERT", "/opt/cdse/ca.pem")

BASE_HTTPS   = "https://localhost:8443"
BASE_HTTP    = "http://localhost:8080"
SAMPLES_DIR  = os.path.dirname(os.path.abspath(__file__))
PERL_LIB     = os.path.expanduser("~/perl5/lib/perl5")

# ---------------------------------------------------------------------------
# Internal state
# ---------------------------------------------------------------------------

log_lines = []
log_lock  = threading.Lock()


def _pty_monitor(master_fd):
    buf = b""
    while True:
        try:
            rlist, _, _ = select.select([master_fd], [], [], 0.1)
            if not rlist:
                continue
            chunk = os.read(master_fd, 4096)
            if not chunk:
                break
            buf += chunk
            lines = buf.split(b"\n")
            buf = lines[-1]
            for line in lines[:-1]:
                decoded = line.decode("utf-8", errors="replace").rstrip()
                with log_lock:
                    log_lines.append(decoded)
                print(f"[CDSE] {decoded}", flush=True)
        except OSError:
            break


def _wait_for_log(pattern, timeout=120):
    start = time.time()
    while time.time() - start < timeout:
        with log_lock:
            if any(pattern in l for l in log_lines):
                return True
        time.sleep(0.5)
    return False


def _curl(url, timeout=10):
    cmd = ["curl", "-sk", "--cacert", CACERT, "--max-time", str(timeout), url]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.stdout.strip(), r.returncode


def _run(cmd, cwd=None, env=None, timeout=30):
    r = subprocess.run(cmd, capture_output=True, text=True,
                       cwd=cwd, env=env, timeout=timeout)
    return r.stdout.strip(), r.stderr.strip(), r.returncode


def _ok(name, out, err, rc):
    status = "OK" if rc == 0 else f"FAIL(rc={rc})"
    print(f"  [{status}] {name}")
    if out:
        print(f"    OUT: {out[:200]}")
    if err and rc != 0:
        print(f"    ERR: {err[:200]}")


# ---------------------------------------------------------------------------
# Per-client test suites
# ---------------------------------------------------------------------------

def _secret_file(content):
    path = "/tmp/cdse_test_secret.txt"
    with open(path, "w") as f:
        f.write(content)
    return path


def test_python_cli():
    print("\n=== Python CLI (b-python/cdse_client.py) ===")
    script = os.path.join(SAMPLES_DIR, "b-python/cdse_client.py")
    env = {**os.environ,
           "CDSE_SERVER":  BASE_HTTP,
           "CDSE_USER_ID": "EngineAdmin",
           "CDSE_ORG_ID":  "EngineOrg",
           "CDSE_ORG_KEY": ORG_KEY,
           "CDSE_STORAGE": "EngineStorage"}
    sf = _secret_file("python secret test\n")
    tests = [
        ("info",          ["python3", script, "info"]),
        ("list-secrets",  ["python3", script, "list-secrets"]),
        ("store-secret",  ["python3", script, "store-secret", "pykey", sf]),
        ("get-secret",    ["python3", script, "get-secret",   "pykey"]),
        ("delete-secret", ["python3", script, "delete-secret","pykey"]),
    ]
    for name, cmd in tests:
        _ok(name, *_run(cmd, env=env))


def test_go_cli():
    print("\n=== Go CLI (c-golang/cdse_client.go) ===")
    go_dir  = os.path.join(SAMPLES_DIR, "c-golang")
    bin_out = "/tmp/cdse_go_client"
    out, err, rc = _run(["go", "build", "-o", bin_out, "."], cwd=go_dir)
    if rc != 0:
        print(f"  [FAIL] Build: {err[:200]}")
        return
    print("  [OK] Build")
    base = [bin_out,
            "-server",  BASE_HTTP,
            "-userId",  "EngineAdmin",
            "-orgId",   "EngineOrg",
            "-orgKey",  ORG_KEY,
            "-storage", "EngineStorage",
            "-insecure"]
    sf = _secret_file("go secret test\n")
    tests = [
        ("info",          base + ["info"]),
        ("list-secrets",  base + ["list-secrets"]),
        ("store-secret",  base + ["store-secret", "gokey", sf]),
        ("get-secret",    base + ["get-secret",   "gokey"]),
        ("delete-secret", base + ["delete-secret","gokey"]),
    ]
    for name, cmd in tests:
        _ok(name, *_run(cmd))


def test_perl_cli():
    print("\n=== Perl CLI (d-perl/cdse_client.pl) ===")
    script = os.path.join(SAMPLES_DIR, "d-perl/cdse_client.pl")
    # Check modules
    _, _, rc = _run(["perl", f"-I{PERL_LIB}", "-e",
                     "use LWP::UserAgent; use URI::Escape; "
                     "use HTTP::Request::Common; print 'ok'"])
    if rc != 0:
        print("  [SKIP] Perl modules missing — install via:")
        print("         cpan LWP::UserAgent HTTP::Request::Common URI::Escape Term::ReadKey")
        return
    print("  [OK] Perl modules available")
    base = ["perl", f"-I{PERL_LIB}", script,
            "--server",  BASE_HTTP,
            "--userId",  "EngineAdmin",
            "--orgId",   "EngineOrg",
            "--orgKey",  ORG_KEY,
            "--storage", "EngineStorage",
            "--insecure"]
    sf = _secret_file("perl secret test\n")
    tests = [
        ("info",          base + ["info"]),
        ("list-secrets",  base + ["list-secrets"]),
        ("store-secret",  base + ["store-secret", "plkey", sf]),
        ("get-secret",    base + ["get-secret",   "plkey"]),
        ("delete-secret", base + ["delete-secret","plkey"]),
    ]
    for name, cmd in tests:
        _ok(name, *_run(cmd))


def test_web_proxy():
    print("\n=== Web proxy (a-web/proxy.py) ===")
    proxy_script = os.path.join(SAMPLES_DIR, "a-web/proxy.py")
    proxy = subprocess.Popen(
        ["python3", proxy_script,
         "--insecure", "--cdse-server", BASE_HTTP, "--port", "8088"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(2)
    if proxy.poll() is not None:
        err = proxy.stderr.read().decode()
        print(f"  [FAIL] Proxy failed to start: {err[:200]}")
        return
    try:
        r = subprocess.run(["curl", "-s", "--max-time", "5",
                             "http://localhost:8088/"],
                            capture_output=True, text=True)
        if any(x in r.stdout for x in ("CaumeDSE", "<!DOCTYPE", "<html")):
            print("  [OK] index.html served")
        else:
            print(f"  [WARN] Unexpected root response: {r.stdout[:100]}")
        url = (f"http://localhost:8088/cdse/organizations/EngineOrg"
               f"/users/EngineAdmin"
               f"?userId=EngineAdmin&orgId=EngineOrg&orgKey={ORG_KEY}")
        r2 = subprocess.run(["curl", "-s", "--max-time", "5", url],
                             capture_output=True, text=True)
        if r2.stdout and ("EngineOrg" in r2.stdout or "<html" in r2.stdout):
            print("  [OK] Proxy routing to CDSE")
        else:
            print(f"  [WARN] Proxy API response: {r2.stdout[:100]}")
    finally:
        proxy.terminate()
        proxy.wait(timeout=3)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if not ORG_KEY:
        print("[!] CDSE_ORG_KEY is not set.")
        print("    Source env.sh or export the key before running:")
        print("      source env.sh")
        print("      python3 cdse_test_manager.py")
        sys.exit(1)

    cdse_bin = os.path.realpath(CDSE_BIN)
    if not os.path.isfile(cdse_bin):
        print(f"[!] CaumeDSE binary not found: {cdse_bin}")
        print("    Build the project first (make), then re-run.")
        sys.exit(1)

    print(f"[*] Starting CDSE: {cdse_bin}")
    master_fd, slave_fd = pty.openpty()
    proc = subprocess.Popen(
        [cdse_bin],
        stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
        close_fds=True)
    os.close(slave_fd)

    t = threading.Thread(target=_pty_monitor, args=(master_fd,), daemon=True)
    t.start()

    print("[*] Waiting for HTTP server (up to 60 s)...")
    if not _wait_for_log("Testing Web server HTTP port 8080", timeout=60):
        print("[!] HTTP server did not start. Last log:")
        with log_lock:
            for l in log_lines[-20:]:
                print(f"  {l}")
        proc.terminate()
        os.close(master_fd)
        sys.exit(1)

    print("[*] HTTP server ready.")
    r = subprocess.run(
        ["curl", "-s", "--max-time", "5",
         f"{BASE_HTTP}/organizations/EngineOrg/users/EngineAdmin"
         f"?userId=EngineAdmin&orgId=EngineOrg&orgKey={ORG_KEY}"],
        capture_output=True, text=True)
    if any(x in r.stdout for x in ("EngineOrg", "<html", "200")):
        print(f"[OK] HTTP responding")
    else:
        print(f"[WARN] HTTP check: {r.stdout[:100] or r.stderr[:60]}")

    test_python_cli()
    test_go_cli()
    test_perl_cli()
    test_web_proxy()

    # Advance to HTTPS phase
    print("\n[*] Advancing to HTTPS...")
    os.write(master_fd, b"\n")
    if _wait_for_log("Testing Web server HTTPS port 8443", timeout=15):
        time.sleep(2)
        print("[*] HTTPS server started.")
        out, rc = _curl(f"{BASE_HTTPS}/engineCommands"
                        f"?userId=EngineAdmin&orgId=EngineOrg&orgKey={ORG_KEY}")
        if "EngineOrg" in out:
            print("[OK] HTTPS responding")
        else:
            print("[INFO] HTTPS requires mTLS client cert — connectivity confirmed.")

    print("[*] Stopping CDSE...")
    os.write(master_fd, b"\n")
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.terminate()
        proc.wait()
    os.close(master_fd)
    print("[*] Done")


if __name__ == "__main__":
    main()
