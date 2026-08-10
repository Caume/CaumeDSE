# CaumeDSE Operational Readiness

This sample reports a safe readiness view for operators, monitoring, and
AI-agent preflight checks. It does not read protected data and it redacts
credential-style fields before printing output.

## Commands

Render JSON readiness:

```sh
python3 samples/operational-readiness/readiness_check.py check \
  --storage-path TEST \
  --parser-temp-dir /tmp \
  --storage-profile aes-256-cbc \
  --tls-auth-state required \
  --build-mode release \
  --parser-policy-enabled
```

Render concise operator text:

```sh
python3 samples/operational-readiness/readiness_check.py check --output text
```

Run offline checks:

```sh
python3 samples/operational-readiness/readiness_check.py self-test
```

## Readiness States

- `healthy`: all declared checks are safe and usable.
- `degraded`: usable, but a non-critical capability is missing or unknown.
- `misconfigured`: required paths or selected crypto profiles are not usable.
- `unsafe`: DEBUG-only or insecure settings are active.

The JSON output is marked `safeForAgent:true` and avoids organization keys,
private keys, access passwords, OAuth secrets, and document contents.
