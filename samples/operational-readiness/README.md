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

Load declared settings from JSON:

```sh
python3 samples/operational-readiness/readiness_check.py check \
  --config samples/operational-readiness/config.example.json
```

Environment variables such as `CDSE_READINESS_STORAGE_PATH`,
`CDSE_READINESS_STORAGE_PROFILE`, `CDSE_READINESS_HERRADURA_AVAILABLE`, and
`CDSE_READINESS_TLS_AUTH_STATE` override the config file.

Render concise operator text:

```sh
python3 samples/operational-readiness/readiness_check.py check --output text
```

Compare a current report against a known-good baseline:

```sh
python3 samples/operational-readiness/readiness_check.py compare \
  --current readiness-current.json \
  --baseline readiness-baseline.json
```

Render compact context for AI-agent preflight decisions:

```sh
python3 samples/operational-readiness/readiness_check.py context \
  --config samples/operational-readiness/config.example.json
```

Render Prometheus-style metrics:

```sh
python3 samples/operational-readiness/readiness_check.py metrics \
  --config samples/operational-readiness/config.example.json
```

Render compact state counts:

```sh
python3 samples/operational-readiness/readiness_check.py summary \
  --config samples/operational-readiness/config.example.json
```

Render a Nagios-compatible status line:

```sh
python3 samples/operational-readiness/readiness_check.py nagios \
  --config samples/operational-readiness/config.example.json
```

Render the monitoring runbook:

```sh
python3 samples/operational-readiness/readiness_check.py runbook \
  --config samples/operational-readiness/config.example.json
```

Render SARIF findings for security review tooling:

```sh
python3 samples/operational-readiness/readiness_check.py sarif \
  --config samples/operational-readiness/config.example.json
```

Render remediation action items for unhealthy checks:

```sh
python3 samples/operational-readiness/readiness_check.py remediation \
  --config samples/operational-readiness/config.example.json
```

Fail when readiness is worse than an operator-selected maximum state:

```sh
python3 samples/operational-readiness/readiness_check.py threshold \
  --config samples/operational-readiness/config.example.json \
  --max-state degraded
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
