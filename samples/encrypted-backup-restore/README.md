# CaumeDSE Encrypted Backup And Restore Utility

This sample provides a portable encrypted backup/restore workflow for a
CaumeDSE data directory. It records file paths, sizes, SHA-256 hashes,
storage-file classification, creation time, and redacted source identifiers,
then stores a tar payload inside an authenticated encrypted backup package.

The utility deliberately preserves existing protected values exactly as stored.
It does not re-encrypt AES or Herradura-protected database values and does not
change storage profiles. Use the separate re-protect workflow when an operator
explicitly wants to migrate protected values between AES and Herradura profiles.

The backup key is read from `CDSE_BACKUP_KEY` by default, or from a key file via
`--key-file`. Do not pass backup keys on command lines.

## Commands

Create a manifest:

```sh
python3 samples/encrypted-backup-restore/cdse_backup_restore.py manifest \
  --source /tmp/cdse-verify/cdse \
  --label test-storage \
  --output backup-manifest.json
```

Verify a manifest against a source directory:

```sh
python3 samples/encrypted-backup-restore/cdse_backup_restore.py verify \
  --manifest backup-manifest.json \
  --source /tmp/cdse-verify/cdse
```

Render a restore plan without writing files:

```sh
python3 samples/encrypted-backup-restore/cdse_backup_restore.py plan-restore \
  --manifest backup-manifest.json \
  --target /tmp/cdse-restore
```

Run offline checks:

```sh
python3 samples/encrypted-backup-restore/cdse_backup_restore.py self-test
```

Create an encrypted backup package:

```sh
CDSE_BACKUP_KEY="$(openssl rand -base64 32)" \
python3 samples/encrypted-backup-restore/cdse_backup_restore.py create-backup \
  --source /tmp/cdse-verify/cdse \
  --label test-storage \
  --profile mixed-existing \
  --output backup.cdsebackup.json
```

Authenticate a backup package without restoring it:

```sh
CDSE_BACKUP_KEY="$CDSE_BACKUP_KEY" \
python3 samples/encrypted-backup-restore/cdse_backup_restore.py verify-backup \
  --backup backup.cdsebackup.json
```

Dry-run a restore into a fresh prefix:

```sh
CDSE_BACKUP_KEY="$CDSE_BACKUP_KEY" \
python3 samples/encrypted-backup-restore/cdse_backup_restore.py restore \
  --backup backup.cdsebackup.json \
  --target /tmp/cdse-restore \
  --expected-profile mixed-existing \
  --dry-run
```

Restore after reviewing the plan:

```sh
CDSE_BACKUP_KEY="$CDSE_BACKUP_KEY" \
python3 samples/encrypted-backup-restore/cdse_backup_restore.py restore \
  --backup backup.cdsebackup.json \
  --target /tmp/cdse-restore \
  --expected-profile mixed-existing
```

## Security Notes

- Do not put organization keys, TLS private keys, delegated tokens, or OAuth
  secrets in manifest labels, paths, or logs.
- Treat manifests as sensitive operational metadata even though identifiers are
  redacted.
- The encrypted package uses OpenSSL `enc` with AES-256-CBC/PBKDF2 and an outer
  HMAC-SHA256 over the ciphertext for wrong-key and tamper rejection.
- Preserve mixed AES/Herradura data as-is unless a separate explicit re-protect
  workflow is run.
- Verify manifests before restoring, and restore into a fresh prefix unless an
  operator explicitly approves overwrite behavior.
