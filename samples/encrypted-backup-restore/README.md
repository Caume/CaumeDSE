# CaumeDSE Encrypted Backup And Restore Utility

This sample starts the backup/restore workflow with a portable integrity
manifest. It records file paths, sizes, SHA-256 hashes, storage-file
classification, creation time, and redacted source identifiers for a CaumeDSE
data directory.

Batch 1 deliberately preserves existing protected values exactly as stored. It
does not re-encrypt AES or Herradura-protected database values and does not
change storage profiles. Encryption wrapping for the archive payload is the next
batch; this manifest is the integrity contract that encrypted backups will
carry.

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

## Security Notes

- Do not put organization keys, TLS private keys, delegated tokens, or OAuth
  secrets in manifest labels, paths, or logs.
- Treat manifests as sensitive operational metadata even though identifiers are
  redacted.
- Preserve mixed AES/Herradura data as-is unless a separate explicit re-protect
  workflow is run.
- Verify manifests before restoring, and restore into a fresh prefix unless an
  operator explicitly approves overwrite behavior.
