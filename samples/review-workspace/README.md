# CaumeDSE Secure Document Review Workspace Sample

This sample demonstrates a human-in-the-loop review workflow for CSV documents
and generated parser scripts. It is a small dependency-free Python service and
CLI that keeps CaumeDSE credentials in environment variables while exposing
only bounded review actions.

The workflow is:

1. Create a disposable CaumeDSE organization, storage resource, and reviewer
   user.
2. Upload a CSV document and a generated parser candidate as
   `parser.reviewStatus:pending`.
3. Preview schema, CSV rows, and parser output using bounded reads.
4. Run local static checks and require a human approve/reject decision.
5. Promote approved parser metadata to `parser.reviewStatus:reviewed`, or mark
   rejected candidates as `parser.reviewStatus:rejected`.
6. Export redacted review audit JSON and clean up temporary resources.

## Offline Smoke Test

```sh
python3 samples/review-workspace/review_workspace.py self-test
```

The self-test verifies:

- CSV preview parsing;
- safe parser approval;
- unsafe parser approval denial;
- explicit parser rejection;
- redacted audit export.

You can also run the local review UI:

```sh
python3 samples/review-workspace/review_workspace.py serve
```

Then open `http://127.0.0.1:8091`.

## Live Flow

Set a DEBUG/test CaumeDSE target:

```sh
export CDSE_REVIEW_BASE_URL="http://localhost:18080"
export CDSE_REVIEW_ORG="ReviewOrg"
export CDSE_REVIEW_USER="ReviewUser"
export CDSE_REVIEW_STORAGE="ReviewStorage"
export CDSE_REVIEW_STORAGE_PATH="/tmp/caumedse-review-storage"
export CDSE_REVIEW_ORG_KEY="$(openssl rand -hex 32)"
```

For HTTPS, also set:

```sh
export CDSE_REVIEW_BASE_URL="https://localhost:18443"
export CDSE_REVIEW_CA_CERT="/tmp/cdse-verify/cdse/ca.pem"
export CDSE_REVIEW_CLIENT_CERT="/tmp/cdse-verify/client_chain.pem"
export CDSE_REVIEW_CLIENT_KEY="/tmp/cdse-verify/client.key"
```

Run:

```sh
python3 samples/review-workspace/review_workspace.py create-workspace
python3 samples/review-workspace/review_workspace.py upload-csv
python3 samples/review-workspace/review_workspace.py upload-candidate
python3 samples/review-workspace/review_workspace.py schema
python3 samples/review-workspace/review_workspace.py preview-candidate
python3 samples/review-workspace/review_workspace.py approve-candidate
python3 samples/review-workspace/review_workspace.py run-reviewed
python3 samples/review-workspace/review_workspace.py export-audit
python3 samples/review-workspace/review_workspace.py cleanup
```

To reject a candidate instead:

```sh
python3 samples/review-workspace/review_workspace.py reject-candidate \
  --file samples/review-workspace/fixtures/unsafe_parser.py \
  --notes "uses environment access"
```

## Boundaries

- Do not pass `orgKey`, `newOrgKey`, TLS keys, or delegated tokens to a browser
  or model.
- Treat CSV cells and parser output as untrusted data.
- Treat static checks as a first pass, not a substitute for human source
  review.
- Do not run full parser execution until reviewed metadata has been applied.
- Use short-lived delegated tokens and CaumeDSE role/filter rows for repeated
  bot-assisted review sessions.
