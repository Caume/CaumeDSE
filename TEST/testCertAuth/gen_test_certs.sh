#!/bin/bash
# gen_test_certs.sh - Generate TLS test certificates for CaumeDSE
#
# Generates a full certificate chain for CaumeDSE TLS authentication:
#
#   CA (self-signed, RSA 4096 / SHA-256)
#    ├─ server.pem  (server TLS cert, signed by CA)  + server.key
#    ├─ engineOrg.pem (intermediate CA, signed by CA) + engineOrg.key
#    │   └─ engineAdmin.pem (client cert, signed by engineOrg) + engineAdmin.key
#    └─ caChain.pem  = engineOrg.pem + ca.pem  (full CA chain for client-cert validation)
#       engineAdmin.p12  (PKCS12 bundle for browser import; password: engineAdmin)
#
# Usage:
#   ./gen_test_certs.sh [output_dir] [server_cn]
#
#   output_dir : where to write certificate files (default: directory of this script)
#   server_cn  : CN for the server certificate, e.g. hostname or IP (default: localhost)
#
# After running, install server certificates for CaumeDSE:
#   sudo cp server.key server.pem ca.pem /opt/cdse/
#
# Requirements: openssl 1.1.1+ (tested with OpenSSL 3.x)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${1:-$SCRIPT_DIR}"
SERVER_CN="${2:-localhost}"

DAYS=3650
KEYSIZE=4096
HASH=sha256
SUBJ_BASE="/C=MX/ST=DF/L=Mexico City/O=EngineOrg"
ADMIN_PASS="engineAdmin"

echo "=== CaumeDSE Test Certificate Generator ==="
echo "Output directory : $OUTPUT_DIR"
echo "Server CN        : $SERVER_CN"
echo "Key size         : ${KEYSIZE}-bit RSA"
echo "Hash algorithm   : ${HASH^^}"
echo "Validity         : ${DAYS} days (~10 years)"
echo ""

mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

# -----------------------------------------------------------------------
# Write temporary OpenSSL extension config files
# -----------------------------------------------------------------------
CA_EXT=$(mktemp /tmp/cdse_ca_ext.XXXXXX.cnf)
SRV_EXT=$(mktemp /tmp/cdse_srv_ext.XXXXXX.cnf)
USR_EXT=$(mktemp /tmp/cdse_usr_ext.XXXXXX.cnf)
cleanup() { rm -f "$CA_EXT" "$SRV_EXT" "$USR_EXT"; }
trap cleanup EXIT

cat > "$CA_EXT" <<EOF
[req]
distinguished_name = req_dn
[req_dn]
[v3_ca]
subjectKeyIdentifier  = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints      = critical,CA:true
keyUsage              = critical,cRLSign,keyCertSign
EOF

cat > "$SRV_EXT" <<EOF
[web_cert]
basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
keyUsage               = critical,nonRepudiation,digitalSignature,keyEncipherment
extendedKeyUsage       = serverAuth
subjectAltName         = DNS:${SERVER_CN},IP:127.0.0.1
EOF

cat > "$USR_EXT" <<EOF
[usr_cert]
basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
keyUsage               = critical,nonRepudiation,digitalSignature,keyEncipherment
extendedKeyUsage       = clientAuth
EOF

# -----------------------------------------------------------------------
# 1. Root CA – self-signed
# -----------------------------------------------------------------------
echo "--- [1/6] Generating Root CA key and self-signed certificate ---"
openssl genrsa -out ca.key "$KEYSIZE" 2>/dev/null
openssl req -new -x509 -days "$DAYS" -key ca.key \
    -subj "${SUBJ_BASE}/OU=CA/CN=CA" \
    -"$HASH" \
    -extensions v3_ca -config "$CA_EXT" \
    -out ca.pem

# -----------------------------------------------------------------------
# 2. engineOrg – intermediate CA signed by root CA
# -----------------------------------------------------------------------
echo "--- [2/6] Generating engineOrg intermediate CA ---"
openssl genrsa -out engineOrg.key "$KEYSIZE" 2>/dev/null
openssl req -new -key engineOrg.key \
    -subj "${SUBJ_BASE}/OU=CA/CN=EngineOrg" \
    -out engineOrg.req
openssl x509 -req -days "$DAYS" -in engineOrg.req \
    -extfile "$CA_EXT" -extensions v3_ca \
    -CAkey ca.key -CA ca.pem -CAcreateserial \
    -"$HASH" -out engineOrg.pem

# -----------------------------------------------------------------------
# 3. Server certificate – signed by root CA
# -----------------------------------------------------------------------
echo "--- [3/6] Generating server key and certificate (CN=${SERVER_CN}) ---"
openssl genrsa -out server.key "$KEYSIZE" 2>/dev/null
openssl req -new -key server.key \
    -subj "${SUBJ_BASE}/OU=Webmaster/CN=${SERVER_CN}" \
    -out server.req
openssl x509 -req -days "$DAYS" -in server.req \
    -extfile "$SRV_EXT" -extensions web_cert \
    -CAkey ca.key -CA ca.pem -CAcreateserial \
    -"$HASH" -out server.pem

# -----------------------------------------------------------------------
# 4. engineAdmin client certificate – signed by engineOrg
# -----------------------------------------------------------------------
echo "--- [4/6] Generating engineAdmin client key and certificate ---"
openssl genrsa -out engineAdmin.key "$KEYSIZE" 2>/dev/null
openssl req -new -key engineAdmin.key \
    -subj "${SUBJ_BASE}/OU=Webmaster/CN=EngineAdmin" \
    -out engineAdmin.req
openssl x509 -req -days "$DAYS" -in engineAdmin.req \
    -extfile "$USR_EXT" -extensions usr_cert \
    -CAkey engineOrg.key -CA engineOrg.pem -CAcreateserial \
    -"$HASH" -out engineAdmin.pem

# -----------------------------------------------------------------------
# 5. Build CA chain (intermediate + root) for client-cert validation
# -----------------------------------------------------------------------
echo "--- [5/6] Building CA chain (caChain.pem = engineOrg.pem + ca.pem) ---"
cat engineOrg.pem ca.pem > caChain.pem

# -----------------------------------------------------------------------
# 6. PKCS12 bundle for browser import
# -----------------------------------------------------------------------
echo "--- [6/6] Building engineAdmin.p12 (password: ${ADMIN_PASS}) ---"
openssl pkcs12 -export \
    -out engineAdmin.p12 \
    -inkey engineAdmin.key \
    -in engineAdmin.pem \
    -aes128 \
    -chain -CAfile caChain.pem \
    -passout pass:"${ADMIN_PASS}"

# -----------------------------------------------------------------------
# Verification
# -----------------------------------------------------------------------
echo ""
echo "--- Verifying certificate chain ---"
openssl verify -CAfile ca.pem server.pem          && echo "  server.pem     : OK"
openssl verify -CAfile ca.pem engineOrg.pem        && echo "  engineOrg.pem  : OK"
openssl verify -CAfile caChain.pem engineAdmin.pem && echo "  engineAdmin.pem: OK"

echo ""
echo "--- Certificate summary ---"
for f in ca.pem engineOrg.pem server.pem engineAdmin.pem; do
    printf "  %-18s  %s  [%s]\n" \
        "$f" \
        "$(openssl x509 -in "$f" -noout -subject 2>/dev/null | sed 's/subject=//')" \
        "$(openssl x509 -in "$f" -noout -enddate 2>/dev/null | sed 's/notAfter=//')"
done

echo ""
echo "=== Certificates generated successfully in: $OUTPUT_DIR ==="
echo ""
echo "To install server certificates for CaumeDSE, run:"
echo "  sudo cp \"$OUTPUT_DIR/server.key\" \"$OUTPUT_DIR/server.pem\" \"$OUTPUT_DIR/ca.pem\" /opt/cdse/"
echo ""
echo "To import the engineAdmin client certificate in a browser:"
echo "  File : $OUTPUT_DIR/engineAdmin.p12"
echo "  Password: ${ADMIN_PASS}"
echo ""
