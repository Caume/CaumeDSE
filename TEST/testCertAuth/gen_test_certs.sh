#!/bin/bash
# gen_test_certs.sh - Generate TLS test certificates for CaumeDSE
#
# Generates a full certificate chain for CaumeDSE TLS authentication:
#
#   CA (self-signed)
#    ├─ server.pem  + server.key   (server TLS cert, signed by CA)
#    ├─ engineOrg.pem + engineOrg.key  (intermediate CA, signed by CA)
#    │   └─ engineAdmin.pem + engineAdmin.key  (client cert, signed by engineOrg)
#    └─ caChain.pem  = engineOrg.pem + ca.pem  (CA chain for client-cert validation)
#       engineAdmin.p12  (PKCS12 bundle for browser import; password: engineAdmin)
#
# Usage:
#   ./gen_test_certs.sh [OPTIONS] [output_dir [server_cn]]
#
# Options:
#   -a, --algo ALGO      Key/hash algorithm preset (default: ecp384)
#   -o, --output-dir DIR Output directory (default: script directory)
#   -s, --server-cn CN   Server CN / hostname for TLS (default: localhost)
#   -h, --help           Show this help and exit
#
# ALGO presets (key algorithm + recommended paired hash):
#   rsa2048   RSA 2048-bit  + SHA-256  (minimum acceptable for RSA)
#   rsa4096   RSA 4096-bit  + SHA-256
#   ecp256    ECDSA P-256   + SHA-256  (128-bit security)
#   ecp384    ECDSA P-384   + SHA-384  (192-bit security, recommended)
#   ecp521    ECDSA P-521   + SHA-512  (256-bit security)
#   ed25519   Ed25519       + intrinsic hash (128-bit, TLS 1.3+ only)
#   ed448     Ed448         + intrinsic hash (224-bit, TLS 1.3+ only)
#
# After running, install server certificates for CaumeDSE:
#   cp server.key server.pem ca.pem /opt/cdse/
#
# Requirements: openssl 1.1.1+ (tested with OpenSSL 3.x)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# -----------------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------------
ALGO="ecp384"
OUTPUT_DIR="$SCRIPT_DIR"
SERVER_CN="localhost"
DAYS=3650
SUBJ_BASE="/C=MX/ST=DF/L=Mexico City/O=EngineOrg"
ADMIN_PASS="engineAdmin"

# -----------------------------------------------------------------------
# Argument parsing  (named flags + legacy positional args)
# -----------------------------------------------------------------------
usage() {
    sed -n '2,/^$/p' "$0" | grep -E '^#' | sed 's/^# \{0,1\}//'
    exit 0
}

POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -a|--algo)        ALGO="$2";       shift 2 ;;
        -o|--output-dir)  OUTPUT_DIR="$2"; shift 2 ;;
        -s|--server-cn)   SERVER_CN="$2";  shift 2 ;;
        -h|--help)        usage ;;
        -*) echo "Unknown option: $1" >&2; exit 1 ;;
        *)  POSITIONAL+=("$1"); shift ;;
    esac
done
# Legacy positional args override if not already set by flags
[[ ${#POSITIONAL[@]} -ge 1 ]] && OUTPUT_DIR="${POSITIONAL[0]}"
[[ ${#POSITIONAL[@]} -ge 2 ]] && SERVER_CN="${POSITIONAL[1]}"

# -----------------------------------------------------------------------
# Resolve algorithm parameters
# -----------------------------------------------------------------------
case "$ALGO" in
    rsa2048)
        KEY_DESC="RSA 2048-bit"
        HASH="sha256"
        HASH_DESC="SHA-256"
        KEY_FAMILY="rsa"
        gen_key() { openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1" 2>/dev/null; }
        ;;
    rsa4096)
        KEY_DESC="RSA 4096-bit"
        HASH="sha256"
        HASH_DESC="SHA-256"
        KEY_FAMILY="rsa"
        gen_key() { openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$1" 2>/dev/null; }
        ;;
    ecp256)
        KEY_DESC="ECDSA P-256"
        HASH="sha256"
        HASH_DESC="SHA-256"
        KEY_FAMILY="ec"
        gen_key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }
        ;;
    ecp384)
        KEY_DESC="ECDSA P-384"
        HASH="sha384"
        HASH_DESC="SHA-384"
        KEY_FAMILY="ec"
        gen_key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$1" 2>/dev/null; }
        ;;
    ecp521)
        KEY_DESC="ECDSA P-521"
        HASH="sha512"
        HASH_DESC="SHA-512"
        KEY_FAMILY="ec"
        gen_key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -out "$1" 2>/dev/null; }
        ;;
    ed25519)
        KEY_DESC="Ed25519"
        HASH=""
        HASH_DESC="intrinsic (SHA-512/EdDSA)"
        KEY_FAMILY="eddsa"
        gen_key() { openssl genpkey -algorithm ed25519 -out "$1" 2>/dev/null; }
        ;;
    ed448)
        KEY_DESC="Ed448"
        HASH=""
        HASH_DESC="intrinsic (SHAKE256/EdDSA)"
        KEY_FAMILY="eddsa"
        gen_key() { openssl genpkey -algorithm ed448 -out "$1" 2>/dev/null; }
        ;;
    *)
        echo "Unknown algorithm: '$ALGO'" >&2
        echo "Valid choices: rsa2048 rsa4096 ecp256 ecp384 ecp521 ed25519 ed448" >&2
        exit 1
        ;;
esac

# Optional hash flag for openssl req / x509  (empty for EdDSA — hash is intrinsic)
HASH_FLAG=${HASH:+-${HASH}}

# keyUsage appropriate for the key family:
#   RSA: digitalSignature + keyEncipherment  (needed for RSA key exchange)
#   EC/EdDSA: digitalSignature only          (ECDHE handles key agreement separately)
if [[ "$KEY_FAMILY" == "rsa" ]]; then
    SRV_KEY_USAGE="critical,nonRepudiation,digitalSignature,keyEncipherment"
    USR_KEY_USAGE="critical,nonRepudiation,digitalSignature,keyEncipherment"
else
    SRV_KEY_USAGE="critical,nonRepudiation,digitalSignature"
    USR_KEY_USAGE="critical,nonRepudiation,digitalSignature"
fi

echo "=== CaumeDSE Test Certificate Generator ==="
echo "Output directory : $OUTPUT_DIR"
echo "Server CN        : $SERVER_CN"
echo "Algorithm        : $KEY_DESC"
echo "Hash             : $HASH_DESC"
echo "Validity         : ${DAYS} days (~10 years)"
[[ "$KEY_FAMILY" == "eddsa" ]] && \
    echo "Note             : EdDSA certificates require TLS 1.3 (GnuTLS 3.6+)"
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
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints       = critical,CA:true
keyUsage               = critical,cRLSign,keyCertSign
EOF

cat > "$SRV_EXT" <<EOF
[web_cert]
basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
keyUsage               = ${SRV_KEY_USAGE}
extendedKeyUsage       = serverAuth
subjectAltName         = DNS:${SERVER_CN},IP:127.0.0.1
EOF

cat > "$USR_EXT" <<EOF
[usr_cert]
basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
keyUsage               = ${USR_KEY_USAGE}
extendedKeyUsage       = clientAuth
EOF

# -----------------------------------------------------------------------
# 1. Root CA – self-signed
# -----------------------------------------------------------------------
echo "--- [1/6] Generating Root CA key and self-signed certificate ---"
gen_key ca.key
openssl req -new -x509 -days "$DAYS" -key ca.key \
    -subj "${SUBJ_BASE}/OU=CA/CN=CA" \
    ${HASH_FLAG} \
    -extensions v3_ca -config "$CA_EXT" \
    -out ca.pem

# -----------------------------------------------------------------------
# 2. engineOrg – intermediate CA signed by root CA
# -----------------------------------------------------------------------
echo "--- [2/6] Generating engineOrg intermediate CA ---"
gen_key engineOrg.key
openssl req -new -key engineOrg.key \
    -subj "${SUBJ_BASE}/OU=CA/CN=EngineOrg" \
    ${HASH_FLAG} \
    -out engineOrg.req
openssl x509 -req -days "$DAYS" -in engineOrg.req \
    -extfile "$CA_EXT" -extensions v3_ca \
    -CAkey ca.key -CA ca.pem -CAcreateserial \
    ${HASH_FLAG} -out engineOrg.pem

# -----------------------------------------------------------------------
# 3. Server certificate – signed by root CA
# -----------------------------------------------------------------------
echo "--- [3/6] Generating server key and certificate (CN=${SERVER_CN}) ---"
gen_key server.key
openssl req -new -key server.key \
    -subj "${SUBJ_BASE}/OU=Webmaster/CN=${SERVER_CN}" \
    ${HASH_FLAG} \
    -out server.req
openssl x509 -req -days "$DAYS" -in server.req \
    -extfile "$SRV_EXT" -extensions web_cert \
    -CAkey ca.key -CA ca.pem -CAcreateserial \
    ${HASH_FLAG} -out server.pem

# -----------------------------------------------------------------------
# 4. engineAdmin client certificate – signed by engineOrg
# -----------------------------------------------------------------------
echo "--- [4/6] Generating engineAdmin client key and certificate ---"
gen_key engineAdmin.key
openssl req -new -key engineAdmin.key \
    -subj "${SUBJ_BASE}/OU=Webmaster/CN=EngineAdmin" \
    ${HASH_FLAG} \
    -out engineAdmin.req
openssl x509 -req -days "$DAYS" -in engineAdmin.req \
    -extfile "$USR_EXT" -extensions usr_cert \
    -CAkey engineOrg.key -CA engineOrg.pem -CAcreateserial \
    ${HASH_FLAG} -out engineAdmin.pem

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
    SIG=$(openssl x509 -in "$f" -noout -text 2>/dev/null \
          | grep "Signature Algorithm" | head -1 | sed 's/.*Signature Algorithm: //')
    EXPIRY=$(openssl x509 -in "$f" -noout -enddate 2>/dev/null | sed 's/notAfter=//')
    printf "  %-18s  sig=%-28s  expires=%s\n" "$f" "$SIG" "$EXPIRY"
done

echo ""
echo "=== Certificates generated successfully in: $OUTPUT_DIR ==="
echo ""
echo "To install server certificates for CaumeDSE, run:"
echo "  cp \"$OUTPUT_DIR/server.key\" \"$OUTPUT_DIR/server.pem\" \"$OUTPUT_DIR/ca.pem\" /opt/cdse/"
echo ""
echo "To import the engineAdmin client certificate in a browser:"
echo "  File    : $OUTPUT_DIR/engineAdmin.p12"
echo "  Password: ${ADMIN_PASS}"
echo ""
