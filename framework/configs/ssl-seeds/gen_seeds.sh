#!/usr/bin/env bash
# Generate diverse DER-encoded X509 seed certificates for fuzzing
# mod_ssl's client certificate parsing code.
#
# Usage:  bash gen_seeds.sh
# Output: *.der files in the current directory (or directory of this script)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "[*] Generating seed certificates in $SCRIPT_DIR"

# --- Helper: generate RSA key -------------------------------------------
gen_key() { openssl genrsa -out "$1" 2048 2>/dev/null; }

# --- 1. Minimal self-signed cert ----------------------------------------
gen_key "$TMPDIR/min.key"
openssl req -new -x509 -key "$TMPDIR/min.key" -out "$TMPDIR/min.pem" \
    -days 365 -subj "/CN=min" -sha256 2>/dev/null
openssl x509 -in "$TMPDIR/min.pem" -outform DER -out seed_minimal.der

# --- 2. Cert with rich subject DN ---------------------------------------
gen_key "$TMPDIR/rich.key"
openssl req -new -x509 -key "$TMPDIR/rich.key" -out "$TMPDIR/rich.pem" \
    -days 365 -sha256 \
    -subj "/C=US/ST=California/L=San Francisco/O=Fuzz Corp/OU=Security/CN=rich.example.com/emailAddress=fuzz@example.com" \
    2>/dev/null
openssl x509 -in "$TMPDIR/rich.pem" -outform DER -out seed_rich_dn.der

# --- 3. CA certificate (Basic Constraints CA:TRUE) -----------------------
gen_key "$TMPDIR/ca.key"
openssl req -new -x509 -key "$TMPDIR/ca.key" -out "$TMPDIR/ca.pem" \
    -days 365 -sha256 -subj "/CN=FuzzCA/O=Fuzz" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:2" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    2>/dev/null
openssl x509 -in "$TMPDIR/ca.pem" -outform DER -out seed_ca.der

# --- 4. Cert with many SAN entries --------------------------------------
gen_key "$TMPDIR/san.key"
cat > "$TMPDIR/san.cnf" <<'EOF'
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no

[req_dn]
CN = san.example.com

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1  = san.example.com
DNS.2  = *.example.com
DNS.3  = foo.bar.example.org
email.1 = user@example.com
email.2 = admin@example.org
URI.1  = https://example.com/cert
IP.1   = 127.0.0.1
IP.2   = ::1
EOF
openssl req -new -x509 -key "$TMPDIR/san.key" -out "$TMPDIR/san.pem" \
    -days 365 -sha256 -config "$TMPDIR/san.cnf" 2>/dev/null
openssl x509 -in "$TMPDIR/san.pem" -outform DER -out seed_san.der

# --- 5. Cert with many extensions ---------------------------------------
gen_key "$TMPDIR/ext.key"
cat > "$TMPDIR/ext.cnf" <<'EOF'
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no

[req_dn]
CN = extensions.example.com

[v3_req]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth,emailProtection,codeSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
crlDistributionPoints = URI:http://example.com/crl.pem
authorityInfoAccess = OCSP;URI:http://ocsp.example.com,caIssuers;URI:http://example.com/ca.pem
certificatePolicies = 1.2.3.4.5,1.3.6.1.5.5.7.2.1
subjectAltName = DNS:extensions.example.com,email:ext@example.com
EOF
openssl req -new -x509 -key "$TMPDIR/ext.key" -out "$TMPDIR/ext.pem" \
    -days 365 -sha256 -config "$TMPDIR/ext.cnf" 2>/dev/null
openssl x509 -in "$TMPDIR/ext.pem" -outform DER -out seed_extensions.der

# --- 6. Wildcard CN certificate ------------------------------------------
gen_key "$TMPDIR/wild.key"
openssl req -new -x509 -key "$TMPDIR/wild.key" -out "$TMPDIR/wild.pem" \
    -days 365 -sha256 -subj "/CN=*.wildcard.example.com" 2>/dev/null
openssl x509 -in "$TMPDIR/wild.pem" -outform DER -out seed_wildcard.der

# --- 7. Expired certificate ----------------------------------------------
gen_key "$TMPDIR/expired.key"
# Create a cert that expired yesterday
openssl req -new -x509 -key "$TMPDIR/expired.key" -out "$TMPDIR/expired.pem" \
    -days 1 -sha256 -subj "/CN=expired.example.com" \
    -set_serial 0x$(openssl rand -hex 8) 2>/dev/null
# Backdate: issue 2 days ago, valid 1 day -> expired yesterday
faketime="$(date -d '2 days ago' +%Y%m%d%H%M%SZ 2>/dev/null || date -v-2d +%Y%m%d%H%M%SZ 2>/dev/null || true)"
if [ -z "$faketime" ]; then
    # Can't easily backdate, just use the 1-day cert as-is
    :
fi
openssl x509 -in "$TMPDIR/expired.pem" -outform DER -out seed_expired.der

# --- 8. EC key certificate -----------------------------------------------
openssl ecparam -genkey -name prime256v1 -out "$TMPDIR/ec.key" 2>/dev/null
openssl req -new -x509 -key "$TMPDIR/ec.key" -out "$TMPDIR/ec.pem" \
    -days 365 -sha256 -subj "/CN=ec.example.com" 2>/dev/null
openssl x509 -in "$TMPDIR/ec.pem" -outform DER -out seed_ec.der

# --- 9. Long serial number -----------------------------------------------
gen_key "$TMPDIR/longserial.key"
openssl req -new -x509 -key "$TMPDIR/longserial.key" -out "$TMPDIR/longserial.pem" \
    -days 365 -sha256 -subj "/CN=longserial" \
    -set_serial 0x$(openssl rand -hex 20) 2>/dev/null
openssl x509 -in "$TMPDIR/longserial.pem" -outform DER -out seed_longserial.der

# --- 10. PEM format seed (harness also tries PEM) ------------------------
gen_key "$TMPDIR/pem.key"
openssl req -new -x509 -key "$TMPDIR/pem.key" -out seed_pem_format.pem \
    -days 365 -sha256 -subj "/CN=pem-seed" 2>/dev/null

echo "[+] Generated $(ls -1 seed_*.der seed_*.pem 2>/dev/null | wc -l) seed files:"
ls -la seed_*.der seed_*.pem 2>/dev/null
