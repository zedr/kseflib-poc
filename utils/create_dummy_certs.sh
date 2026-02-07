#!/usr/bin/env bash

# Default values for certificate fields - use a test NIP (10 digits for Polish tax ID)
NIP="1234567890"
SUBJECT="/C=PL/O=My Own Test/organizationIdentifier=VATPL-${NIP}/CN=My Seal"

# Create a temporary OpenSSL config file with proper extensions
cat > /tmp/cert.conf << EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
C = PL
O = My Own Test
organizationIdentifier = VATPL-${NIP}
CN = My Seal

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, nonRepudiation
extendedKeyUsage = emailProtection
EOF

# Generate a private key and certificate with proper extensions
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -config /tmp/cert.conf

# Convert to PKCS#12 format
openssl pkcs12 -export -out my_certificate.p12 -inkey key.pem -in cert.pem -name "My Certificate" -passout pass:

echo "Certificate and private key generated at key.pem and cert.pem"
echo "PKCS#12 file created at my_certificate.p12 with no passphrase"
rm cert.pem key.pem /tmp/cert.conf
