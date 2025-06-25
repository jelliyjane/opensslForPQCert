#!/bin/bash

# Script to generate dual certificates for testing
# This creates both classical (RSA) and post-quantum (Dilithium) certificates

set -e

# Set OpenSSL 3.3.0 + OQS provider environment variables
export PATH=/usr/local/ssl/bin:$PATH
export LD_LIBRARY_PATH=/usr/local/ssl/lib64:$LD_LIBRARY_PATH
export PKG_CONFIG_PATH=/usr/local/ssl/lib64/pkgconfig
export OPENSSL_MODULES=/usr/local/ssl/lib64/ossl-modules

# Function to run openssl with proper library path
opensslcmd() {
    openssl "$@"
}

echo "Generating dual certificates for testing..."

echo "1. Generating Root CA (RSA)"
# Root CA: create certificate directly
CN="Test Dual Root CA" opensslcmd req -config ../demos/certs/ca.cnf -x509 -nodes \
    -keyout ca_key.pem -out ca_cert.pem -newkey rsa:2048 -days 3650

echo "2. Generating Intermediate CA (RSA)"
# Intermediate CA: request first
CN="Test Dual Intermediate CA" opensslcmd req -config ../demos/certs/ca.cnf -nodes \
    -keyout int_key.pem -out int_req.pem -newkey rsa:2048
# Sign request: CA extensions
opensslcmd x509 -req -in int_req.pem -CA ca_cert.pem -CAkey ca_key.pem -days 3600 \
    -extfile ../demos/certs/ca.cnf -extensions v3_ca -CAcreateserial -out int_cert.pem

echo "3. Generating Classical Server Certificate (RSA)"
# Server certificate: create request first
CN="Test Dual Server Cert" opensslcmd req -config ../demos/certs/ca.cnf -nodes \
    -keyout server_key.pem -out server_req.pem -newkey rsa:2048
# Sign request: end entity extensions
opensslcmd x509 -req -in server_req.pem -CA int_cert.pem -CAkey int_key.pem -days 3600 \
    -extfile ../demos/certs/ca.cnf -extensions usr_cert -CAcreateserial -out server_cert.pem

echo "4. Generating Post-Quantum Server Certificate (Dilithium)"
# Check if OQS provider is available
if opensslcmd list -providers | grep -q oqs; then
    echo "OQS provider found, generating Dilithium certificate..."
    
    # Generate Dilithium key
    opensslcmd genpkey -algorithm dilithium2 -out server_pq_key.pem
    
    # Create certificate request with Dilithium key
    CN="Test Dual Server PQ Cert" opensslcmd req -config ../demos/certs/ca.cnf -new \
        -key server_pq_key.pem -out server_pq_req.pem
    
    # Sign request: end entity extensions
    opensslcmd x509 -req -in server_pq_req.pem -CA int_cert.pem -CAkey int_key.pem -days 3600 \
        -extfile ../demos/certs/ca.cnf -extensions usr_cert -CAcreateserial -out server_pq_cert.pem
else
    echo "OQS provider not found, creating a second RSA certificate as PQ substitute..."
    # Fallback: create another RSA certificate as PQ substitute
    CN="Test Dual Server PQ Cert" opensslcmd req -config ../demos/certs/ca.cnf -nodes \
        -keyout server_pq_key.pem -out server_pq_req.pem -newkey rsa:2048
    opensslcmd x509 -req -in server_pq_req.pem -CA int_cert.pem -CAkey int_key.pem -days 3600 \
        -extfile ../demos/certs/ca.cnf -extensions usr_cert -CAcreateserial -out server_pq_cert.pem
fi

echo "5. Creating combined certificate files"
# Combine classical certificate chain
cat server_cert.pem int_cert.pem > server_chain.pem

# Combine PQ certificate chain  
cat server_pq_cert.pem int_cert.pem > server_pq_chain.pem

# Create combined key file (server key + PQ key)
cat server_key.pem server_pq_key.pem > server_combined_key.pem

echo "6. Creating client certificate for testing"
# Client certificate: request first
CN="Test Dual Client Cert" opensslcmd req -config ../demos/certs/ca.cnf -nodes \
    -keyout client_key.pem -out client_req.pem -newkey rsa:2048
# Sign using intermediate CA
opensslcmd x509 -req -in client_req.pem -CA int_cert.pem -CAkey int_key.pem -days 3600 \
    -extfile ../demos/certs/ca.cnf -extensions usr_cert -CAcreateserial -out client_cert.pem

echo "7. Verifying certificates"
# Verify server certificates
echo "Verifying classical server certificate:"
opensslcmd verify -CAfile ca_cert.pem -untrusted int_cert.pem server_cert.pem

echo "Verifying PQ server certificate:"
opensslcmd verify -CAfile ca_cert.pem -untrusted int_cert.pem server_pq_cert.pem

echo "Verifying client certificate:"
opensslcmd verify -CAfile ca_cert.pem -untrusted int_cert.pem client_cert.pem

echo ""
echo "Certificate generation complete!"
echo "Files created in current directory:"
echo "  ca_cert.pem          - Root CA certificate"
echo "  server_cert.pem      - Classical server certificate"
echo "  server_pq_cert.pem   - Post-quantum server certificate"
echo "  server_chain.pem     - Classical certificate chain"
echo "  server_pq_chain.pem  - PQ certificate chain"
echo "  server_combined_key.pem - Combined private keys"
echo "  client_cert.pem      - Client certificate"
echo ""
echo "To test the dual certificate server:"
echo "  openssl s_server -accept 8444 -cert server_cert.pem -key server_key.pem \\"
echo "    -pqcert server_pq_cert.pem -pqkey server_pq_key.pem -dual-certs"
echo ""
echo "To test the dual certificate client:"
echo "  openssl s_client -connect localhost:8444 -CAfile ca_cert.pem" 