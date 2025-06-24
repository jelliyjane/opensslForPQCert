#!/bin/bash

#Environment variables for using OpenSSL 3.3.0 + OQS provider
export PATH=/usr/local/ssl/bin:$PATH
export LD_LIBRARY_PATH=/usr/local/ssl/lib64:$LD_LIBRARY_PATH
export PKG_CONFIG_PATH=/usr/local/ssl/lib64/pkgconfig
export OPENSSL_MODULES=/usr/local/ssl/lib64/ossl-modules
export OPENSSL_CONF=/usr/local/ssl/openssl.cnf

# Script to test dual certificate encoding
# This script starts a server with dual certificates and captures the Certificate message

set -e

echo "=== Dual Certificate Encoding Test ==="
echo

# Kill any existing processes on port 4433
pkill -f "s_server.*4433" || true
sleep 1

# Start server in background with dual certificates
echo "Starting server with dual certificates..."
./apps/openssl s_server \
    -cert Test_Dual/server_cert.pem \
    -key Test_Dual/server_key.pem \
    -pqcert Test_Dual/pqc_cert.pem \
    -pqkey Test_Dual/pqc_key.pem \
    -enable_dual_certs \
    -accept 4433 \
    -msg \
    -quiet \
    > server_output.log 2>&1 &

SERVER_PID=$!
echo "Server started with PID: $SERVER_PID"

# Wait for server to start
sleep 3

# Test connection and capture output
echo "Testing connection..."
./apps/openssl s_client \
    -connect localhost:4433 \
    -CAfile Test_Dual/ca_cert.pem \
    -msg \
    -brief \
    > client_output.log 2>&1 || true

# Kill server
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

echo
echo "=== Server Output ==="
cat server_output.log

echo
echo "=== Client Output ==="
cat client_output.log

echo
echo "=== Certificate Message Analysis ==="

# Extract Certificate message from client output
if grep -A 100 "Certificate" client_output.log | grep -B 100 "CertificateVerify\|Alert" > cert_message.log; then
    echo "Certificate message captured. Analyzing structure..."
    
    # Parse the hex dump
    echo "Certificate message structure:"
    grep "Certificate" cert_message.log | head -1
    
    # Extract hex data
    grep -A 100 "Certificate" client_output.log | grep -E "^    [0-9a-f]" | head -20 | while read line; do
        echo "$line"
    done
    
    echo
    echo "Analysis complete. Check cert_message.log for full details."
else
    echo "No Certificate message found in output."
fi

echo
echo "=== Test Complete ==="

# Cleanup
rm -f server_output.log client_output.log cert_message.log
