# Hybrid TLS Implementation for OpenSSL

This project implements the "Hybrid TLS" approach for the OpenSSL cryptographic library, providing full support for the hybrid certificates(e.g., Chameleon, Catalyst, etc.) that combine classical and post-quantum cryptography (PQC) in TLS 1.3 handshakes.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Building and Testing](#building-and-testing)


## Overview

Hybrid TLS enables simultaneous use of classical and post-quantum (PQC) certificates within a single TLS 1.3 handshake.
This implementation extends OpenSSL 3.3.4 to integrate PQC algorithms via the OQS provider, ensuring both backward compatibility and quantum-resistant security. This is particularly useful for:
- Support PQC migration through hybrid authentication
- Maintain compatibility with existing X.509 and TLS infrastructures
- Provide flexibility for hybrid certificate usage in TLS
- Enable secure experimentation with post-quantum algorithms


## Features

**Implemented Components**
1.	**Hybrid Certificate Framework**
    - Added hyb_cert and hyb_pkey fields to CERT and SSL_CONNECTION
    - Supports dual private-key management
    - Backward-compatible with non-hybrid certificates
2.	**Hybrid Certificate Hint Extension** (`TLSEXT_TYPE_hybrid_cert_hint`)
    - Negotiates hybrid support in ClientHello and ServerHello
    - Indicates which hybrid certificate (Chameleon/Catalyst) will be used
    - Ensures transparent handshake operation
3.	**Hybrid Certificate Verify Message**
    - Introduces PQCertificateVerify message for PQC signatures
    - Executed after standard CertificateVerify
    - Enables dual-signature verification
4.	**Hybrid Certificate Registration**
    - Supports integration of Chameleon, Catalyst, and future hybrid profiles
    - Fully compatible with deltaCertificateDescriptor extensions


## Building and Testing

### Prerequisites
- OpenSSL 3.3.4 or later
- Make
- liboqs
- oqs provider

### Build Options

```bash
git clone -b develop https://github.com/jelliyjane/opensslForPQCert.git
cd opensslForPQCert
./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl
make -j$(nproc)
sudo make install
```

### Testing Process

#### Step 1: Generate Hybrid Certificates
```bash
# Base private key (ECDSA)
openssl ecparam -name prime256v1 -genkey -noout -out server_base_key.pem

# PQC Certificate (ML-DSA)
openssl req -new -x509 -newkey mldsa44 -keyout server_delta_key.pem -out server_delta_cert.pem -nodes -subj "/CN=Server-Delta-Certificate" -days 365

# Chameleon Certificate
openssl req -new -x509 -key server_base_key.pem -out server_cert.pem -nodes -days 365 -addext "deltaCertificateDescriptor=file:./server_delta_cert.pem"
```

#### Step 2: Start Hybrid TLS Server
```bash
openssl s_server -accept 8443 -cert server_cert.pem -key server_base_key.pem -hybcert chameleon -hybkey server_delta_key.pem -tls1_3 -msg -state
```
**Options**
- `-hybcert` : Hybrid certificate type (Chameleon/Catalyst)
- `-hybkey` : PQC private key associated with hybrid cert
- `-tls1_3` : Use TLS 1.3 hybrid handshake
- `-msg -state` : Verbose debug output


#### Step 3: Connect Hybrid TLS Client
```bash
openssl s_client -connect 127.0.0.1:8443 -tls1_3 -hybcert catalyst,chameleon -msg -state
```
**3.1 Expected TLS 1.3 Message Sequence**
1.	ClientHello
2.	ServerHello
3.	EncryptedExtensions
4.	Certificate (classical)
5.	CertificateVerify (classical signature)
6.	PQCertificateVerify (PQC signature)
7.	Finished