# Chameleon Certificate Implementation for OpenSSL

This project implements the "Chameleon Certificate" approach as defined in [IETF draft-bonnell-lamps-chameleon-certs](http://datatracker.ietf.org/doc/draft-bonnell-lamps-chameleon-certs/) for the OpenSSL cryptographic library. The implementation provides supprot for the `deltaCertificateDescriptor` extension in X.509 Certificate Extension.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Building and Testing](#building-and-testing)


## Overview

The Chameleon Certificates draft introduces a mechanism to encode the differences (delta) between two related X.509 certificates — called a base certificate and a delta certificate — in an extension within the base certificate.
This allows systems to reconstruct the delta certificate from the base without transferring both full chains. This is particularly useful for:
- PQC migration (e.g., ECDSA ↔ ML-DSA)
- Reduced bandwidth and storage overhead
- Full backward compatibility (non-critical v3 extension)


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
./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl --libdir=lib
make -j$(nproc)
sudo make install
```

### Testing Process

This section describes how to test the Chameleon certificate implementation using OpenSSL 3.3.4 with OQS (Open Quantum Safe) supprot.

#### Prerequisites
- OpenSSL 3.3.4 with OQS provider enabled
- Working directory for test certificates

#### Test Setup

```bash
# Create a working directory
mkdir Classic_Root Classic_ICA PQ_Root PQ_ICA Server

mkdir \
Classic_Root/cert Classic_Root/key PQ_Root/cert PQ_Root/key \
Classic_ICA/cert Classic_ICA/key Classic_ICA/csr \
PQ_ICA/cert PQ_ICA/key PQ_ICA/csr \
Server/cert Server/key Server/csr
```

#### Step 1: Generate Key

```bash
# Classical private key (ECDSA)
openssl ecparam -genkey -name secp256r1 -out Classic_Root/key/ca.p256_key.pem
openssl ecparam -genkey -name secp256r1 -out Classic_ICA/key/ica.p256_key.pem
openssl ecparam -genkey -name secp256r1 -out Server/key/server.p256_key.pem

# PQ private key (ML-DSA)
openssl genpkey -algorithm mldsa44 -out PQ_Root/key/ca.mldsa44_key.pem
openssl genpkey -algorithm mldsa44 -out PQ_ICA/key/ica.mldsa44_key.pem
openssl genpkey -algorithm mldsa44 -out Server/key/server.mldsa44_key.pem
```

#### Step 2: Root CA Certificate (self-sign)

```bash
# Classical Certificate Issue (ECDSA)
openssl req -new -x509 \
-key Classic_Root/key/ca.p256_key.pem \
-out Classic_Root/cert/ca.p256_cert.pem \
-subj "/CN=Classic Root CA" -days 3650 \
-addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
-addext "keyUsage=critical,keyCertSign,cRLSign" \
-addext "subjectKeyIdentifier=hash" \
-addext "authorityKeyIdentifier=keyid:always,issuer"

# PQ Certificate Issue (ML-DSA)
openssl req -new -x509 \
-key PQ_Root/key/ca.mldsa44_key.pem \
-out PQ_Root/cert/ca.mldsa44_cert.pem \
-subj "/CN=PQ Root CA" -days 3650 \
-addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
-addext "keyUsage=critical,keyCertSign,cRLSign" \
-addext "subjectKeyIdentifier=hash" \
-addext "authorityKeyIdentifier=keyid:always,issuer"
```

#### Step 3: Intermediate CA Certificate

**3.1 Intermedicate CA Certificate Request**
```bash
# ICA CSR Issue
openssl req -new \
-key Classic_ICA/key/ica.p256_key.pem \
-out Classic_ICA/csr/ica.p256_csr.pem \
-subj "/CN=Classic Intermediate CA"

openssl req -new \
-key PQ_ICA/key/ica.mldsa44_key.pem \
-out PQ_ICA/csr/ica.mldsa44_csr.pem \
-subj "/CN=PQ Intermediate CA"
```

**3.2 Intermediate CA Certificate Extension**
``` bash
# ica_ext_lv1.cnf
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
```

**3.3 intermediate CA Certificate Issue**
```bash
# ICA Classical Certificate Issue (ECDSA)
openssl x509 -req -days 1850 \
-in Classic_ICA/csr/ica.p256_csr.pem \
-CA Classic_Root/cert/ca.p256_cert.pem \
-CAkey Classic_Root/key/ca.p256_key.pem \
-CAcreateserial \
-out Classic_ICA/cert/ica.p256_cert.pem \
-extfile Classic_ICA/ica_ext_lv1.cnf

# ICA PQ Certificate Issue (ML-DSA)
openssl x509 -req -days 1850 \
-in PQ_ICA/csr/ica.mldsa44_csr.pem \
-CA PQ_Root/cert/ca.mldsa44_cert.pem \
-CAkey PQ_Root/key/ca.mldsa44_key.pem \
-CAcreateserial \
-out PQ_ICA/cert/ica.mldsa44_cert.pem \
-extfile PQ_ICA/ica_ext_lv1.cnf
```

#### Step 4: Server Certificate (Chameleon, ML-DSA + ECDSA)

**4.1 Delta Certificate Issue**
```bash
# Delta Certificate CSR Issue (ML-DSA)
openssl req -new \
-key Server/key/server.mldsa44_key.pem \
-out Server/csr/server.delta.mldsa44_csr.pem \
-subj "/CN=Server PQ Cert"

# Delta Certificate Issue
openssl x509 -req \
-in Server/csr/server.delta.mldsa44_csr.pem \
-CA PQ_ICA/cert/ica.mldsa44_cert.pem \
-CAkey PQ_ICA/key/ica.mldsa44_key.pem \
-CAcreateserial \
-out Server/cert/server.delta.mldsa44_cert.pem
```

**4.2 Chameleon Certificate Issue**
```bash
# Chameleon Certificate CSR Issue (ECDSA)
openssl req -new \
-key Server/key/server.p256_key.pem \
-out Server/csr/server.chameleon.mldsa44_p256_csr.pem \
-subj "/CN=Server Chameleon Cert"

# Chameleon Certificate Issue (ECDSA + ML-DSA)
openssl x509 -req \
-in Server/csr/server.chameleon.mldsa44_p256_csr.pem \
-CA Classic_ICA/cert/ica.p256_cert.pem \
-CAkey Classic_ICA/key/ica.p256_key.pem \
-CAcreateserial \
-out Server/cert/server.chameleon.mldsa44_p256_cert.pem \
-delta_cert Server/certserver.delta.mldsa44_cert.pem
```

#### Step 5: Verification

**5.1 Generate Bundle**
```bash
cat Classic_Root/cert/ca.p256_cert.pem PQ_Root/cert/ca.mldsa44_cert.pem > Server/cert/rootca_lv1.pem
cat Classic_ICA/cert/ica.p256_cert.pem PQ_ICA/cert/ica.mldsa44_cert.pem > Server/cert/ica_lv1.pem
```

**5.2 Verify Certificate**
```bash
openssl verify \
-CAfile Server/cert/rootca_lv1.pem \
-untrusted Server/cert/ica_lv1.pem \
-dcd_verify \
Server/cert/server.chameleon.mldsa44_p256_cert.pem
```

#### Step 6: TLS Handshaking Testing

**6.1 Generate Certificate Chain**
```bash
cat Server/cert/server.chameleon.mldsa44_p256_cert.pem \
Classic_ICA/cert/ica.p256_cert.pem \
PQ_ICA/cert/ica.mldsa44_cert.pem \
> Server/cert/chameleon_server_chain_lv1.pem
```

**Server**
```bash
openssl s_server -accept 14434 \
-cert Server/cert/chameleon_server_chain_lv1.pem \
-key Server/key/server.p256_key.pem \
-hybkey Server/key/server.mldsa44_key.pem \
-hybcert chameleon \
-tls1_3 -msg -state
```

**Client**
```bash
openssl s_client -connect 127.0.0.1:14434 \
-CAfile Server/cert/rootca_lv1.pem \
-hybcert chameleon \
-tls1_3 -msg -state
```