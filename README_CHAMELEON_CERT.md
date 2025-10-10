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


## Features

1. **Delta Certificate Descriptor (DCD) Extension** (`id-ce-deltaCertificateDescriptor`)
    - Embedded in the base certificate as a non-critical extension
    - Contains only the differences required to reconstruct the paired delta certificate (serial, signature algorithm, extensions, etc.)
    - Compatible with existing PKI validation (RFC 5280)

2. **OpenSSL Integration**
    - Added encoder/decoder for DCD in crypto/x509/v3_dcd.c.
    - New CLI options in apps/verify.c:
        -  -dcd_verify


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

This section describes how to test the Chameleon certificate implementation using OpenSSL 3.3.4 with OQS (Open Quantum Safe) supprot.

#### Prerequisites
- OpenSSL 3.3.4 with OQS provider enabled
- Working directory for test certificates

#### Test Setup
```bash
# Create a working directory
mkdir -p test_chameleon_certs
cd test_chameleon_certs
```

#### Step 1: Generate Base Key (ECDSA)
```bash
# Base private key (ECDSA)
openssl ecparam -name prime256v1 -genkey -noout -out base_key.pem
```

#### Step 2: Create Delta Certicate (ML-DSA)PQC
```bash
openssl req -new -x509 -newkey mldsa44 -keyout delta_key.pem -out delta_cert.pem -nodes -subj "/CN=Delta Certificate" -days 365
```

#### Step 3: Create Paired Certificate (ECDAS + ML-DSA)
```bash
openssl req -new -x509 -key base_key.pem -out paired_cert.pem -nodes -subj "/CN=Paired Certificate" -days 365 -addext "deltaCertificateDescriptor=file:./delta_cert.pem"
```

#### Step 4: Verification
```bash
openssl verify -CAfile paired_cert.pem -dcd_verify paired_cert.pem
```