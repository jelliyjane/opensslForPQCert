#ifndef OPENSSL_V3_DCD_H
#define OPENSSL_V3_DCD_H

#include <openssl/x509.h>

int verify_dcd_signature(X509 *cert);

#endif