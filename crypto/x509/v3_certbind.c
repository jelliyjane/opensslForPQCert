/* certbind.c - Implements the relatedCertRequest attribute for CSRs and relatedCertificate extension */

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1t.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/stack.h>
#include <openssl/conf.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <openssl/obj_mac.h>
#include <openssl/v3_certbind.h>
#include <openssl/safestack.h>
#include <openssl/http.h>
#include <errno.h>


#ifndef NID_id_pe_relatedCert
#define NID_id_pe_relatedCert 1322
#endif

// Default timeout for requestTime freshness (6 months)
#define REQUEST_TIME_FRESHNESS_TIMEOUT 15768000


// Default HTTP timeout for certificate loading (30 seconds)
#define HTTP_TIMEOUT 30

// URI scheme detection macros
#define IS_HTTP_URI(uri) ((uri) != NULL && strncmp((uri), "http://", 7) == 0)
#define IS_HTTPS_URI(uri) ((uri) != NULL && strncmp((uri), "https://", 8) == 0)
#define IS_FILE_URI(uri) ((uri) != NULL && strncmp((uri), "file://", 7) == 0)


// ASN.1 structure definitions
ASN1_SEQUENCE(CERT_ID) = {
    ASN1_SIMPLE(CERT_ID, issuer, X509_NAME),
    ASN1_SIMPLE(CERT_ID, serialNumber, ASN1_INTEGER)
} ASN1_SEQUENCE_END(CERT_ID)
IMPLEMENT_ASN1_FUNCTIONS(CERT_ID)

ASN1_SEQUENCE(BINARY_TIME) = {
    ASN1_SIMPLE(BINARY_TIME, time, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(BINARY_TIME)
IMPLEMENT_ASN1_FUNCTIONS(BINARY_TIME)

ASN1_SEQUENCE(UNIFORM_RESOURCE_IDENTIFIERS) = {
    ASN1_SEQUENCE_OF(UNIFORM_RESOURCE_IDENTIFIERS, uris, ASN1_IA5STRING)
} ASN1_SEQUENCE_END(UNIFORM_RESOURCE_IDENTIFIERS)
IMPLEMENT_ASN1_FUNCTIONS(UNIFORM_RESOURCE_IDENTIFIERS)

ASN1_SEQUENCE(REQUESTER_CERTIFICATE) = {
    ASN1_SIMPLE(REQUESTER_CERTIFICATE, certID, CERT_ID),
    ASN1_SIMPLE(REQUESTER_CERTIFICATE, requestTime, BINARY_TIME),
    ASN1_SIMPLE(REQUESTER_CERTIFICATE, locationInfo, UNIFORM_RESOURCE_IDENTIFIERS),
    ASN1_OPT(REQUESTER_CERTIFICATE, signature, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(REQUESTER_CERTIFICATE)
IMPLEMENT_ASN1_FUNCTIONS(REQUESTER_CERTIFICATE)

ASN1_SEQUENCE(RELATED_CERTIFICATE) = {
    ASN1_SIMPLE(RELATED_CERTIFICATE, hashAlgorithm, X509_ALGOR),
    ASN1_SIMPLE(RELATED_CERTIFICATE, hashValue, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(RELATED_CERTIFICATE)
IMPLEMENT_ASN1_FUNCTIONS(RELATED_CERTIFICATE)

/* Export ASN.1 functions for RELATED_CERTIFICATE */
OPENSSL_EXPORT RELATED_CERTIFICATE *RELATED_CERTIFICATE_new(void);
OPENSSL_EXPORT void RELATED_CERTIFICATE_free(RELATED_CERTIFICATE *a);
OPENSSL_EXPORT RELATED_CERTIFICATE *d2i_RELATED_CERTIFICATE(RELATED_CERTIFICATE **a, const unsigned char **in, long len);
OPENSSL_EXPORT int i2d_RELATED_CERTIFICATE(const RELATED_CERTIFICATE *a, unsigned char **out);

// Helper function to create BinaryTime from time_t according to RFC 6019
static BINARY_TIME *create_binary_time(time_t t) {
    BINARY_TIME *bt = BINARY_TIME_new();
    if (!bt) return NULL;
    
    // RFC 6019: BinaryTime is a 64-bit integer representing seconds since 1970-01-01 00:00:00 UTC
    uint64_t binary_time = (uint64_t)t;
    unsigned char time_bytes[8];
    
    // Convert to big-endian format
    time_bytes[0] = (binary_time >> 56) & 0xFF;
    time_bytes[1] = (binary_time >> 48) & 0xFF;
    time_bytes[2] = (binary_time >> 40) & 0xFF;
    time_bytes[3] = (binary_time >> 32) & 0xFF;
    time_bytes[4] = (binary_time >> 24) & 0xFF;
    time_bytes[5] = (binary_time >> 16) & 0xFF;
    time_bytes[6] = (binary_time >> 8) & 0xFF;
    time_bytes[7] = binary_time & 0xFF;
    
    if (!ASN1_OCTET_STRING_set(bt->time, time_bytes, 8)) {
        BINARY_TIME_free(bt);
        return NULL;
    }
    
    return bt;
}

// Helper function to extract time_t from BinaryTime
static time_t extract_time_from_binary_time(BINARY_TIME *bt) {
    if (!bt || !bt->time || bt->time->length != 8) return 0;
    
    uint64_t binary_time = 0;
    const unsigned char *time_bytes = bt->time->data;
    
    // Convert from big-endian format
    binary_time = ((uint64_t)time_bytes[0] << 56) |
                  ((uint64_t)time_bytes[1] << 48) |
                  ((uint64_t)time_bytes[2] << 40) |
                  ((uint64_t)time_bytes[3] << 32) |
                  ((uint64_t)time_bytes[4] << 24) |
                  ((uint64_t)time_bytes[5] << 16) |
                  ((uint64_t)time_bytes[6] << 8) |
                  (uint64_t)time_bytes[7];
    
    return (time_t)binary_time;
}

// Helper function to create UniformResourceIdentifiers from URI string
static UNIFORM_RESOURCE_IDENTIFIERS *create_uri_sequence(const char *uri) {
    UNIFORM_RESOURCE_IDENTIFIERS *uris = UNIFORM_RESOURCE_IDENTIFIERS_new();
    if (!uris) return NULL;
    
    ASN1_IA5STRING *uri_str = ASN1_IA5STRING_new();
    if (!uri_str) {
        UNIFORM_RESOURCE_IDENTIFIERS_free(uris);
        return NULL;
    }
    
    if (!ASN1_STRING_set(uri_str, uri, strlen(uri))) {
        ASN1_IA5STRING_free(uri_str);
        UNIFORM_RESOURCE_IDENTIFIERS_free(uris);
        return NULL;
    }
    
    if (!uris->uris)
        uris->uris = sk_ASN1_STRING_new_null();
    if (!uris->uris || !sk_ASN1_STRING_push(uris->uris, (ASN1_STRING *)uri_str)) {
        ASN1_IA5STRING_free(uri_str);
        UNIFORM_RESOURCE_IDENTIFIERS_free(uris);
        return NULL;
    }
    
    return uris;
}

int add_related_cert_request_to_csr(X509_REQ *req, EVP_PKEY *pkey, X509 *related_cert, 
                                   const char *uri, const EVP_MD *hash_alg) {
    if (!req || !pkey || !related_cert || !uri)
        return 0;

    int ret = 0;
    REQUESTER_CERTIFICATE *rcr = NULL;
    CERT_ID *cid = NULL;
    ASN1_OBJECT *obj = NULL;
    X509_ATTRIBUTE *attr = NULL;
    unsigned char *buf = NULL, *sigbuf = NULL;
    int len = 0;
    size_t siglen = 0;
    EVP_MD_CTX *mdctx = NULL;

    // Use SHA-256 as default if no hash algorithm specified
    if (!hash_alg) hash_alg = EVP_sha256();

    // Build REQUESTER_CERTIFICATE
    rcr = REQUESTER_CERTIFICATE_new();
    if (!rcr) {
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    // Set certID
    cid = CERT_ID_new();
    if (!cid) {
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    cid->issuer = X509_NAME_dup(X509_get_issuer_name(related_cert));
    cid->serialNumber = ASN1_INTEGER_dup(X509_get_serialNumber(related_cert));
    if (!cid->issuer || !cid->serialNumber) {
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    rcr->certID = cid;

    // Set requestTime using BinaryTime format
    rcr->requestTime = create_binary_time(time(NULL));
    if (!rcr->requestTime) {
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    // Set locationInfo using proper URI sequence
    rcr->locationInfo = create_uri_sequence(uri);
    if (!rcr->locationInfo) {
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    // Remove signature temporarily for signing
    rcr->signature = NULL;
    len = i2d_REQUESTER_CERTIFICATE(rcr, NULL);
    if (len <= 0) {
        ERR_raise(ERR_LIB_X509, ERR_R_ASN1_LIB);
        goto err;
    }

    buf = OPENSSL_malloc(len);
    if (!buf) {
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    unsigned char *p = buf;
    if (i2d_REQUESTER_CERTIFICATE(rcr, &p) <= 0) {
        ERR_raise(ERR_LIB_X509, ERR_R_ASN1_LIB);
        goto err;
    }
    
    // Sign the encoded structure
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        ERR_raise(ERR_LIB_X509, ERR_R_EVP_LIB);
        goto err;
    }

    if (EVP_DigestSignInit(mdctx, NULL, hash_alg, NULL, pkey) <= 0 ||
        EVP_DigestSignUpdate(mdctx, buf, len) <= 0 ||
        EVP_DigestSignFinal(mdctx, NULL, &siglen) <= 0) {
        ERR_raise(ERR_LIB_X509, ERR_R_EVP_LIB);
        goto err;
    }

    sigbuf = OPENSSL_malloc(siglen);
    if (!sigbuf) {
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EVP_DigestSignFinal(mdctx, sigbuf, &siglen) <= 0) {
        ERR_raise(ERR_LIB_X509, ERR_R_EVP_LIB);
        goto err;
    }

    EVP_MD_CTX_free(mdctx); mdctx = NULL;
    OPENSSL_free(buf); buf = NULL;

    rcr->signature = ASN1_BIT_STRING_new();
    if (!rcr->signature || !ASN1_BIT_STRING_set(rcr->signature, sigbuf, siglen)) {
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    // Re-encode with signature
    len = i2d_REQUESTER_CERTIFICATE(rcr, NULL);
    if (len <= 0) {
        ERR_raise(ERR_LIB_X509, ERR_R_ASN1_LIB);
        goto err;
    }
    buf = OPENSSL_malloc(len);
    if (!buf) {
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    p = buf;
    if (i2d_REQUESTER_CERTIFICATE(rcr, &p) <= 0) {
        ERR_raise(ERR_LIB_X509, ERR_R_ASN1_LIB);
        goto err;
    }

    // Create the attribute using the correct method
    obj = OBJ_txt2obj("1.2.840.113549.1.9.16.2.60", 1);
    if (!obj) {
        ERR_raise(ERR_LIB_X509, ERR_R_OBJ_LIB);
        goto err;
    }

    // Create attribute with proper ASN.1 encoding
    attr = X509_ATTRIBUTE_create_by_OBJ(NULL, obj, V_ASN1_SEQUENCE, buf, len);
    if (!attr) {
        ERR_raise(ERR_LIB_X509, ERR_R_X509_LIB);
        goto err;
    }

    // Add attribute to CSR using the correct method
    if (!X509_REQ_add1_attr(req, attr)) {
        ERR_raise(ERR_LIB_X509, ERR_R_X509_LIB);
        goto err;
    }

    ret = 1;

err:
    if (!ret) {
        // Error handling - errors are already set in the error stack
    }
    REQUESTER_CERTIFICATE_free(rcr);
    X509_ATTRIBUTE_free(attr);
    ASN1_OBJECT_free(obj);
    OPENSSL_clear_free(buf, len);
    OPENSSL_clear_free(sigbuf, siglen);
    EVP_MD_CTX_free(mdctx);
    return ret;
}

// Function to add RelatedCertificate extension to X.509 certificate
int add_related_certificate_extension(X509 *cert, X509 *related_cert, const EVP_MD *hash_alg, const char *uri) {
    if (!cert || !related_cert || !hash_alg || !uri) {
        return 0;
    }
    int ret = 0;
    RELATED_CERTIFICATE *rc = NULL;
    X509_ALGOR *hash_algor = NULL;
    ASN1_OCTET_STRING *hash_value = NULL;
    unsigned char *cert_der = NULL;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    int cert_len = 0;
    unsigned char *ext_der = NULL;
    int ext_len = 0;

    // Create RelatedCertificate structure
    rc = RELATED_CERTIFICATE_new();
    if (!rc) {
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    // Set hash algorithm
    hash_algor = X509_ALGOR_new();
    if (!hash_algor) {
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!X509_ALGOR_set0(hash_algor, OBJ_nid2obj(EVP_MD_get_type(hash_alg)), 
                        V_ASN1_NULL, NULL)) {
        ERR_raise(ERR_LIB_X509, ERR_R_X509_LIB);
        goto err;
    }
    rc->hashAlgorithm = hash_algor;

    // Calculate hash of the related certificate
    cert_len = i2d_X509(related_cert, &cert_der);
    if (cert_len <= 0) {
        ERR_raise(ERR_LIB_X509, ERR_R_ASN1_LIB);
        goto err;
    }

    if (!EVP_Digest(cert_der, cert_len, hash, &hash_len, hash_alg, NULL)) {
        ERR_raise(ERR_LIB_X509, ERR_R_EVP_LIB);
        goto err;
    }

    // Set hash value
    hash_value = ASN1_OCTET_STRING_new();
    if (!hash_value) {
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!ASN1_OCTET_STRING_set(hash_value, hash, hash_len)) {
        ERR_raise(ERR_LIB_X509, ERR_R_ASN1_LIB);
        goto err;
    }
    rc->hashValue = hash_value;

     // Encode the RelatedCertificate structure
    ext_len = i2d_RELATED_CERTIFICATE(rc, &ext_der);
    if (ext_len <= 0) {
        ERR_raise(ERR_LIB_X509, ERR_R_ASN1_LIB);
        goto err;
    }

    // Create the extension
    X509_EXTENSION *ext = X509_EXTENSION_new();
    if (!ext) {
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    ASN1_OBJECT *obj = OBJ_txt2obj("1.3.6.1.5.5.7.1.36", 1);
    if (!obj) {
        ERR_raise(ERR_LIB_X509, ERR_R_OBJ_LIB);
        X509_EXTENSION_free(ext);
        goto err;
    }

    ASN1_OCTET_STRING *ext_data = ASN1_OCTET_STRING_new();
    if (!ext_data) {
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        ASN1_OBJECT_free(obj);
        X509_EXTENSION_free(ext);
        goto err;
    }

    if (!ASN1_OCTET_STRING_set(ext_data, ext_der, ext_len)) {
        ERR_raise(ERR_LIB_X509, ERR_R_ASN1_LIB);
        ASN1_OCTET_STRING_free(ext_data);
        ASN1_OBJECT_free(obj);
        X509_EXTENSION_free(ext);
        goto err;
    }

    // Set extension object and data
    if (!X509_EXTENSION_set_object(ext, obj)) {
        ERR_raise(ERR_LIB_X509, ERR_R_X509_LIB);
        ASN1_OCTET_STRING_free(ext_data);
        ASN1_OBJECT_free(obj);
        X509_EXTENSION_free(ext);
        goto err;
    }

    if (!X509_EXTENSION_set_data(ext, ext_data)) {
        ERR_raise(ERR_LIB_X509, ERR_R_X509_LIB);
        ASN1_OCTET_STRING_free(ext_data);
        X509_EXTENSION_free(ext);
        goto err;
    }

    // Add extension to certificate
    if (!X509_add_ext(cert, ext, -1)) {
        ERR_raise(ERR_LIB_X509, ERR_R_X509_LIB);
        X509_EXTENSION_free(ext);
        goto err;
    }

    X509_EXTENSION_free(ext);
    ret = 1;

err:
    if (!ret) {
        // Error handling - errors are already set in the error stack
    }
    RELATED_CERTIFICATE_free(rc);
    OPENSSL_free(cert_der);
    OPENSSL_free(ext_der);
    return ret;
}



// Function to verify RelatedCertificate extension
OPENSSL_EXPORT int verify_related_certificate_extension(X509 *cert, X509 *related_cert) {
    if (!cert || !related_cert)
        return -1; // Invalid parameters

    RELATED_CERTIFICATE *rc = NULL;
    X509_EXTENSION *ext = NULL;
    int idx = -1;
    int ret = -1;
    unsigned char *cert_der = NULL;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    int cert_len = 0;
    const EVP_MD *hash_alg = NULL;

    // Find the RelatedCertificate extension
    idx = X509_get_ext_by_NID(cert, OBJ_txt2nid("1.3.6.1.5.5.7.1.36"), -1);
    if (idx < 0) {
        // Extension not found - this is acceptable, return -1 to indicate no extension
        return -1;
    }

    ext = X509_get_ext(cert, idx);
    if (!ext) {
        ERR_raise(ERR_LIB_X509, ERR_R_X509_LIB);
        return 0; // Extension found but invalid
    }

    // Get the extension data
    ASN1_OCTET_STRING *ext_data = X509_EXTENSION_get_data(ext);
    if (!ext_data) {
        ERR_raise(ERR_LIB_X509, ERR_R_X509_LIB);
        return 0; // Extension found but invalid
    }

    // Decode the RelatedCertificate structure
    const unsigned char *p = ext_data->data;
    rc = d2i_RELATED_CERTIFICATE(NULL, &p, ext_data->length);
    if (!rc) {
        ERR_raise(ERR_LIB_X509, ERR_R_ASN1_LIB);
        return 0; // Extension found but invalid
    }

    // Get hash algorithm
    hash_alg = EVP_get_digestbyobj(rc->hashAlgorithm->algorithm);
    if (!hash_alg) {
        ERR_raise(ERR_LIB_X509, ERR_R_EVP_LIB);
        RELATED_CERTIFICATE_free(rc);
        return 0; // Extension found but invalid
    }

    // Calculate hash of the related certificate
    cert_len = i2d_X509(related_cert, &cert_der);
    if (cert_len <= 0) {
        RELATED_CERTIFICATE_free(rc);
        return 0; // Extension found but invalid
    }

    if (!EVP_Digest(cert_der, cert_len, hash, &hash_len, hash_alg, NULL)) {
        OPENSSL_free(cert_der);
        RELATED_CERTIFICATE_free(rc);
        return 0; // Extension found but invalid
    }

    // Compare hashes
    if (hash_len != (unsigned int)rc->hashValue->length ||
        memcmp(hash, rc->hashValue->data, hash_len) != 0) {
        ERR_raise(ERR_LIB_X509, X509_R_CERTIFICATE_VERIFICATION_FAILED);
        OPENSSL_free(cert_der);
        RELATED_CERTIFICATE_free(rc);
        return 0; // Extension found but validation failed
    }

    ret = 1; // Extension found and validation successful

    OPENSSL_free(cert_der);
    RELATED_CERTIFICATE_free(rc);
    return ret;
}

// Function to extract RelatedCertificate extension from certificate
OPENSSL_EXPORT RELATED_CERTIFICATE *get_related_certificate_extension(X509 *cert) {
    if (!cert)
        return NULL;

    X509_EXTENSION *ext = NULL;
    int idx = -1;

    idx = X509_get_ext_by_NID(cert, OBJ_txt2nid("1.3.6.1.5.5.7.1.36"), -1);
    if (idx < 0)
        return NULL;

    ext = X509_get_ext(cert, idx);
    if (!ext)
        return NULL;

    // Get the extension data
    ASN1_OCTET_STRING *ext_data = X509_EXTENSION_get_data(ext);
    if (!ext_data)
        return NULL;

    // Decode the RelatedCertificate structure
    const unsigned char *p = ext_data->data;
    return d2i_RELATED_CERTIFICATE(NULL, &p, ext_data->length);
}

// Enhanced certificate loader with HTTP support (HTTPS moved to application level)
static X509 *load_cert_file(const char *path) {
    BIO *out = BIO_new_fp(stderr, BIO_NOCLOSE);
    if (!out) return NULL;
    
    X509 *cert = NULL;
    const char *file_path = path;
    
    // Handle HTTP URIs
    if (IS_HTTP_URI(path)) {
        // Use OpenSSL's HTTP client to fetch the certificate
        cert = X509_load_http(path, NULL, NULL, HTTP_TIMEOUT);
        if (!cert) {
            ERR_print_errors(out);
        }
        BIO_free(out);
        return cert;
    }
    
    // Handle HTTPS URIs - return error with suggestion to use HTTP or file
    if (IS_HTTPS_URI(path)) {
        ERR_raise(ERR_LIB_X509, ERR_R_UNSUPPORTED);
        BIO_free(out);
        return NULL;
    }
    
    // Handle file:// URIs - extract the path
    if (IS_FILE_URI(path)) {
        file_path = path + 7;  // Skip "file://"
        // For file:///path/to/file, we get /path/to/file (absolute)
        // For file://path/to/file, we get path/to/file (relative)
    }
    
    // Handle absolute paths (starting with /) - treat directly as file path
    // This works for both direct absolute paths and file:/// URIs
    if (file_path[0] == '/') {
        // Remove any trailing slashes
        size_t len = strlen(file_path);
        while (len > 1 && file_path[len-1] == '/') {
            len--;
        }
        
        // Create a temporary buffer without trailing slashes
        char *temp_path = OPENSSL_malloc(len + 1);
        if (!temp_path) {
            BIO_free(out);
            ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
        snprintf(temp_path, len + 1, "%.*s", (int)len, file_path);
        
        FILE *fp = fopen(temp_path, "r");
        if (!fp) {
            OPENSSL_free(temp_path);
            BIO_free(out);
            ERR_raise(ERR_LIB_X509, ERR_R_SYS_LIB);
            return NULL;
        }
        cert = PEM_read_X509(fp, NULL, NULL, NULL);
        fclose(fp);
        OPENSSL_free(temp_path);
        if (!cert) {
            ERR_raise(ERR_LIB_X509, ERR_R_PEM_LIB);
        }
        BIO_free(out);
        return cert;
    }
    
    // Handle regular file paths (relative paths or paths without URI scheme)
    FILE *fp = fopen(file_path, "r");
    if (!fp) {
        BIO_free(out);
        ERR_raise(ERR_LIB_X509, ERR_R_SYS_LIB);
        return NULL;
    }
    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!cert) {
        ERR_raise(ERR_LIB_X509, ERR_R_PEM_LIB);
    }
    BIO_free(out);
    return cert;
}

int verify_related_cert_request(X509_REQ *req) {
    BIO *out = BIO_new_fp(stderr, BIO_NOCLOSE);
    if (!out) return 0;

    int idx = X509_REQ_get_attr_by_NID(req, OBJ_txt2nid("1.2.840.113549.1.9.16.2.60"), -1);
    if (idx < 0) {
        BIO_printf(out, "relatedCertRequest attribute not found\n");
        BIO_free(out);
        return -1; // Not an error if attribute is not present
    }

    X509_ATTRIBUTE *attr = X509_REQ_get_attr(req, idx);
    const ASN1_TYPE *av = X509_ATTRIBUTE_get0_type(attr, 0);
    if (!av || av->type != V_ASN1_SEQUENCE) {
        BIO_printf(out, "Invalid relatedCertRequest format\n");
        BIO_free(out);
        return 0;
    }

    const unsigned char *p = av->value.sequence->data;
    REQUESTER_CERTIFICATE *rcr = d2i_REQUESTER_CERTIFICATE(NULL, &p, av->value.sequence->length);
    if (!rcr) {
        BIO_printf(out, "Unable to decode relatedCertRequest attribute\n");
        BIO_free(out);
        return 0;
    }

    // Extract URI from locationInfo
    if (!rcr->locationInfo || sk_ASN1_STRING_num(rcr->locationInfo->uris) == 0) {
        BIO_printf(out, "No URI found in locationInfo\n");
        REQUESTER_CERTIFICATE_free(rcr);
        BIO_free(out);
        return 0;
    }

    ASN1_STRING *uri_str = sk_ASN1_STRING_value(rcr->locationInfo->uris, 0);
    char uri[512] = {0};
    if (uri_str->length >= (int)sizeof(uri)) {
        BIO_printf(out, "URI too long\n");
        REQUESTER_CERTIFICATE_free(rcr);
        BIO_free(out);
        return 0;
    }
    memcpy(uri, uri_str->data, uri_str->length);



    X509 *related_cert = load_cert_file(uri);
    if (!related_cert) {
        BIO_printf(out, "Unable to load related certificate from: %s\n", uri);
        REQUESTER_CERTIFICATE_free(rcr);
        BIO_free(out);
        return 0;
    }

    // Verify certID matches
    if (X509_NAME_cmp(rcr->certID->issuer, X509_get_issuer_name(related_cert)) != 0 ||
        ASN1_INTEGER_cmp(rcr->certID->serialNumber, X509_get_serialNumber(related_cert)) != 0) {
        BIO_printf(out, "certID does not match related certificate\n");
        X509_free(related_cert);
        REQUESTER_CERTIFICATE_free(rcr);
        BIO_free(out);
        return 0;
    }

    // Check timestamp freshness using BinaryTime
    time_t t_req = extract_time_from_binary_time(rcr->requestTime);
    time_t now = time(NULL);
    if (t_req == 0 || labs(now - t_req) > REQUEST_TIME_FRESHNESS_TIMEOUT) {
        BIO_printf(out, "requestTime not fresh (delta: %ld seconds)\n", labs(now - t_req));
        X509_free(related_cert);
        REQUESTER_CERTIFICATE_free(rcr);
        BIO_free(out);
        return 0;
    }

    // Get the public key from the CSR (not the related certificate)
    EVP_PKEY *pubkey = X509_REQ_get_pubkey(req);
    if (!pubkey) {
        BIO_printf(out, "Failed to get public key from CSR\n");
        X509_free(related_cert);
        REQUESTER_CERTIFICATE_free(rcr);
        BIO_free(out);
        return 0;
    }

    // Signature verification
    ASN1_BIT_STRING *saved_sig = rcr->signature;
    rcr->signature = NULL;

    int len = i2d_REQUESTER_CERTIFICATE(rcr, NULL);
    if (len <= 0) {
        BIO_printf(out, "Failed to encode REQUESTER_CERTIFICATE for verification\n");
        EVP_PKEY_free(pubkey);
        X509_free(related_cert);
        REQUESTER_CERTIFICATE_free(rcr);
        BIO_free(out);
        return 0;
    }

    unsigned char *encoded = OPENSSL_malloc(len);
    if (!encoded) {
        EVP_PKEY_free(pubkey);
        X509_free(related_cert);
        REQUESTER_CERTIFICATE_free(rcr);
        BIO_free(out);
        return 0;
    }

    unsigned char *tmp = encoded;
    if (i2d_REQUESTER_CERTIFICATE(rcr, &tmp) <= 0) {
        OPENSSL_free(encoded);
        EVP_PKEY_free(pubkey);
        X509_free(related_cert);
        REQUESTER_CERTIFICATE_free(rcr);
        BIO_free(out);
        return 0;
    }
    
    rcr->signature = saved_sig;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = 0;



    // For BIT STRING, we need to extract the data
    const unsigned char *sig_data = ASN1_STRING_get0_data(rcr->signature);
    int sig_len = ASN1_STRING_length(rcr->signature);

    // Try different hash algorithms if the default fails
    const EVP_MD *hash_algs[] = {EVP_sha256(), EVP_sha384(), EVP_sha512(), EVP_sha1()};
    int num_algs = sizeof(hash_algs) / sizeof(hash_algs[0]);
    
    for (int i = 0; i < num_algs && !ok; i++) {
        if (ctx && pubkey) {
            EVP_MD_CTX_reset(ctx);
            if (EVP_DigestVerifyInit(ctx, NULL, hash_algs[i], NULL, pubkey) == 1 &&
                EVP_DigestVerifyUpdate(ctx, encoded, len) == 1 &&
                EVP_DigestVerifyFinal(ctx, sig_data, sig_len) == 1) {
                BIO_printf(out, "relatedCertRequest signature verification OK with algorithm %d\n", i);
                ok = 1;
                break;
            }
        }
    }

    if (!ok) {
        BIO_printf(out, "relatedCertRequest signature verification FAILED with all algorithms\n");
        ERR_print_errors(out);
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pubkey);
    OPENSSL_free(encoded);
    REQUESTER_CERTIFICATE_free(rcr);
    X509_free(related_cert);
    BIO_free(out);
    return ok;
}

// Function to print RelatedCertificate extension
int print_related_certificate_extension(BIO *bio, X509 *cert, int indent) {
    if (!bio || !cert)
        return 0;

    RELATED_CERTIFICATE *rc = get_related_certificate_extension(cert);
    if (!rc) {
        BIO_printf(bio, "%*sRelatedCertificate: <not present>\n", indent, "");
        return 1;
    }

    BIO_printf(bio, "%*sRelatedCertificate:\n", indent, "");
    BIO_printf(bio, "%*sHash Algorithm: ", indent + 2, "");
    i2a_ASN1_OBJECT(bio, rc->hashAlgorithm->algorithm);
    BIO_printf(bio, "\n%*sHash Value: ", indent + 2, "");
    
    for (int i = 0; i < rc->hashValue->length; i++) {
        BIO_printf(bio, "%02X", rc->hashValue->data[i]);
        if (i + 1 != rc->hashValue->length)
            BIO_printf(bio, ":");
        if ((i + 1) % 16 == 0 && (i + 1) != rc->hashValue->length)
            BIO_printf(bio, "\n%*s", indent + 4, "");
    }
    BIO_printf(bio, "\n");

    // Print URI if present
    if (rc->uri && rc->uri->length > 0) {
        BIO_printf(bio, "%*s", indent + 2, "");
        // Convert file:// to file: for display
        if (rc->uri->length >= 7 && strncmp((char*)rc->uri->data, "file://", 7) == 0) {
            BIO_printf(bio, "file:");
            BIO_write(bio, rc->uri->data + 7, rc->uri->length - 7);
        } else {
            BIO_write(bio, rc->uri->data, rc->uri->length);
        }
        BIO_printf(bio, "\n");
    }

    RELATED_CERTIFICATE_free(rc);
    return 1;
}

// Function to print relatedCertRequest attribute from CSR
int print_related_cert_request(BIO *bio, X509_REQ *req, int indent) {
    if (!bio || !req)
        return 0;

    int idx = X509_REQ_get_attr_by_NID(req, OBJ_txt2nid("1.2.840.113549.1.9.16.2.60"), -1);
    if (idx < 0) {
        BIO_printf(bio, "%*srelatedCertRequest: <not present>\n", indent, "");
        return 1;
    }

    X509_ATTRIBUTE *attr = X509_REQ_get_attr(req, idx);
    const ASN1_TYPE *av = X509_ATTRIBUTE_get0_type(attr, 0);
    if (!av || av->type != V_ASN1_SEQUENCE) {
        BIO_printf(bio, "%*srelatedCertRequest: <invalid format>\n", indent, "");
        return 0;
    }

    const unsigned char *p = av->value.sequence->data;
    REQUESTER_CERTIFICATE *rcr = d2i_REQUESTER_CERTIFICATE(NULL, &p, av->value.sequence->length);
    if (!rcr) {
        BIO_printf(bio, "%*srelatedCertRequest: <unable to decode>\n", indent, "");
        return 0;
    }

    BIO_printf(bio, "%*srelatedCertRequest:\n", indent, "");
    
    // Print certID
    BIO_printf(bio, "%*sIssuer: ", indent + 2, "");
    X509_NAME_print(bio, rcr->certID->issuer, 0);
    BIO_printf(bio, "\n%*sSerial Number: ", indent + 2, "");
    i2a_ASN1_INTEGER(bio, rcr->certID->serialNumber);
    
    // Print requestTime
    time_t req_time = extract_time_from_binary_time(rcr->requestTime);
    BIO_printf(bio, "\n%*sRequest Time: %s", indent + 2, "", ctime(&req_time));
    
    // Print locationInfo
    if (rcr->locationInfo && sk_ASN1_STRING_num(rcr->locationInfo->uris) > 0) {
        ASN1_STRING *uri_str = sk_ASN1_STRING_value(rcr->locationInfo->uris, 0);
        BIO_printf(bio, "%*sURI: ", indent + 2, "");
        BIO_write(bio, uri_str->data, uri_str->length);
    }
    
    BIO_printf(bio, "\n%*sSignature Present: %s\n", indent + 2, "", 
               rcr->signature ? "Yes" : "No");

    REQUESTER_CERTIFICATE_free(rcr);
    return 1;
}

// X509V3 extension method for RelatedCertificate
static int i2r_related_certificate(const X509V3_EXT_METHOD *method, void *ext, BIO *out, int indent)
{
    RELATED_CERTIFICATE *rc = (RELATED_CERTIFICATE *)ext;
    if (!rc) return 0;
    
    BIO_printf(out, "%*sHash Algorithm: ", indent, "");
    i2a_ASN1_OBJECT(out, rc->hashAlgorithm->algorithm);
    BIO_printf(out, "\n%*sHash Value: ", indent, "");
    
    for (int i = 0; i < rc->hashValue->length; i++) {
        BIO_printf(out, "%02X", rc->hashValue->data[i]);
        if (i + 1 != rc->hashValue->length)
            BIO_printf(out, ":");
        if ((i + 1) % 16 == 0 && (i + 1) != rc->hashValue->length)
            BIO_printf(out, "\n%*s", indent + 4, "");
    }
    BIO_printf(out, "\n");

    return 1;
}

static void *d2i_related_certificate(const X509V3_EXT_METHOD *method, const unsigned char **in, long len) {
    return d2i_RELATED_CERTIFICATE(NULL, in, len);
}

// Convert configuration values to RELATED_CERTIFICATE structure (v2i)
static void *v2i_related_certificate(const X509V3_EXT_METHOD *method,
                                     X509V3_CTX *ctx,
                                     STACK_OF(CONF_VALUE) *nval)
{
    RELATED_CERTIFICATE *rc = NULL;
    X509_ALGOR *hash_algor = NULL;
    ASN1_OCTET_STRING *hash_value = NULL;
    X509 *related_cert = NULL;
    unsigned char *cert_der = NULL;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    int cert_len = 0;
    const EVP_MD *hash_alg = EVP_sha256(); // Default to SHA-256
    char *cert_path = NULL;
    char *hash_alg_name = NULL;
    int i, num;
    CONF_VALUE *val;

    if (nval == NULL || (num = sk_CONF_VALUE_num(nval)) == 0) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_EXTENSION_STRING);
        return NULL;
    }

    // Parse configuration values
    for (i = 0; i < num; i++) {
        val = sk_CONF_VALUE_value(nval, i);
        if (val->name == NULL)
            continue;

        if (strcmp(val->name, "certificate") == 0 || strcmp(val->name, "cert") == 0) {
            if (val->value == NULL) {
                ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_EXTENSION_STRING);
                goto err;
            }
            cert_path = val->value;
        } else if (strcmp(val->name, "hashAlgorithm") == 0 || strcmp(val->name, "hash") == 0) {
            if (val->value == NULL) {
                ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_EXTENSION_STRING);
                goto err;
            }
            hash_alg_name = val->value;
        }
    }

    // Certificate path is required
    if (cert_path == NULL) {
        ERR_raise_data(ERR_LIB_X509V3, X509V3_R_INVALID_EXTENSION_STRING,
                       "certificate path is required");
        goto err;
    }

    // Get hash algorithm if specified
    if (hash_alg_name != NULL) {
        hash_alg = EVP_get_digestbyname(hash_alg_name);
        if (hash_alg == NULL) {
            ERR_raise_data(ERR_LIB_X509V3, X509V3_R_INVALID_EXTENSION_STRING,
                           "unknown hash algorithm: %s", hash_alg_name);
            goto err;
        }
    }

    // Load the related certificate
    related_cert = load_cert_file(cert_path);
    if (related_cert == NULL) {
        ERR_raise_data(ERR_LIB_X509V3, X509V3_R_INVALID_EXTENSION_STRING,
                       "failed to load certificate from: %s", cert_path);
        goto err;
    }

    // Create RELATED_CERTIFICATE structure
    rc = RELATED_CERTIFICATE_new();
    if (!rc) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    // Set hash algorithm
    hash_algor = X509_ALGOR_new();
    if (!hash_algor) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!X509_ALGOR_set0(hash_algor, OBJ_nid2obj(EVP_MD_get_type(hash_alg)),
                         V_ASN1_NULL, NULL)) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_X509_LIB);
        goto err;
    }
    rc->hashAlgorithm = hash_algor;

    // Calculate hash of the related certificate
    cert_len = i2d_X509(related_cert, &cert_der);
    if (cert_len <= 0) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB);
        goto err;
    }

    if (!EVP_Digest(cert_der, cert_len, hash, &hash_len, hash_alg, NULL)) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_EVP_LIB);
        goto err;
    }

    // Set hash value
    hash_value = ASN1_OCTET_STRING_new();
    if (!hash_value) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!ASN1_OCTET_STRING_set(hash_value, hash, hash_len)) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB);
        goto err;
    }
    rc->hashValue = hash_value;

    // Cleanup
    X509_free(related_cert);
    OPENSSL_free(cert_der);
    return rc;

err:
    RELATED_CERTIFICATE_free(rc);
    X509_free(related_cert);
    OPENSSL_free(cert_der);
    return NULL;
}

// Convert RELATED_CERTIFICATE structure to configuration values (i2v)
static STACK_OF(CONF_VALUE) *i2v_related_certificate(const X509V3_EXT_METHOD *method,
                                                     void *ext,
                                                     STACK_OF(CONF_VALUE) *extlist)
{
    RELATED_CERTIFICATE *rc = (RELATED_CERTIFICATE *)ext;
    char hash_alg_name[80];
    char hash_hex[EVP_MAX_MD_SIZE * 2 + 1];
    int i;

    if (rc == NULL) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    // Get hash algorithm name
    if (rc->hashAlgorithm && rc->hashAlgorithm->algorithm) {
        OBJ_obj2txt(hash_alg_name, sizeof(hash_alg_name),
                    rc->hashAlgorithm->algorithm, 0);
    } else {
        strncpy(hash_alg_name, "unknown", sizeof(hash_alg_name) - 1);
        hash_alg_name[sizeof(hash_alg_name) - 1] = '\0';
    }

    // Convert hash value to hex string
    if (rc->hashValue && rc->hashValue->length > 0) {
        for (i = 0; i < rc->hashValue->length && i < EVP_MAX_MD_SIZE; i++) {
            snprintf(hash_hex + (i * 2), 3, "%02X", rc->hashValue->data[i]);
        }
        hash_hex[rc->hashValue->length * 2] = '\0';
    } else {
        hash_hex[0] = '\0';
    }

    // Add values to the list
    if (extlist == NULL) {
        extlist = sk_CONF_VALUE_new_null();
        if (extlist == NULL) {
            ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
    }

    if (!X509V3_add_value("hashAlgorithm", hash_alg_name, &extlist)) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        if (extlist != NULL)
            sk_CONF_VALUE_pop_free(extlist, X509V3_conf_free);
        return NULL;
    }

    if (!X509V3_add_value("hashValue", hash_hex, &extlist)) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        if (extlist != NULL)
            sk_CONF_VALUE_pop_free(extlist, X509V3_conf_free);
        return NULL;
    }

    return extlist;
}

X509V3_EXT_METHOD v3_related_certificate = {
    NID_id_pe_relatedCert,           /* ext_nid */
    X509V3_EXT_MULTILINE,            /* ext_flags */
    ASN1_ITEM_ref(RELATED_CERTIFICATE), /* it */
    NULL, NULL,                      /* ext_new, ext_free */
    (X509V3_EXT_D2I)d2i_related_certificate,         /* d2i */
    NULL,                            /* i2d */
    NULL, NULL,                      /* i2s, s2i */
    (X509V3_EXT_I2V)i2v_related_certificate,  /* i2v */
    (X509V3_EXT_V2I)v2i_related_certificate,   /* v2i */
    i2r_related_certificate,         /* i2r */
    NULL,                            /* r2i */
    NULL                             /* usr_data */
};

// Function to initialize RelatedCertificate extension support
int v3_certbind_init(void) {
    // Register the extension method
    if (!X509V3_EXT_add(&v3_related_certificate)) {
        return 0;
    }
    return 1;
}
