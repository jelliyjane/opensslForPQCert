// crypto/x509/v3_delta_cert.c
#include <openssl/x509v3.h>
#include <openssl/asn1t.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <string.h>

#include <openssl/v3_dcd.h>
#include <crypto/x509.h>


typedef struct DeltaValidity_st {
    ASN1_TIME *notBefore;
    ASN1_TIME *notAfter;
} DeltaValidity;

typedef struct DeltaCertificateDescriptor_st {
    ASN1_INTEGER *serialNumber;
    X509_ALGOR *signature;
    X509_NAME *issuer;
    DeltaValidity *validity;
    X509_NAME *subject;
    X509_PUBKEY *SubjectPublicKeyInfo;
    STACK_OF(X509_EXTENSION) *extensions;
    ASN1_BIT_STRING *signatureValue;
} DeltaCertificateDescriptor;

ASN1_SEQUENCE(DeltaValidity) = {
    ASN1_SIMPLE(DeltaValidity, notBefore, ASN1_TIME),
    ASN1_SIMPLE(DeltaValidity, notAfter, ASN1_TIME),
} ASN1_SEQUENCE_END(DeltaValidity);

IMPLEMENT_ASN1_FUNCTIONS(DeltaValidity);

ASN1_SEQUENCE(DeltaCertificateDescriptor) = {
    ASN1_SIMPLE(DeltaCertificateDescriptor, serialNumber, ASN1_INTEGER),
    ASN1_EXP_OPT(DeltaCertificateDescriptor, signature, X509_ALGOR, 0),
    ASN1_EXP_OPT(DeltaCertificateDescriptor, issuer, X509_NAME, 1),
    ASN1_EXP_OPT(DeltaCertificateDescriptor, validity, DeltaValidity, 2),
    ASN1_EXP_OPT(DeltaCertificateDescriptor, subject, X509_NAME, 3),
    ASN1_SIMPLE(DeltaCertificateDescriptor, SubjectPublicKeyInfo, X509_PUBKEY),
    ASN1_EXP_SEQUENCE_OF_OPT(DeltaCertificateDescriptor, extensions, X509_EXTENSION, 4),
    ASN1_SIMPLE(DeltaCertificateDescriptor, signatureValue, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(DeltaCertificateDescriptor);

IMPLEMENT_ASN1_FUNCTIONS(DeltaCertificateDescriptor);

static void *v2i_dcd_cert(const struct v3_ext_method *method, struct v3_ext_ctx *ctx, STACK_OF(CONF_VALUE) *value);
static int i2r_dcd_cert(const struct v3_ext_method *method, void *ext, BIO *out, int indent);

X509_ALGOR *copy_sigalg_from_cert(X509 *cert);
DeltaValidity *copy_validity_from_cert(X509 *cert);
STACK_OF(X509_EXTENSION) *copy_extensions_except_delta(X509 *cert);

const X509V3_EXT_METHOD v3_delta_cert_desc = {
    NID_id_ce_deltaCertificateDescriptor,
    0,
    ASN1_ITEM_ref(DeltaCertificateDescriptor),
    NULL, NULL, NULL, NULL,
    NULL,
    NULL,
    NULL,
        v2i_dcd_cert,
        i2r_dcd_cert,
    NULL,
    NULL
};

static void *v2i_dcd_cert(
    const struct v3_ext_method *method, 
    struct v3_ext_ctx *ctx, 
    STACK_OF(CONF_VALUE) *value) {
    
    DeltaCertificateDescriptor *dcd = DeltaCertificateDescriptor_new();

    if (sk_CONF_VALUE_num(value) != 1) {
        fprintf(stderr, "deltaCertificateDescriptor must contain only one certificate\n");
        return NULL;
    }

    CONF_VALUE *val = sk_CONF_VALUE_value(value, 0);

    if (strncmp("file", val->name, 4)) {
        fprintf(stderr, "Value for deltaCertificateDescriptor must start with 'file:'\n");
        return NULL;
    }

    FILE *cert_file = fopen(val->value, "rb");
    if (!cert_file) {
        fprintf(stderr, "Failed to open certificate file\n");
        return NULL;
    }

    X509 *cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    if (!cert) {
        fprintf(stderr, "Failed to load certificate\n");
        return NULL;
    }

    int len = i2d_re_X509_tbs(cert, NULL);

    dcd->serialNumber = ASN1_INTEGER_dup(X509_get_serialNumber(cert));
    dcd->signature = copy_sigalg_from_cert(cert);
    dcd->subject = X509_NAME_dup(X509_get_subject_name(cert));
    dcd->issuer = X509_NAME_dup(X509_get_issuer_name(cert));
    dcd->validity = copy_validity_from_cert(cert);
    dcd->extensions = copy_extensions_except_delta(cert);
    

    // Delta SubjectPublicKeyInfo
    EVP_PKEY *pubkey = X509_get_pubkey(cert);
    if (!pubkey) {
        fprintf(stderr, "Failed to extract public key\n");
        X509_free(cert);
        return NULL;
    }

    if (!dcd || !X509_PUBKEY_set(&dcd->SubjectPublicKeyInfo, pubkey)) {
        fprintf(stderr, "Failed to set public key in DeltaCertificateDescriptor\n");
        EVP_PKEY_free(pubkey);
        X509_free(cert);
        DeltaCertificateDescriptor_free(dcd);
        return NULL;
    }

    // Delta signatureValue
    const ASN1_BIT_STRING *sig = NULL;
    X509_get0_signature(&sig, NULL, cert);
    if (sig != NULL) {
        dcd->signatureValue = ASN1_STRING_dup(sig);
        if(!dcd->signatureValue) {
            fprintf(stderr, "Failed to copy signatureValue\n");
            X509_free(cert);
            DeltaCertificateDescriptor_free(dcd);
            return NULL;
        }
    }

    EVP_PKEY_free(pubkey);
    X509_free(cert);
    return dcd;
}

static int i2r_dcd_cert(const struct v3_ext_method *method, void *ext, BIO *out, int indent) {
    DeltaCertificateDescriptor *dcd = ext;
    int ret = 0;

    if (dcd == NULL) {
        BIO_printf(out, "%*sNo DeltaCertificateDescriptor data\n", indent, "");
        return 1;
    }

    if (dcd->serialNumber) {
        BIO_printf(out, "%*sSerial Number: \n", indent, "");

        const BIGNUM *bn = ASN1_INTEGER_to_BN(dcd->serialNumber, NULL);
        if (bn != NULL) {
            unsigned char *buf = NULL;
            int len = BN_num_bytes(bn);

            buf = OPENSSL_malloc(len);
            if (buf != NULL) {
                BN_bn2bin(bn, buf);
                BIO_printf(out, "%*s", indent + 4, "");
                for (int i = 0; i < len; i++) {
                    BIO_printf(out, "%02x", buf[i]);
                    if (i < len - 1)
                        BIO_printf(out, ":");
                }
                BIO_printf(out, "\n");
                OPENSSL_free(buf);
            }
            BN_free((BIGNUM *)bn);
        } else {
            BIO_printf(out, "%*s<invalid serial number>\n", indent + 4, "");
        }
    }

    if (dcd->signature) {
        BIO_printf(out, "%*sSignature Algorithm: ", indent, "");
        if (i2a_ASN1_OBJECT(out, dcd->signature->algorithm) <= 0)
            goto err;
        BIO_printf(out, "\n");
    }


    if (dcd->issuer) {
        BIO_printf(out, "%*sIssuer: ", indent, "");
        if (X509_NAME_print_ex(out, dcd->issuer, 0, XN_FLAG_ONELINE) <= 0)
            goto err;
        BIO_printf(out, "\n");
    }

    if (dcd->validity) {
        BIO_printf(out, "%*sValidity:\n", indent, "");
        if (dcd->validity->notBefore) {
            BIO_printf(out, "%*sNot Before: ", indent + 4, "");
            ASN1_TIME_print(out, dcd->validity->notBefore);
            BIO_printf(out, "\n");
        }
        if (dcd->validity->notAfter) {
            BIO_printf(out, "%*sNot After: ", indent + 4, "");
            ASN1_TIME_print(out, dcd->validity->notAfter);
            BIO_printf(out, "\n");
        }
    }

    if (dcd->subject) {
        BIO_printf(out, "%*sSubject: ", indent, "");
        if (X509_NAME_print_ex(out, dcd->subject, 0, XN_FLAG_ONELINE) <= 0)
            goto err;
        BIO_printf(out, "\n");
    }

    if (dcd->SubjectPublicKeyInfo) {
        BIO_printf(out, "%*sSubject Public Key Info:\n", indent, "");
        {
            ASN1_OBJECT *xpoid = NULL;
            X509_PUBKEY_get0_param(&xpoid, NULL, NULL, NULL, dcd->SubjectPublicKeyInfo);
            BIO_printf(out, "%*sPublic Key Algorithm: ", indent + 4, "");
            if (i2a_ASN1_OBJECT(out, xpoid) <= 0)
                goto err;
            BIO_printf(out, "\n");
        
            EVP_PKEY *pkey = X509_PUBKEY_get0(dcd->SubjectPublicKeyInfo);
            if (pkey == NULL) {
                BIO_printf(out, "%*sUnable to load Public Key\n", indent + 4, "");
            } else {
                EVP_PKEY_print_public(out, pkey, indent + 8, NULL);
            }
        }
    }

    if (dcd->extensions && sk_X509_EXTENSION_num(dcd->extensions) > 0) {
        BIO_printf(out, "%*sX509v3 extensions:\n", indent, "");
    
        for (int i = 0; i < sk_X509_EXTENSION_num(dcd->extensions); i++) {
            X509_EXTENSION *ext = sk_X509_EXTENSION_value(dcd->extensions, i);
            ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
    
            const X509V3_EXT_METHOD *method = X509V3_EXT_get(ext);
            void *ext_str = X509V3_EXT_d2i(ext);
    
            BIO_printf(out, "%*s", indent + 4, "");
            i2a_ASN1_OBJECT(out, obj);
    
            if (X509_EXTENSION_get_critical(ext))
                BIO_printf(out, ": critical\n");
            else
                BIO_printf(out, ":\n");
    
            if (method && ext_str) {
                if (method->i2r) {
                    BIO_printf(out, "%*s", indent + 8, "");
                    method->i2r(method, ext_str, out, indent + 8);
                } else {
                    BIO_printf(out, "%*s", indent + 8, "");
                    X509V3_EXT_print(out, ext, 0, 0);
                }
            } else {
                BIO_printf(out, "%*sUnable to decode or unrecognized extension\n", indent + 8, "");
            }
            BIO_printf(out, "\n");
        }
    }

    if (dcd->signatureValue) {
        BIO_printf(out, "%*sSignature Value:\n", indent, "");
        for (int i = 0; i < dcd->signatureValue->length; i++) {
            if (i % 19 == 0)
                BIO_printf(out, "%*s", indent + 4, "");
            BIO_printf(out, "%02x", dcd->signatureValue->data[i]);
            if (i < dcd->signatureValue->length - 1)
                BIO_printf(out, ":");
            if ((i + 1) % 19 == 0)
                BIO_printf(out, "\n");
            
        }
    }

    ret = 1;
err:
    return ret;
}



X509_ALGOR *copy_sigalg_from_cert(X509 *cert) {
    const X509_ALGOR *alg = NULL;
    X509_ALGOR *copy = NULL;

    alg = X509_get0_tbs_sigalg(cert);

    if(!alg) {
        fprintf(stderr, "No signature algorithm found\n");
        return NULL;
    }

    copy = X509_ALGOR_dup(alg);
    if (!copy) {
        fprintf(stderr, "Failed to copy signature algorithm\n");
        return NULL;
    }

    return copy;
}

DeltaValidity *copy_validity_from_cert(X509 *cert) {
    const ASN1_TIME *nb = X509_get0_notBefore(cert);
    const ASN1_TIME *na = X509_get0_notAfter(cert);

    DeltaValidity *val = DeltaValidity_new();
    if (!val) {
        fprintf(stderr, "Failed to allocate memory for validity\n");
        return NULL;
    }

    val->notBefore = ASN1_TIME_dup(nb);
    val->notAfter = ASN1_TIME_dup(na);

    if (!val->notBefore || !val->notAfter) {
        ASN1_TIME_free(val->notBefore);
        ASN1_TIME_free(val->notAfter);
        DeltaValidity_free(val);
        return NULL;
    }

    return val;
}

STACK_OF(X509_EXTENSION) *copy_extensions_except_delta(X509 *cert) {
    int delta_ext_nid = NID_id_ce_deltaCertificateDescriptor;

    const STACK_OF(X509_EXTENSION) *orig_exts = X509_get0_extensions(cert);
    if (!orig_exts) return NULL;

    STACK_OF(X509_EXTENSION) *copy_exts = sk_X509_EXTENSION_new_null();
    if (!copy_exts) return NULL;

    for (int i = 0; i < sk_X509_EXTENSION_num(orig_exts); i++) {
        X509_EXTENSION *ext = sk_X509_EXTENSION_value(orig_exts, i);
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);

        if (OBJ_obj2nid(obj) == delta_ext_nid) continue;

        X509_EXTENSION *ext_dup = X509_EXTENSION_dup(ext);
        
        if (!ext_dup) {
            for (int j = 0; j < sk_X509_EXTENSION_num(copy_exts); j++)
                X509_EXTENSION_free(sk_X509_EXTENSION_value(copy_exts, j));
            sk_X509_EXTENSION_free(copy_exts);
            return NULL;
        }

        sk_X509_EXTENSION_push(copy_exts, ext_dup);
    }

    return copy_exts;
}

STACK_OF(X509_EXTENSION) *copy_extensions_from_dcd(DeltaCertificateDescriptor *dcd) {
    const STACK_OF(X509_EXTENSION) *orig_exts = dcd->extensions;
    if (!orig_exts) return NULL;

    STACK_OF(X509_EXTENSION) *copy_exts = sk_X509_EXTENSION_new_null();
    if (!copy_exts) return NULL;

    for (int i = 0; i < sk_X509_EXTENSION_num(orig_exts); i++) {
        X509_EXTENSION *ext = sk_X509_EXTENSION_value(orig_exts, i);
        X509_EXTENSION *ext_dup = X509_EXTENSION_dup(ext);
        
        if (!ext_dup) {
            for (int j = 0; j < sk_X509_EXTENSION_num(copy_exts); j++)
                X509_EXTENSION_free(sk_X509_EXTENSION_value(copy_exts, j));
            sk_X509_EXTENSION_free(copy_exts);
            return NULL;
        }

        sk_X509_EXTENSION_push(copy_exts, ext_dup);
    }

    return copy_exts;
}

X509 *reconstruct_delta(X509 *base, DeltaCertificateDescriptor *dcd) {
    X509 *delta = X509_dup(base);
    int idx = X509_get_ext_by_NID(delta, NID_id_ce_deltaCertificateDescriptor, -1);

    if (idx >= 0)
        X509_delete_ext(delta, idx);

    if (dcd->serialNumber) {
        ASN1_INTEGER *sn_dup = ASN1_INTEGER_dup(dcd->serialNumber);
        if (!X509_set_serialNumber(delta, sn_dup)) {
            fprintf(stderr, "Failed to set serialNumber\n");
            ASN1_INTEGER_free(sn_dup);
            return NULL;
        }
    }
    
    if (dcd->signature) {
        if(!X509_ALGOR_copy(&delta->cert_info.signature, dcd->signature)) {
            fprintf(stderr, "Failed to copy signature to tbs\n");
            return NULL;
        }

        if (!X509_ALGOR_copy(&delta->sig_alg, dcd->signature)) {
            fprintf(stderr, "Failed to copy signature to outer\n");
            return NULL;
        }
    }
    

    if (dcd->issuer) {
        if (!X509_set_issuer_name(delta, dcd->issuer)) {
            fprintf(stderr, "Failed to copy issuer name\n");
            return NULL;
        }
    }

    if (dcd->validity) {
        if (!X509_set1_notAfter(delta, dcd->validity->notAfter) ||
            !X509_set1_notBefore(delta, dcd->validity->notBefore)) {
                fprintf(stderr, "Failed to copy validity\n");
                return NULL;
            }
    }

    if (dcd->subject) {
        if (!X509_set_subject_name(delta, dcd->subject)) {
            fprintf(stderr, "Failed to copy subject name\n");
            return NULL;
        }
    }

    if (dcd->SubjectPublicKeyInfo) {
        EVP_PKEY *pk = X509_PUBKEY_get0(dcd->SubjectPublicKeyInfo);
        if(!X509_set_pubkey(delta, pk)) {
            fprintf(stderr, "Failed to copy SubjectPublicKeyInfo\n");
            EVP_PKEY_free(pk);
            return NULL;
        }
        EVP_PKEY_free(pk);
    }

    while (X509_get_ext_count(delta) > 0) {
        X509_delete_ext(delta, 0);
    }
    
    if (dcd->extensions) {
        for (int i = 0; i < sk_X509_EXTENSION_num(dcd->extensions); ++i) {
            X509_EXTENSION *dup = X509_EXTENSION_dup(sk_X509_EXTENSION_value(dcd->extensions, i));
            if (!dup || !X509_add_ext(delta, dup, -1)) {
                X509_EXTENSION_free(dup);
                return NULL;
            }
            X509_EXTENSION_free(dup);
        }
    }

    if (dcd->signatureValue && !ASN1_STRING_copy(&delta->signature, dcd->signatureValue)) {
        fprintf(stderr, "Failed to copy signatureValue\n");
    }

    delta->cert_info.enc.modified = 1;

    return delta;

}

int verify_dcd_signature(X509 *cert) {
    int ok = 0;
    int crit = -1;
    DeltaCertificateDescriptor *dcd = X509_get_ext_d2i(cert, NID_id_ce_deltaCertificateDescriptor, &crit, NULL);
    if (!dcd || !dcd->SubjectPublicKeyInfo) {
        fprintf(stderr, "No DeltaCertificateDescriptor or missing public key\n");
        return 0;
    }

    X509 *delta = reconstruct_delta(cert, dcd);
    if (!delta) goto end;
    
    EVP_PKEY *capub = X509_get_pubkey(delta);
    ok = X509_verify(delta, capub);
end:
    X509_free(delta);
    DeltaCertificateDescriptor_free(dcd);
    return ok;
}