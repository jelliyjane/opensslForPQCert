#include <openssl/x509v3.h>
#include <openssl/asn1t.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <string.h>

#include <crypto/x509.h>
#include <stdbool.h>


ASN1_BIT_STRING* create_dummy_extension(EVP_PKEY* key);
static void *v2i_altAlg(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *values);
static int i2r_altAlg(const X509V3_EXT_METHOD *method, void *ext, BIO *out, int indent);

const X509V3_EXT_METHOD ossl_v3_alt_sig_alg = {
    NID_alt_signature_algorithm,        /* .ext_nid = */
    0,                      /* .ext_flags = */
    ASN1_ITEM_ref(X509_ALGOR), /* .it = */
    0, 0, 0, 0,
    0,                   /* .i2s = */
    0,                   /* .s2i = */
    NULL,                   /* .i2v = */
    v2i_altAlg,          /* .v2i = */
    i2r_altAlg,         /* .i2r = */
    NULL,                   /* .r2i = */
    NULL                    /* extension-specific data */
};


static void *v2i_altAlg(const X509V3_EXT_METHOD *method,
                        X509V3_CTX *ctx,
                        STACK_OF(CONF_VALUE) *values)
{
    if (sk_CONF_VALUE_num(values) != 1) {
        printf("[altSigAlg] error: only one algorithm OID must be specified.\n");
        return NULL;
    }

    CONF_VALUE *val = sk_CONF_VALUE_value(values, 0);
    //printf("name: %s, value: %s\n", val->name, val->value);
    /*if (!val || !val->value) {
        printf("[altSigAlg] error: missing or invalid config value.\n");
        return NULL;
    }*/

    ASN1_OBJECT *obj = OBJ_txt2obj(val->name, 0);
    if (!obj) {
        printf("[altSigAlg] error: invalid OID value: %s\n", val->value);
        return NULL;
    }

    X509_ALGOR *alg = X509_ALGOR_new();
    if (!alg) {
        printf("[altSigAlg] error: memory allocation failed for X509_ALGOR.\n");
        ASN1_OBJECT_free(obj);
        return NULL;
    }

    X509_ALGOR_set0(alg, obj, V_ASN1_UNDEF, NULL);  // no parameters

    return alg;
}

static int i2r_altAlg(const X509V3_EXT_METHOD *method,
                      void *ext,
                      BIO *out,
                      int indent)
{
    X509_ALGOR *alg = (X509_ALGOR *)ext;

    if (!alg || !alg->algorithm) {
        BIO_printf(out, "%*s[altSigAlg] error: missing algorithm identifier\n", indent, "");
        return 0;
    }

    int nid = OBJ_obj2nid(alg->algorithm);
    if (nid != NID_undef) {
        BIO_printf(out, "%*saltSigAlg: %s\n", indent, "", OBJ_nid2ln(nid));
    } else {
        char objbuf[80];
        OBJ_obj2txt(objbuf, sizeof(objbuf), alg->algorithm, 1);
        BIO_printf(out, "%s\n", indent, "", objbuf);
    }

    return 1;
}

static void *v2i_altSig(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *values);
static int i2r_altSig(const X509V3_EXT_METHOD *method, void *ext_value, BIO *out, int indent);
static int ALT_SIGNATURE_verify(X509* x, EVP_PKEY* public_key);

const X509V3_EXT_METHOD ossl_v3_alt_sig_val = {
    NID_alt_signature_value,        /* .ext_nid = */
    0,                      /* .ext_flags = */
    ASN1_ITEM_ref(ASN1_BIT_STRING), /* .it = */
    0, 0, 0, 0,
    0,                   /* .i2s = */
    0,                   /* .s2i = */
    NULL,                   /* .i2v = */
    v2i_altSig,          /* .v2i = */
    i2r_altSig,         /* .i2r = */
    NULL,                   /* .r2i = */
    NULL                    /* extension-specific data */
};

static void *v2i_altSig(const X509V3_EXT_METHOD *method,
                        X509V3_CTX *ctx,
                        STACK_OF(CONF_VALUE) *values)
{
    //printf("[altSig] \n");
    ASN1_BIT_STRING* altsig = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *keybio = NULL;
    unsigned char *tbs = NULL;
    int tbslen = 0;

    if (sk_CONF_VALUE_num(values) != 1)
        return NULL;

    CONF_VALUE *val = sk_CONF_VALUE_value(values, 0);
    if (strncmp("file", val->name, 4)) {
        printf("[altSig] Value for alt_sig_val must start with 'file:'\n");
        return NULL;
    }

    keybio = BIO_new_file(val->value, "rb");
    if (!keybio){ 
        printf("[altSig] Failed to make alternative private key file\n");
        return NULL;
    }

    pkey = PEM_read_bio_PrivateKey(keybio, NULL, NULL, NULL);
    BIO_free(keybio);
    if (!pkey){ 
        printf("[altSig] Failed to open alternative private key file\n");
        return NULL;
    }


    if((altsig = create_dummy_extension(pkey))==NULL) {
        printf("[altsig] create_dummy_extension error\n");
        return NULL;
    }

    if (ctx->flags & CTX_TEST) {
        return altsig;
    }
 
   ctx->subject_cert->alt_sig_private_key = pkey;
   return altsig;


}

static int i2r_altSig(const X509V3_EXT_METHOD *method, void *ext_value,
                      BIO *out, int indent)
{
    ASN1_BIT_STRING *bs = (ASN1_BIT_STRING *)ext_value;
    if (!bs || !bs->data)
        return 0;

    BIO_printf(out, "%*s", indent, "");
    BIO_printf(out, "altSignatureValue: ");

    for (int i = 0; i < bs->length; i++) {
        BIO_printf(out, "%02X", bs->data[i]);
        if (i < bs->length - 1)
            BIO_printf(out, ":");
    }

    BIO_printf(out, "\n");
    return 1;
}

ASN1_BIT_STRING* create_dummy_extension(EVP_PKEY* key) {
    printf("[create dummy]\n");
    ASN1_BIT_STRING* hs;
    int signatureLength;

    hs = ASN1_BIT_STRING_new();

    signatureLength = EVP_PKEY_size(key);
    printf("signatureLength: %d\n",signatureLength);
    if(hs->data){
        OPENSSL_free(hs->data);
    }
    printf("key type: %s\n", OBJ_nid2sn(EVP_PKEY_base_id(key)));

    if ((hs->data = OPENSSL_zalloc(signatureLength)) == NULL) {
        printf("create_dummy_extension error\n");
        return NULL;
    }
    hs->length = signatureLength;
    hs->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    hs->flags |= ASN1_STRING_FLAG_BITS_LEFT;

    return hs;

}

void ALT_SIGNATURE_sign(X509* x) {
    int i;
    X509_EXTENSION* ext;
    ASN1_OCTET_STRING *ext_oct = NULL;
    EVP_PKEY* private_key;
    ASN1_BIT_STRING* altsig;
    int ext_len;
    unsigned char *ext_der = NULL;
    if ((i = X509_get_ext_by_NID(x, NID_alt_signature_value, -1)) < 0) {
        // No extension to be signed
        return;
    }
    if ((ext = X509_get_ext(x, i)) == NULL) {
        printf("[ALT_SIGN] no extension\n");
        return;
    }
    if ((private_key = x->alt_sig_private_key) == NULL) {
        printf("[ALT_SIGN] no private_key\n");
        return;
    }
    if ((altsig = create_dummy_extension(private_key)) == NULL) {
        // Error set by createDummyExtension, so we do not need to set any.
        return;
    }
    if (ASN1_item_sign(ASN1_ITEM_rptr(X509_CINF), NULL,
                                   NULL, altsig, &x->cert_info, private_key,
                                   NULL) == 0) {
        printf("[ALT_SIGN] sign failure\n");
        return;
    }
    ext_der = NULL;
    ext_len = ASN1_item_i2d((void*)altsig, &ext_der, ASN1_ITEM_rptr(ASN1_BIT_STRING));
    if (ext_len < 0) {
        printf("[ALT_SIGN] sign failure\n");
        return;
    }
    if ((ext_oct = ASN1_OCTET_STRING_new()) == NULL) {
        printf("[ALT_SIGN] sign failure\n");
        return;
    }
    ext_oct->data = ext_der;
    ext_oct->length = ext_len;
    if (X509_EXTENSION_set_data(ext, ext_oct) != 1) {
        printf("[ALT_SIGN] sign failure\n");
    }
    x->cert_info.enc.modified = 1;
}

static int ALT_SIGNATURE_verify(X509* x, EVP_PKEY* public_key) {
    printf("[ALT_verify] start\n");
    int i;
    X509_EXTENSION* ext;
    X509_EXTENSION* ext_alg;
    ASN1_OCTET_STRING *extoct;
    ASN1_BIT_STRING* dummy = NULL;
    int ext_len;
    unsigned char *ext_der = NULL;
    ASN1_BIT_STRING *altsig = NULL;
    X509_ALGOR* altalg = NULL;
    ASN1_OCTET_STRING* ext_oct;
    ASN1_BIT_STRING* signature;

    // get the alternative signature value extension
    if ((i = X509_get_ext_by_NID(x, NID_alt_signature_value, -1)) < 0) {
        printf("[ALT_verify] no alt sig val extension\n");
        return 0;
    }
    if ((ext = X509_get_ext(x, i)) == NULL) {
        printf("[ALT_verify] no alt sig val extension\n");
        return 0;
    }
    extoct = ASN1_OCTET_STRING_dup(X509_EXTENSION_get_data(ext));
    if ((altsig = X509V3_EXT_d2i(ext)) == NULL) {
        printf("[ALT_verify] alt sig val parsing failure\n");
        return 0;
    }
    printf("[ALT_verify] extract altsig\n");
    signature = ASN1_STRING_dup(altsig);
 // get the alternative signature algorithm extension
    if ((i = X509_get_ext_by_NID(x, NID_alt_signature_algorithm, -1)) < 0) {
        printf("[ALT_verify] no alt sig alg extension\n");
        return 0;
    }
    if ((ext_alg = X509_get_ext(x, i)) == NULL) {
        printf("[ALT_verify] no alt sig alg extension\n");
        return 0;
    }
    if ((altalg = X509V3_EXT_d2i(ext_alg)) == NULL) {
    printf("[ALT_verify] alt sig alg parsing failure\n");
    return 0;
    }

    printf("[ALT_verify] extract altalg\n");


    //create a dummy extension for verification (contains all 0's as the signature string)
    if ((dummy = create_dummy_extension(public_key)) == NULL) {
        // Error set by createDummyExtension, so we do not need to set any.
        return 0;
    }

    printf("[ALT_verify] generte dummy extension\n");

    ext_len = ASN1_item_i2d((void*)dummy, &ext_der, ASN1_ITEM_rptr(ASN1_BIT_STRING));
    if (ext_len < 0) {
        printf("[ALT_verify] alt sig parsing failure\n");
        return 0;
    }
    if ((ext_oct = ASN1_OCTET_STRING_new()) == NULL) {
        printf("[ALT_verify] alt sig malloc failure\n");
        return 0;
    }
    ext_oct->data = ext_der;
    ext_oct->length = ext_len;
    printf("[ALT_verify] ext_len: %d\n ", ext_len);
    //replace the extension data with the dummy extension data
    if (X509_EXTENSION_set_data(ext, ext_oct) != 1) {
        printf("[ALT_verify] replace dummy extension failure\n");
        return 0;
    }
    x->cert_info.enc.modified = 1;

    //verify the alternative signature
    if (ASN1_item_verify(ASN1_ITEM_rptr(X509_CINF), altalg, signature, &x->cert_info, public_key) != 1) {
        printf("[ALT_verify] alt sig verification failure\n");
        //restore the extension to its original state for further verification
        X509_EXTENSION_set_data(ext, extoct);
        return 0;
    }

    //restore the extension to its original state for further verification
    X509_EXTENSION_set_data(ext, extoct);
    x->cert_info.enc.modified = 1;

    return 1;
}

static int alt_sig_validate_path_internal(X509_STORE_CTX *ctx,
                                             STACK_OF(X509) *chain) {
    printf("alt_sig_validate_path_internal\n");
    EVP_PKEY* public_key = NULL;
    int i;
    X509 *x;
    bool need_pubkey = false; // if one certificate has a alternative key, all others upwards in the chain need one as well

    i = 0;
    x = sk_X509_value(chain, i);

    /*
     * Walk up the chain. Verify each alternative signature with the alternative key of the parent.
     */
    for (; i < sk_X509_num(chain) - 1; i++) {
        X509* parent = sk_X509_value(chain, i + 1);
        public_key = X509_get_alt_pubkey(parent);
        if (!public_key) {
            if (need_pubkey) {
                ctx->error = X509_V_ERR_ALT_SIG_VERIFY_FAIL;
                ctx->error_depth = i;
                ctx->current_cert = x;
                if (ctx->verify_cb(0, ctx) == 0)
                    return 0;
            }
            // we do not have a alternative key, but we do not need one. Continue checking the chain
            continue;
        }
        else {
            // this certificate has a alternative public key -> all parent certificates need to have one as well
            need_pubkey = true;
        }
        if (ALT_SIGNATURE_verify(x, public_key) == 0) {
            ctx->error = X509_V_ERR_ALT_SIG_VERIFY_FAIL;
            ctx->error_depth = i;
            ctx->current_cert = x;
            if (ctx->verify_cb(0, ctx) == 0)
                return 0;
        }
        x = parent;
    }

    // Check self signed alternative signature of the root certificate.
    public_key = X509_get_alt_pubkey(x);
    printf("EVP_PKEY bits: %d\n", EVP_PKEY_bits(public_key));
    printf("EVP_PKEY size: %d\n", EVP_PKEY_size(public_key));

    if (!public_key) {
        if (need_pubkey) {
            ctx->error = X509_V_ERR_ALT_SIG_VERIFY_FAIL;
            ctx->error_depth = i;
            ctx->current_cert = x;
            if (ctx->verify_cb(0, ctx) == 0)
                return 0;
        }
        return 1; // we do not need a alternative key -> all is good :)
    }
    return ALT_SIGNATURE_verify(x, public_key);
}

/*
 * Verify a the alternative signatures for a certificate chain.
 */
int X509v3_alt_sig_validate_path(X509_STORE_CTX *ctx) {
    printf("X509v3_alt_sig_validate_path\n");
    if (ctx->chain == NULL
            || sk_X509_num(ctx->chain) == 0
            || ctx->verify_cb == NULL) {
        ctx->error = X509_V_ERR_UNSPECIFIED;
        return 0;
    }
    return alt_sig_validate_path_internal(ctx, ctx->chain);
}