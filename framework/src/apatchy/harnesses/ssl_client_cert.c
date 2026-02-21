/*
 * @description: X509 client certificate parsing - DER/PEM input through mod_ssl/OpenSSL paths
 *
 * Fuzzes the certificate processing code that mod_ssl uses when handling
 * client certificates:  DER/ASN.1 parsing (d2i_X509), Subject Alternative
 * Name extraction, Distinguished Name formatting, Basic Constraints,
 * hostname matching, extension enumeration, serial/validity/version
 * extraction, PEM round-tripping, and chain verification.
 *
 * Does NOT require the Apache pipeline - only APR pools and OpenSSL.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* APR */
#include "apr_general.h"
#include "apr_pools.h"
#include "apr_tables.h"

/* OpenSSL (also pulled in by ssl_util_ssl.h, but kept explicit) */
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

/* mod_ssl types needed by ssl_util_ssl.h */
#ifndef BOOL
#define BOOL unsigned int
#endif
#ifndef TRUE
#define TRUE  1
#endif
#ifndef FALSE
#define FALSE 0
#endif
typedef struct server_rec server_rec;
#ifndef IDCONST
#define IDCONST const
#endif

/* mod_ssl utility functions - non-static, linked from libmod_ssl.la */
#include "ssl_util_ssl.h"

/* ----------------------------------------------------------------
 * Core fuzzing logic
 * ---------------------------------------------------------------- */

static apr_pool_t *g_root_pool = NULL;

static void fuzz_init_once(void)
{
    static int done = 0;
    if (done) return;

    apr_initialize();
    apr_pool_create(&g_root_pool, NULL);

    /* OpenSSL >= 1.1 auto-initialises; call explicitly for older builds */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    OpenSSL_add_all_algorithms();
#endif

    done = 1;
}

static void exercise_cert(apr_pool_t *pool, X509 *cert)
{
    /* --- Subject / Issuer DN ------------------------------------------ */
    X509_NAME *subject = X509_get_subject_name(cert);
    X509_NAME *issuer  = X509_get_issuer_name(cert);

    if (subject) {
        /* mod_ssl calls X509_NAME_oneline in ssl_var_lookup_ssl_cert */
        char *s = X509_NAME_oneline(subject, NULL, 0);
        OPENSSL_free(s);

        /* mod_ssl's modssl_X509_NAME_to_string (richer formatting) */
        char *name_str = modssl_X509_NAME_to_string(pool, subject, 0);
        (void)name_str;

        /* Iterate individual RDN entries - mirrors ssl_var_lookup_ssl_cert_dn */
        int n = X509_NAME_entry_count(subject);
        for (int i = 0; i < n && i < 64; i++) {
            X509_NAME_ENTRY *entry = X509_NAME_get_entry(subject, i);
            char *entry_str = modssl_X509_NAME_ENTRY_to_string(pool, entry, 0);
            (void)entry_str;
        }
    }
    if (issuer) {
        char *s = X509_NAME_oneline(issuer, NULL, 0);
        OPENSSL_free(s);
        char *name_str = modssl_X509_NAME_to_string(pool, issuer, 0);
        (void)name_str;
    }

    /* --- Serial number ------------------------------------------------ */
    ASN1_INTEGER *serial = X509_get_serialNumber(cert);
    if (serial) {
        BIO *bio = BIO_new(BIO_s_mem());
        if (bio) {
            i2a_ASN1_INTEGER(bio, serial);
            char *tmp = modssl_bio_free_read(pool, bio);
            (void)tmp;
            /* bio freed by modssl_bio_free_read */
        }
    }

    /* --- Validity dates ----------------------------------------------- */
    (void)X509_get_notBefore(cert);
    (void)X509_get_notAfter(cert);

    /* --- Version ------------------------------------------------------ */
    (void)X509_get_version(cert);

    /* --- Signature algorithm ------------------------------------------ */
    const ASN1_OBJECT *sig_obj = NULL;
    X509_ALGOR_get0(&sig_obj, NULL, NULL, X509_get0_tbs_sigalg(cert));

    /* --- Public key algorithm ----------------------------------------- */
    const ASN1_OBJECT *pk_obj = NULL;
    X509_PUBKEY_get0_param((ASN1_OBJECT **)&pk_obj, NULL, 0, NULL,
                           X509_get_X509_PUBKEY(cert));

    /* --- Extensions --------------------------------------------------- */
    int ext_count = X509_get_ext_count(cert);
    for (int i = 0; i < ext_count && i < 128; i++) {
        X509_EXTENSION *ext = X509_get_ext(cert, i);
        BIO *bio = BIO_new(BIO_s_mem());
        if (bio) {
            X509V3_EXT_print(bio, ext, 0, 0);
            BIO_free(bio);
        }
    }

    /* --- Subject Alternative Names (mod_ssl specific) ----------------- */
    apr_array_header_t *entries = NULL;

    modssl_X509_getSAN(pool, cert, GEN_EMAIL, NULL, -1, &entries);
    entries = NULL;
    modssl_X509_getSAN(pool, cert, GEN_DNS,   NULL, -1, &entries);
    entries = NULL;
    modssl_X509_getSAN(pool, cert, GEN_URI,   NULL, -1, &entries);

    /* otherName with known OID strings used by mod_ssl */
    entries = NULL;
    modssl_X509_getSAN(pool, cert, GEN_OTHERNAME, "msUPN", -1, &entries);
    entries = NULL;
    modssl_X509_getSAN(pool, cert, GEN_OTHERNAME, "id-on-dnsSRV", -1, &entries);

    /* --- Basic Constraints (mod_ssl specific) ------------------------- */
    int ca = 0, pathlen = 0;
    modssl_X509_getBC(cert, &ca, &pathlen);

    /* --- Hostname matching (mod_ssl specific) ------------------------- */
    modssl_X509_match_name(pool, cert, "localhost", TRUE, NULL);
    modssl_X509_match_name(pool, cert, "*.example.com", TRUE, NULL);
    modssl_X509_match_name(pool, cert, "test.example.org", FALSE, NULL);

    /* --- PEM round-trip (exercises i2d / DER re-encoding) ------------- */
    const char *pem_out = NULL;
    modssl_cert_get_pem(pool, cert, NULL, &pem_out);

    /* --- Certificate chain verification ------------------------------- */
    X509_STORE *store = X509_STORE_new();
    if (store) {
        X509_STORE_CTX *store_ctx = X509_STORE_CTX_new();
        if (store_ctx) {
            if (X509_STORE_CTX_init(store_ctx, store, cert, NULL)) {
                X509_verify_cert(store_ctx);
            }
            X509_STORE_CTX_free(store_ctx);
        }
        X509_STORE_free(store);
    }
}

static int fuzz_one_cert(const uint8_t *data, size_t size)
{
    if (size == 0 || size > 65536) return 0;

    apr_pool_t *pool;
    apr_pool_create(&pool, g_root_pool);

    /* Try DER first (most common binary format) */
    const unsigned char *p = data;
    X509 *cert = d2i_X509(NULL, &p, (long)size);

    /* Fall back to PEM */
    if (!cert) {
        BIO *bio = BIO_new_mem_buf(data, (int)size);
        if (bio) {
            cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
            BIO_free(bio);
        }
    }

    if (cert) {
        exercise_cert(pool, cert);
        X509_free(cert);
    }

    apr_pool_destroy(pool);
    ERR_clear_error();
    return 0;
}

/* ----------------------------------------------------------------
 * Entry points
 * ---------------------------------------------------------------- */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fuzz_init_once();
    return fuzz_one_cert(data, size);
}

/*
 * main() for AFL and standalone modes.
 * When linking against Apache's libmain.a, this main() coexists via
 * -z muldefs.  Our object file main() wins over the archive's.
 */
#ifndef LIBFUZZER_MODE

int main(int argc, char **argv)
{
    fuzz_init_once();

    uint8_t buf[1024 * 64]; /* 64 KB max input */

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
    while (__AFL_LOOP(10000)) {
        ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
        if (n > 0) {
            fuzz_one_cert(buf, (size_t)n);
        }
    }
#else
    /* Standalone / non-persistent AFL: read stdin once and exit */
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
    if (n > 0) {
        fuzz_one_cert(buf, (size_t)n);
    }
#endif

    return 0;
}

#endif /* LIBFUZZER_MODE */
