#define _POSIX_C_SOURCE 200809L
#include "../src/security/oidc.h"
#include "../src/security/oidc_json.h"
#include <openssl/evp.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static const char *fault = "";
static unsigned allocation;
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__wrap_malloc(size_t n) {
    if (!strncmp(fault, "alloc-", 6) && ++allocation == strtoul(fault + 6, NULL, 10)) return NULL;
    return __real_malloc(n);
}
void *__wrap_calloc(size_t n, size_t s) {
    if (!strncmp(fault, "alloc-", 6) && ++allocation == strtoul(fault + 6, NULL, 10)) return NULL;
    return __real_calloc(n, s);
}
EVP_MD_CTX *__real_EVP_MD_CTX_new(void);
EVP_MD_CTX *__wrap_EVP_MD_CTX_new(void) {
    return !strcmp(fault, "context") ? NULL : __real_EVP_MD_CTX_new();
}
int __real_EVP_DigestVerifyInit_ex(EVP_MD_CTX *, EVP_PKEY_CTX **,
    const char *, OSSL_LIB_CTX *, const char *, EVP_PKEY *, const OSSL_PARAM *);
int __wrap_EVP_DigestVerifyInit_ex(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
    const char *md, OSSL_LIB_CTX *lib, const char *properties, EVP_PKEY *key,
    const OSSL_PARAM *params) {
    if (!strcmp(fault, "init")) return 0;
    return __real_EVP_DigestVerifyInit_ex(ctx, pctx, md, lib, properties, key, params);
}
int __real_EVP_DigestVerify(EVP_MD_CTX *, const unsigned char *, size_t,
    const unsigned char *, size_t);
int __wrap_EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *signature,
    size_t length, const unsigned char *data, size_t size) {
    if (!strcmp(fault, "verify-error")) return -1;
    if (!strcmp(fault, "verify-invalid")) return 0;
    return __real_EVP_DigestVerify(ctx, signature, length, data, size);
}
static unsigned char *file(const char *path, size_t *length) {
    FILE *f = fopen(path, "rb");
    if (!f || fseek(f, 0, SEEK_END)) exit(70);
    long size = ftell(f);
    if (size < 0 || size > 131072 || fseek(f, 0, SEEK_SET)) exit(70);
    unsigned char *text = malloc((size_t)size + 1);
    if (!text || fread(text, 1, (size_t)size, f) != (size_t)size || fclose(f)) exit(70);
    text[size] = 0; *length = (size_t)size; return text;
}
static void hex(const char *text) {
    if (!*text) { putchar('-'); return; }
    while (*text) printf("%02x", (unsigned char)*text++);
}
typedef struct { const YDOIDC *oidc; const char *jwt; size_t length; int64_t now; int ok; } Job;
static void *thread(void *argument) {
    Job *j = argument;
    j->ok = 1;
    for (unsigned i = 0; i < 64; i++) {
        YDOIDCIdentity identity;
        if (yd_oidc_verify(j->oidc, j->jwt, j->length, j->now, &identity) != YD_OIDC_VALID ||
            strcmp(identity.subject, "service-1") || strcmp(identity.client_id, "client-1"))
            j->ok = 0;
    }
    return NULL;
}
int main(int argc, char **argv) {
    if (argc < 4) return 64;
    size_t size = 0;
    unsigned char *bytes = file(argv[2], &size);
    if (!strcmp(argv[1], "json")) {
        YDOIDCJSON *doc = NULL;
        int status = yd_oidc_json_parse(bytes, size, strtoul(argv[3], NULL, 10), &doc);
        printf("JSON %d %d\n", status, doc == NULL);
        yd_oidc_json_free(doc); free(bytes); return 0;
    }
    if (argc < 5) return 64;
    char issuer[514] = "https://issuer.example/tenant";
    char audience[258] = "urn:yamora:test";
    char scope[130] = "yamora.access";
    if (argc > 6) snprintf(issuer, sizeof(issuer), "%s", argv[6]);
    if (argc > 7) snprintf(audience, sizeof(audience), "%s", argv[7]);
    if (argc > 8) snprintf(scope, sizeof(scope), "%s", argv[8]);
    YDOIDCOptions options = {issuer, audience, scope, 30, 900};
    if (argc > 9) options.clock_skew_seconds = (unsigned)strtoul(argv[9], NULL, 10);
    if (argc > 10) options.max_token_lifetime_seconds = (unsigned)strtoul(argv[10], NULL, 10);
    if (argc > 5 && !strcmp(argv[1], "load")) fault = argv[5];
    char error[64];
    memset(error, 0xA5, sizeof(error));
    YDOIDC *oidc = yd_oidc_new(&options, bytes, size, error, sizeof(error));
    if (!oidc) { puts("LOAD_INVALID"); free(bytes); return 0; }
    if (!strcmp(argv[1], "load")) {
        puts("LOAD_OK"); yd_oidc_free(oidc); yd_oidc_free(NULL); free(bytes); return 0;
    }
    size_t length = 0;
    unsigned char *jwt = file(argv[3], &length);
    int64_t now = strtoll(argv[4], NULL, 10);
    fault = argc > 5 ? argv[5] : "";
    if (!strcmp(fault, "ownership")) {
        memset(bytes, 'x', size);
        memset(issuer, 'x', sizeof(issuer) - 1);
        memset(audience, 'x', sizeof(audience) - 1);
        memset(scope, 'x', sizeof(scope) - 1);
    }
    if (!strcmp(fault, "threads")) {
        Job jobs[6]; pthread_t threads[6];
        for (size_t i = 0; i < 6; i++) {
            jobs[i] = (Job){oidc, (char *)jwt, length, now, 0};
            if (pthread_create(&threads[i], NULL, thread, &jobs[i])) return 71;
        }
        int ok = 1;
        for (size_t i = 0; i < 6; i++) {
            if (pthread_join(threads[i], NULL)) return 71;
            ok &= jobs[i].ok;
        }
        printf("THREADS %d\n", ok);
    } else {
        YDOIDCIdentity identity;
        memset(&identity, 0xA5, sizeof(identity));
        YDOIDCResult result = yd_oidc_verify(!strcmp(fault, "null-context") ? NULL : oidc,
            !strcmp(fault, "null-token") ? NULL : (char *)jwt, length, now,
            !strcmp(fault, "null-output") ? NULL : &identity);
        const unsigned char *raw = (const unsigned char *)&identity;
        bool clear = true;
        for (size_t i = 0; i < sizeof(identity); i++) clear &= raw[i] == 0;
        printf("RESULT %d %u %" PRId64 " ", result, result == YD_OIDC_VALID ? identity.required_scope_present : 0,
            result == YD_OIDC_VALID ? identity.expires_at : INT64_C(0));
        /* Invalid output is checked bytewise, never dereferenced as strings. */
        if (result == YD_OIDC_VALID) hex(identity.subject); else putchar('-');
        putchar(' ');
        if (result == YD_OIDC_VALID) hex(identity.client_id); else putchar('-');
        printf(" %u\n", clear);
    }
    yd_oidc_free(oidc); free(jwt); free(bytes); return 0;
}
