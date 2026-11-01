#define _POSIX_C_SOURCE 200809L
#include "oidc.h"
#include "oidc_json.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY_LIMIT 8U
#define HEADER_LIMIT 512U
#define CLAIMS_LIMIT 2048U
#define DATE_MAX INT64_C(253402300799)
typedef struct {
    char kid[129];
    EVP_PKEY *public_key;
    unsigned char modulus[512];
    size_t size;
} Key;
struct YDOIDC {
    char issuer[513], audience[257], required_scope[129];
    unsigned skew, lifetime;
    size_t count;
    Key keys[KEY_LIMIT];
    bool id_profile;
};
typedef YDOIDCJSONNode Node;
static const Node *get(const Node *n, const char *key) { return yd_oidc_json_get(n, key); }
static bool visible(const char *s, size_t maximum) {
    if (!s) return false;
    size_t n = strnlen(s, maximum + 1);
    if (!n || n > maximum) return false;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)s[i] < 0x21 || (unsigned char)s[i] > 0x7e) return false;
    return true;
}
static bool scope_word(const char *s, size_t n) {
    if (!n) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x21 || c > 0x7e || c == '"' || c == '\\') return false;
    }
    return true;
}
static bool issuer_valid(const char *s) {
    if (!visible(s, 512) || strncmp(s, "https://", 8)) return false;
    const char *authority = s + 8, *end = strchr(authority, '/');
    if (!end) end = s + strlen(s);
    if (authority == end) return false;
    for (const char *p = authority; *p; p++)
        if (*p == '@' || *p == '?' || *p == '#' || *p == '\\') return false;
    return true;
}
static bool scalar(const Node *n, size_t maximum) {
    if (!n || n->type != YD_OIDC_JSON_STRING || !n->length || n->length > maximum) return false;
    for (size_t i = 0; i < n->length; i++)
        if ((unsigned char)n->text[i] < 0x20 || (unsigned char)n->text[i] == 0x7f) return false;
    return true;
}
static bool equal(const Node *n, const char *s) {
    return n && n->type == YD_OIDC_JSON_STRING && n->length == strlen(s) &&
        !memcmp(n->text, s, n->length);
}
static bool folded(const Node *n, const char *s) {
    if (!n || n->type != YD_OIDC_JSON_STRING || n->length != strlen(s)) return false;
    for (size_t i = 0; i < n->length; i++) {
        unsigned char c = (unsigned char)n->text[i];
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + 'a' - 'A');
        if (c != (unsigned char)s[i]) return false;
    }
    return true;
}
static int sextet(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}
static bool decode(const char *text, size_t length, unsigned char *out,
    size_t capacity, size_t *used) {
    *used = 0;
    if (!length || length % 4 == 1 || length > (capacity * 4 + 2) / 3) return false;
    uint32_t accumulator = 0;
    unsigned bits = 0;
    for (size_t i = 0; i < length; i++) {
        int n = sextet((unsigned char)text[i]);
        if (n < 0) return false;
        accumulator = (accumulator << 6) | (unsigned)n; bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (*used == capacity) return false;
            out[(*used)++] = (unsigned char)(accumulator >> bits);
        }
    }
    return !bits || !(accumulator & ((UINT32_C(1) << bits) - 1));
}
static bool public_key(Key *key, const Node *spec) {
    static const char *const allowed[] = {"kty", "alg", "kid", "n", "e", "use", "key_ops"};
    if (!spec || spec->type != YD_OIDC_JSON_OBJECT || spec->count < 5 || spec->count > 7)
        return false;
    for (const Node *p = spec->first; p; p = p->next) {
        bool known = false;
        for (size_t i = 0; i < sizeof(allowed) / sizeof(*allowed); i++)
            known |= !strcmp(p->name, allowed[i]);
        if (!known) return false;
    }
    const Node *kid = get(spec, "kid"), *n = get(spec, "n"), *e = get(spec, "e");
    const Node *use = get(spec, "use"), *operations = get(spec, "key_ops");
    if (!equal(get(spec, "kty"), "RSA") || !equal(get(spec, "alg"), "RS256") ||
        !scalar(kid, 128) || !visible(kid->text, 128) || !scalar(n, 683) ||
        !scalar(e, 4) || (use && !equal(use, "sig")) ||
        (operations && (operations->type != YD_OIDC_JSON_ARRAY ||
            operations->count != 1 || !equal(operations->first, "verify")))) return false;
    unsigned char exponent[3]; size_t exponent_length = 0;
    if (!decode(n->text, n->length, key->modulus, sizeof(key->modulus), &key->size) ||
        key->size < 256 || !key->modulus[0] || !(key->modulus[key->size - 1] & 1) ||
        !decode(e->text, e->length, exponent, sizeof(exponent), &exponent_length) ||
        exponent_length != 3 || exponent[0] != 1 || exponent[1] != 0 || exponent[2] != 1)
        return false;
    memcpy(key->kid, kid->text, kid->length + 1);
    BIGNUM *modulus = BN_bin2bn(key->modulus, (int)key->size, NULL);
    BIGNUM *exp = BN_bin2bn(exponent, sizeof(exponent), NULL);
    OSSL_PARAM_BLD *builder = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *context = NULL, *check = NULL, *verify_key = NULL;
    EVP_MD_CTX *verify = NULL;
    bool valid = modulus && exp && builder && BN_num_bits(modulus) >= 2048 &&
        BN_num_bits(modulus) <= 4096 &&
        OSSL_PARAM_BLD_push_BN(builder, "n", modulus) == 1 &&
        OSSL_PARAM_BLD_push_BN(builder, "e", exp) == 1;
    if (valid) {
        params = OSSL_PARAM_BLD_to_param(builder);
        context = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        valid = params && context && EVP_PKEY_fromdata_init(context) == 1 &&
            EVP_PKEY_fromdata(context, &key->public_key, EVP_PKEY_PUBLIC_KEY, params) == 1;
    }
    if (valid) {
        check = EVP_PKEY_CTX_new_from_pkey(NULL, key->public_key, NULL);
        verify = EVP_MD_CTX_new();
        valid = check && EVP_PKEY_public_check(check) == 1 && verify &&
            EVP_DigestVerifyInit_ex(verify, &verify_key, "SHA256", NULL, NULL,
                key->public_key, NULL) == 1 &&
            EVP_PKEY_CTX_set_rsa_padding(verify_key, RSA_PKCS1_PADDING) == 1;
    }
    EVP_MD_CTX_free(verify); EVP_PKEY_CTX_free(check); EVP_PKEY_CTX_free(context);
    OSSL_PARAM_free(params); OSSL_PARAM_BLD_free(builder); BN_free(exp); BN_free(modulus);
    return valid;
}
void yd_oidc_free(YDOIDC *oidc) {
    if (!oidc) return;
    for (size_t i = 0; i < oidc->count; i++) EVP_PKEY_free(oidc->keys[i].public_key);
    OPENSSL_cleanse(oidc, sizeof(*oidc)); free(oidc);
}
YDOIDC *yd_oidc_new(const YDOIDCOptions *options, const unsigned char *jwks,
    size_t length, char *error, size_t error_length) {
    if (error && error_length) error[0] = 0;
    YDOIDC *oidc = NULL;
    YDOIDCJSON *doc = NULL;
    ERR_clear_error();
    if (!options || !jwks || !length || length > YD_OIDC_JWKS_MAX_BYTES ||
        !issuer_valid(options->issuer) || !visible(options->audience, 256) ||
        !visible(options->required_scope, 128) ||
        !scope_word(options->required_scope, strlen(options->required_scope)) ||
        options->clock_skew_seconds > 120 || options->max_token_lifetime_seconds < 60 ||
        options->max_token_lifetime_seconds > 3600 ||
        yd_oidc_json_parse(jwks, length, YD_OIDC_JSON_MAX_NODES, &doc) != YD_OIDC_JSON_OK)
        goto invalid;
    const Node *root = yd_oidc_json_root(doc), *keys = get(root, "keys");
    if (!root || root->type != YD_OIDC_JSON_OBJECT || root->count != 1 ||
        !keys || keys->type != YD_OIDC_JSON_ARRAY || !keys->count || keys->count > KEY_LIMIT)
        goto invalid;
    oidc = calloc(1, sizeof(*oidc));
    if (!oidc) goto invalid;
    strcpy(oidc->issuer, options->issuer); strcpy(oidc->audience, options->audience);
    strcpy(oidc->required_scope, options->required_scope);
    oidc->skew = options->clock_skew_seconds; oidc->lifetime = options->max_token_lifetime_seconds;
    oidc->count = keys->count;
    const Node *spec = keys->first;
    for (size_t i = 0; i < oidc->count; i++, spec = spec->next) {
        if (!public_key(&oidc->keys[i], spec)) goto invalid;
        for (size_t j = 0; j < i; j++)
            if (!strcmp(oidc->keys[j].kid, oidc->keys[i].kid)) goto invalid;
    }
    yd_oidc_json_free(doc); ERR_clear_error(); return oidc;
invalid:
    yd_oidc_json_free(doc); yd_oidc_free(oidc); ERR_clear_error();
    if (error && error_length) snprintf(error, error_length, "invalid OIDC configuration or public key set");
    return NULL;
}
YDOIDC *yd_oidc_new_id(const YDOIDCOptions *options, const unsigned char *jwks,
    size_t length, char *error, size_t error_length) {
    YDOIDC *oidc = yd_oidc_new(options, jwks, length, error, error_length);
    if (oidc) oidc->id_profile = true;
    return oidc;
}
static bool date(const Node *n, int64_t *out) {
    if (!n || n->type != YD_OIDC_JSON_NUMBER || !n->length || n->length > 12) return false;
    int64_t value = 0;
    for (size_t i = 0; i < n->length; i++) {
        unsigned char c = (unsigned char)n->text[i];
        if (c < '0' || c > '9' || value > (DATE_MAX - (c - '0')) / 10) return false;
        value = value * 10 + c - '0';
    }
    *out = value; return true;
}
static bool audience(const Node *n, const char *wanted) {
    if (n && n->type == YD_OIDC_JSON_STRING) return scalar(n, 256) && equal(n, wanted);
    if (!n || n->type != YD_OIDC_JSON_ARRAY || !n->count || n->count > 8) return false;
    bool found = false;
    for (const Node *p = n->first; p; p = p->next) {
        if (!scalar(p, 256)) return false;
        for (const Node *q = n->first; q != p; q = q->next)
            if (p->length == q->length && !memcmp(p->text, q->text, p->length)) return false;
        found |= equal(p, wanted);
    }
    return found;
}
static bool scope(const Node *n, const char *wanted, bool *present) {
    *present = false;
    if (!n) return true;
    if (n->type != YD_OIDC_JSON_STRING || n->length > 1024) return false;
    if (!n->length) return true;
    size_t start = 0;
    for (size_t i = 0; i <= n->length; i++) {
        if (i != n->length && n->text[i] != ' ') continue;
        if (!scope_word(n->text + start, i - start)) return false;
        if (i - start == strlen(wanted) && !memcmp(n->text + start, wanted, i - start))
            *present = true;
        start = i + 1;
    }
    return true;
}
static YDOIDCResult verify(const YDOIDC *oidc, const char *jwt, size_t length,
    const char *nonce, bool id_profile, int64_t now, YDOIDCIdentity *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!oidc || !jwt || !out || now < 0 || now > DATE_MAX) return YD_OIDC_ERROR;
    if (oidc->id_profile != id_profile || (id_profile && !visible(nonce, 255))) return YD_OIDC_ERROR;
    if (!length || length > YD_OIDC_JWT_MAX_BYTES) return YD_OIDC_INVALID;
    const char *first = memchr(jwt, '.', length);
    if (!first) return YD_OIDC_INVALID;
    size_t header_length = (size_t)(first - jwt), remaining = length - header_length - 1;
    const char *second = memchr(first + 1, '.', remaining);
    if (!second || memchr(second + 1, '.', length - (size_t)(second + 1 - jwt)))
        return YD_OIDC_INVALID;
    unsigned char header[HEADER_LIMIT], claims[CLAIMS_LIMIT], signature[512];
    size_t hn = 0, cn = 0, sn = 0;
    YDOIDCJSON *header_doc = NULL, *claims_doc = NULL;
    EVP_MD_CTX *context = NULL;
    EVP_PKEY_CTX *key_context = NULL;
    YDOIDCResult result = YD_OIDC_INVALID;
    if (!decode(jwt, header_length, header, sizeof(header), &hn) ||
        !decode(first + 1, (size_t)(second - first - 1), claims, sizeof(claims), &cn) ||
        !decode(second + 1, length - (size_t)(second + 1 - jwt), signature, sizeof(signature), &sn))
        goto done;
    YDOIDCJSONResult parsed = yd_oidc_json_parse(header, hn, 256, &header_doc);
    if (parsed != YD_OIDC_JSON_OK) {
        if (parsed == YD_OIDC_JSON_ERROR) result = YD_OIDC_ERROR;
        goto done;
    }
    const Node *h = yd_oidc_json_root(header_doc), *kid = get(h, "kid");
    if (!h || h->type != YD_OIDC_JSON_OBJECT || h->count != 3 ||
        !equal(get(h, "alg"), "RS256") || !scalar(kid, 128) ||
        (id_profile ? !folded(get(h, "typ"), "jwt") :
        (!folded(get(h, "typ"), "at+jwt") && !folded(get(h, "typ"), "application/at+jwt"))))
        goto done;
    const Key *key = NULL;
    for (size_t i = 0; i < oidc->count; i++)
        if (equal(kid, oidc->keys[i].kid)) key = &oidc->keys[i];
    if (!key || sn != key->size || memcmp(signature, key->modulus, sn) >= 0) goto done;
    parsed = yd_oidc_json_parse(claims, cn, 256, &claims_doc);
    if (parsed != YD_OIDC_JSON_OK) {
        if (parsed == YD_OIDC_JSON_ERROR) result = YD_OIDC_ERROR;
        goto done;
    }
    const Node *c = yd_oidc_json_root(claims_doc), *sub = get(c, "sub");
    const Node *client = get(c, id_profile ? "azp" : "client_id");
    if (id_profile && !client) client = get(c, "aud");
    int64_t issued = 0, expires = 0, not_before = 0;
    const Node *nbf = get(c, "nbf");
    bool scoped = false;
    if (!c || c->type != YD_OIDC_JSON_OBJECT || !equal(get(c, "iss"), oidc->issuer) ||
        !audience(get(c, "aud"), oidc->audience) || !scalar(sub, YD_OIDC_IDENTITY_MAX_BYTES) ||
        !scalar(client, YD_OIDC_IDENTITY_MAX_BYTES) ||
        (id_profile ? (!equal(client, oidc->audience) || !equal(get(c, "nonce"), nonce)) :
            !scalar(get(c, "jti"), 255)) ||
        get(c, "cnf") || !date(get(c, "iat"), &issued) || !date(get(c, "exp"), &expires) ||
        (nbf && (!date(nbf, &not_before) || not_before >= expires)) ||
        issued >= expires || expires - issued > oidc->lifetime ||
        issued > now + oidc->skew || now >= expires + oidc->skew ||
        (nbf && not_before > now + oidc->skew) ||
        (!id_profile && !scope(get(c, "scope"), oidc->required_scope, &scoped))) goto done;
    ERR_clear_error();
    context = EVP_MD_CTX_new();
    if (!context || EVP_DigestVerifyInit_ex(context, &key_context, "SHA256", NULL, NULL,
            key->public_key, NULL) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(key_context, RSA_PKCS1_PADDING) != 1) {
        result = YD_OIDC_ERROR; goto done;
    }
    /* Zero means invalid signature even when OpenSSL's queue contains padding
     * errors. Negative is an operational failure; structural signature errors
     * (width and representative >= modulus) have already returned INVALID. */
    int verified = EVP_DigestVerify(context, signature, sn,
        (const unsigned char *)jwt, (size_t)(second - jwt));
    if (verified != 1) {
        result = verified == 0 ? YD_OIDC_INVALID : YD_OIDC_ERROR; goto done;
    }
    memcpy(out->subject, sub->text, sub->length + 1);
    memcpy(out->client_id, client->text, client->length + 1);
    out->expires_at = expires; out->required_scope_present = scoped;
    result = YD_OIDC_VALID;
done:
    EVP_MD_CTX_free(context); yd_oidc_json_free(header_doc); yd_oidc_json_free(claims_doc);
    OPENSSL_cleanse(header, sizeof(header)); OPENSSL_cleanse(claims, sizeof(claims));
    OPENSSL_cleanse(signature, sizeof(signature)); ERR_clear_error(); return result;
}
YDOIDCResult yd_oidc_verify(const YDOIDC *oidc, const char *jwt, size_t length,
    int64_t now, YDOIDCIdentity *out) {
    return verify(oidc, jwt, length, NULL, false, now, out);
}
YDOIDCResult yd_oidc_verify_id(const YDOIDC *oidc, const char *jwt, size_t length,
    const char *nonce, int64_t now, YDOIDCIdentity *out) {
    return verify(oidc, jwt, length, nonce, true, now, out);
}
