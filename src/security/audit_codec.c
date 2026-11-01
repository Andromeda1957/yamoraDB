#include "audit_codec.h"
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <stdlib.h>
#include <string.h>

struct YDAuditMAC {
    EVP_MAC *algorithm;
    EVP_MAC_CTX *context;
    unsigned char key[32];
};
bool yd_audit_nonzero(const unsigned char *p, size_t n) {
    unsigned char any = 0;
    for (size_t i = 0; i < n; i++) any |= p[i];
    return any != 0;
}
bool yd_audit_limits_valid(const YDAuditLimits *l) {
    return l && l->segment_records >= 4 && l->segment_records <= YD_AUDIT_MAX_RECORDS &&
        l->segments && l->segments <= YD_AUDIT_MAX_SEGMENTS &&
        l->bytes >= 4096 && l->bytes <= YD_AUDIT_MAX_BYTES &&
        l->pending && l->pending <= YD_AUDIT_MAX_PENDING &&
        l->pending <= (l->segment_records - 2) / 2;
}
bool yd_audit_limits_equal(const YDAuditLimits *a, const YDAuditLimits *b) {
    return a->segment_records == b->segment_records && a->segments == b->segments &&
        a->bytes == b->bytes && a->pending == b->pending;
}
bool yd_audit_head_equal(const YDAuditHead *a, const YDAuditHead *b) {
    return a->version == b->version && a->segment == b->segment && a->sequence == b->sequence &&
        !memcmp(a->key_id, b->key_id, 16) && !memcmp(a->stream_id, b->stream_id, 16) &&
        !memcmp(a->segment_id, b->segment_id, 16) && !CRYPTO_memcmp(a->mac, b->mac, 32);
}
static void put32(unsigned char *p, uint32_t n) {
    for (unsigned i = 0; i < 4; i++) p[i] = (unsigned char)(n >> (i * 8));
}
static void put64(unsigned char *p, uint64_t n) {
    for (unsigned i = 0; i < 8; i++) p[i] = (unsigned char)(n >> (i * 8));
}
static uint32_t get32(const unsigned char *p) {
    uint32_t n = 0;
    for (unsigned i = 0; i < 4; i++) n |= (uint32_t)p[i] << (i * 8);
    return n;
}
static uint64_t get64(const unsigned char *p) {
    uint64_t n = 0;
    for (unsigned i = 0; i < 8; i++) n |= (uint64_t)p[i] << (i * 8);
    return n;
}
static bool initialize(YDAuditMAC *m) {
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0),
        OSSL_PARAM_construct_end()
    };
    return EVP_MAC_init(m->context, m->key, 32, params) == 1 &&
        EVP_MAC_CTX_get_mac_size(m->context) == 32;
}
YDAuditMAC *yd_audit_mac_new(const unsigned char key[32]) {
    if (!key) return NULL;
    YDAuditMAC *m = calloc(1, sizeof(*m));
    if (!m) return NULL;
    memcpy(m->key, key, 32);
    m->algorithm = EVP_MAC_fetch(NULL, "HMAC", NULL);
    m->context = m->algorithm ? EVP_MAC_CTX_new(m->algorithm) : NULL;
    if (!m->context || !initialize(m)) { yd_audit_mac_free(m); return NULL; }
    return m;
}
void yd_audit_mac_free(YDAuditMAC *m) {
    if (!m) return;
    EVP_MAC_CTX_free(m->context);
    EVP_MAC_free(m->algorithm);
    OPENSSL_cleanse(m->key, sizeof(m->key));
    free(m);
}
static bool mac(YDAuditMAC *m, const unsigned char *page, unsigned char out[32]) {
    /* Exactly 22 ASCII bytes plus ONE NUL = 23 bytes, then exactly 992 bytes. */
    static const unsigned char domain[] = "YAMORA-AUDIT-RECORD-V1";
    size_t n = 0;
    return initialize(m) && EVP_MAC_update(m->context, domain, sizeof(domain)) == 1 &&
        EVP_MAC_update(m->context, page, 992) == 1 &&
        EVP_MAC_final(m->context, out, &n, 32) == 1 && n == 32;
}
static bool zero_limits(const YDAuditLimits *l) {
    return !l->segment_records && !l->segments && !l->bytes && !l->pending;
}
bool yd_audit_record_valid(const YDAuditRecord *r) {
    if (!r || r->head.version != 1 || r->kind < YD_AUDIT_GENESIS || r->kind > YD_AUDIT_CONTINUE ||
        !r->head.segment || !r->head.sequence || !yd_audit_nonzero(r->head.key_id, 16) ||
        !yd_audit_nonzero(r->head.stream_id, 16) || !yd_audit_nonzero(r->head.segment_id, 16) ||
        (r->flags & ~YD_AUDIT_HAS_REVISION) || r->wall_ms > UINT64_C(253402300799999)) return false;
    if (r->kind == YD_AUDIT_GENESIS) {
        if (r->head.segment != 1 || r->head.sequence != 1 || yd_audit_nonzero(r->previous, 32)) return false;
    } else if (r->head.sequence < 2 || !yd_audit_nonzero(r->previous, 32)) return false;
    bool header = r->kind == YD_AUDIT_GENESIS || r->kind == YD_AUDIT_CONTINUE;
    if (header ? !yd_audit_limits_valid(&r->limits) : !zero_limits(&r->limits)) return false;
    if (r->kind == YD_AUDIT_CONTINUE && r->head.segment < 2) return false;
    if (r->kind == YD_AUDIT_SEAL) {
        if (r->head.segment == UINT64_MAX || r->next_segment != r->head.segment + 1 ||
            !yd_audit_nonzero(r->next_id, 16) || !memcmp(r->next_id, r->head.segment_id, 16)) return false;
    } else if (r->next_segment || yd_audit_nonzero(r->next_id, 16)) return false;
    if (header || r->kind == YD_AUDIT_SEAL)
        return !r->flags && !r->intent && !r->wall_ms && !r->elapsed_us && !r->transport &&
            !r->authentication && !r->operation && !r->outcome && !r->status && !r->actor_length &&
            !yd_audit_nonzero(r->actor, 128) && !yd_audit_nonzero(r->revision, 16) &&
            !r->subject_length && !yd_audit_nonzero(r->subject, 128);
    if (!r->transport || r->transport > YD_AUDIT_INTERNAL || r->authentication > YD_AUDIT_KERBEROS ||
        !r->operation || r->operation > YD_AUDIT_OPERATION_LAST || r->actor_length > 128 ||
        r->subject_length > 128) return false;
    /* A management record names exactly one role or principal; no other does. */
    if (YD_AUDIT_SUBJECT_OPERATION(r->operation) != (r->subject_length != 0)) return false;
    for (unsigned i = 0; i < 128; i++) {
        unsigned char c = r->subject[i];
        if (i >= r->subject_length ? c != 0 :
            !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
    }
    bool named = (r->authentication >= YD_AUDIT_STATIC && r->authentication <= YD_AUDIT_OIDC) ||
        r->authentication >= YD_AUDIT_AWS;
    if (named != (r->actor_length != 0)) return false;
    for (unsigned i = 0; i < 128; i++) {
        unsigned char c = r->actor[i];
        if (i >= r->actor_length ? c != 0 :
            !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
    }
    if (r->kind == YD_AUDIT_INTENT)
        return !r->intent && !r->outcome && !r->status && !r->elapsed_us && !r->flags &&
            !yd_audit_nonzero(r->revision, 16);
    if (!r->intent || r->intent >= r->head.sequence || !r->outcome || r->outcome > YD_AUDIT_UNKNOWN ||
        (r->status && (r->status < 100 || r->status > 599))) return false;
    for (unsigned i = 0; i < 16; i++) {
        unsigned char c = r->revision[i];
        if (r->flags ? !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) : c != 0) return false;
    }
    return true;
}
YDAuditResult yd_audit_record_encode(YDAuditMAC *m, const YDAuditRecord *r, unsigned char out[1024]) {
    if (out) memset(out, 0, 1024);
    if (!m || !r || !out || !yd_audit_record_valid(r)) return YD_AUDIT_REFUSED;
    memcpy(out, "YDAUDR01", 8);
    put32(out + 8, r->head.version); put32(out + 12, r->kind);
    put32(out + 16, 1024); put32(out + 20, r->flags);
    memcpy(out + 24, r->head.key_id, 16); memcpy(out + 40, r->head.stream_id, 16);
    memcpy(out + 56, r->head.segment_id, 16); put64(out + 72, r->head.segment);
    put64(out + 80, r->head.sequence); put64(out + 88, r->intent);
    memcpy(out + 96, r->previous, 32); put64(out + 128, r->wall_ms);
    put64(out + 136, r->elapsed_us); put32(out + 144, r->transport);
    put32(out + 148, r->authentication); put32(out + 152, r->operation);
    put32(out + 156, r->outcome); put32(out + 160, r->status);
    put32(out + 164, r->actor_length); memcpy(out + 168, r->actor, 128);
    memcpy(out + 296, r->revision, 16); put64(out + 312, r->next_segment);
    memcpy(out + 320, r->next_id, 16); put64(out + 336, r->limits.segment_records);
    put64(out + 344, r->limits.segments); put64(out + 352, r->limits.bytes);
    put32(out + 360, r->limits.pending);
    put32(out + 364, r->subject_length); memcpy(out + 368, r->subject, 128);
    if (!mac(m, out, out + 992)) { memset(out, 0, 1024); return YD_AUDIT_ERROR; }
    return YD_AUDIT_OK;
}
YDAuditResult yd_audit_record_decode(YDAuditMAC *m, const unsigned char bytes[1024], YDAuditRecord *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!m || !bytes || !out) return YD_AUDIT_REFUSED;
    if (memcmp(bytes, "YDAUDR01", 8) || get32(bytes + 8) != 1 || get32(bytes + 16) != 1024 ||
        yd_audit_nonzero(bytes + 496, 496)) return YD_AUDIT_CORRUPT;
    YDAuditRecord r = {0};
    r.head.version = get32(bytes + 8); r.kind = get32(bytes + 12); r.flags = get32(bytes + 20);
    memcpy(r.head.key_id, bytes + 24, 16); memcpy(r.head.stream_id, bytes + 40, 16);
    memcpy(r.head.segment_id, bytes + 56, 16); r.head.segment = get64(bytes + 72);
    r.head.sequence = get64(bytes + 80); r.intent = get64(bytes + 88);
    memcpy(r.previous, bytes + 96, 32); r.wall_ms = get64(bytes + 128); r.elapsed_us = get64(bytes + 136);
    r.transport = get32(bytes + 144); r.authentication = get32(bytes + 148);
    r.operation = get32(bytes + 152); r.outcome = get32(bytes + 156);
    r.status = get32(bytes + 160); r.actor_length = get32(bytes + 164);
    memcpy(r.actor, bytes + 168, 128); memcpy(r.revision, bytes + 296, 16);
    r.next_segment = get64(bytes + 312); memcpy(r.next_id, bytes + 320, 16);
    r.limits.segment_records = get64(bytes + 336); r.limits.segments = get64(bytes + 344);
    r.limits.bytes = get64(bytes + 352); r.limits.pending = get32(bytes + 360);
    r.subject_length = get32(bytes + 364); memcpy(r.subject, bytes + 368, 128);
    memcpy(r.head.mac, bytes + 992, 32);
    if (!yd_audit_record_valid(&r)) return YD_AUDIT_CORRUPT;
    unsigned char expected[32];
    if (!mac(m, bytes, expected)) return YD_AUDIT_ERROR;
    if (CRYPTO_memcmp(expected, r.head.mac, 32)) return YD_AUDIT_CORRUPT;
    *out = r;
    return YD_AUDIT_OK;
}
