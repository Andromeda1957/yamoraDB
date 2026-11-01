#define _POSIX_C_SOURCE 200809L
#include "audit_helper_codec.h"
#include "audit_codec.h"
#include <string.h>
static void put(unsigned char *p, uint64_t n, unsigned bytes) {
    for (unsigned i = 0; i < bytes; i++) p[i] = (unsigned char)(n >> (8 * i));
}
static uint64_t get(const unsigned char *p, unsigned bytes) {
    uint64_t n = 0;
    for (unsigned i = 0; i < bytes; i++) n |= (uint64_t)p[i] << (8 * i);
    return n;
}
static bool head_valid(const YDAuditHead *h) {
    return h && h->version == 1 && h->segment && h->sequence &&
        yd_audit_nonzero(h->key_id, 16) && yd_audit_nonzero(h->stream_id, 16) &&
        yd_audit_nonzero(h->segment_id, 16) && yd_audit_nonzero(h->mac, 32);
}
bool yd_audit_anchor_encode(const YDAuditHead *h, unsigned char out[128]) {
    if (!out) return false;
    memset(out, 0, 128);
    if (!head_valid(h)) return false;
    memcpy(out, "YDAUAN01", 8); put(out + 8, 1, 4); put(out + 12, 128, 4);
    memcpy(out + 16, h->key_id, 16); memcpy(out + 32, h->stream_id, 16);
    memcpy(out + 48, h->segment_id, 16); put(out + 64, h->segment, 8);
    put(out + 72, h->sequence, 8); memcpy(out + 80, h->mac, 32);
    return true;
}
bool yd_audit_anchor_decode(const unsigned char bytes[128], YDAuditHead *out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!bytes || memcmp(bytes, "YDAUAN01", 8) || get(bytes + 8, 4) != 1 ||
        get(bytes + 12, 4) != 128 || yd_audit_nonzero(bytes + 112, 16)) return false;
    YDAuditHead h = {.version = 1, .segment = get(bytes + 64, 8), .sequence = get(bytes + 72, 8)};
    memcpy(h.key_id, bytes + 16, 16); memcpy(h.stream_id, bytes + 32, 16);
    memcpy(h.segment_id, bytes + 48, 16); memcpy(h.mac, bytes + 80, 32);
    if (!head_valid(&h)) return false;
    *out = h; return true;
}
static bool name_valid(const char *name, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
    }
    return true;
}
static bool event_valid(const YDAuditEvent *e) {
    size_t n = strnlen(e->actor, sizeof(e->actor)), s = strnlen(e->subject, sizeof(e->subject));
    if (e->wall_ms > UINT64_C(253402300799999) || !e->transport || e->transport > YD_AUDIT_INTERNAL ||
        e->authentication > YD_AUDIT_KERBEROS || !e->operation || e->operation > YD_AUDIT_OPERATION_LAST ||
        n > 128 || s > 128) return false;
    bool named = (e->authentication >= YD_AUDIT_STATIC && e->authentication <= YD_AUDIT_OIDC) ||
        e->authentication >= YD_AUDIT_AWS;
    if (named != (n != 0) || YD_AUDIT_SUBJECT_OPERATION(e->operation) != (s != 0)) return false;
    return name_valid(e->actor, n) && name_valid(e->subject, s);
}
static bool completion_valid(const YDAuditCompletion *c) {
    if (c->wall_ms > UINT64_C(253402300799999) || !c->outcome || c->outcome > YD_AUDIT_UNKNOWN ||
        (c->status && (c->status < 100 || c->status > 599))) return false;
    if (c->has_revision) {
        if (strnlen(c->revision, 17) != 16) return false;
        for (size_t i = 0; i < 16; i++) {
            char v = c->revision[i];
            if (!((v >= '0' && v <= '9') || (v >= 'a' && v <= 'f'))) return false;
        }
    } else if (yd_audit_nonzero((const unsigned char *)c->revision, 17)) return false;
    return true;
}
bool yd_audit_packet_encode(const YDAuditPacket *p, unsigned char out[512]) {
    if (!out) return false;
    memset(out, 0, 512);
    if (!p || !p->id || p->kind < 1 || p->kind > 4) return false;
    unsigned char *b = out + 32; uint32_t length = 0;
    if (p->kind == YD_AUDIT_BEGIN) {
        if (!event_valid(&p->event)) return false;
        const YDAuditEvent *e = &p->event;
        length = 152; put(b, e->wall_ms, 8); put(b + 8, e->transport, 4);
        put(b + 12, e->authentication, 4); put(b + 16, e->operation, 4);
        size_t n = strlen(e->actor); put(b + 20, n, 4); memcpy(b + 24, e->actor, n);
        /* Subject-bearing BEGIN is longer, so an older helper rejects it. */
        size_t s = strlen(e->subject);
        if (s) { length = 284; put(b + 152, s, 4); memcpy(b + 156, e->subject, s); }
    } else if (p->kind == YD_AUDIT_FINISH_REQUEST) {
        if (!yd_audit_nonzero(p->handle, 16) || !completion_valid(&p->completion)) return false;
        const YDAuditCompletion *c = &p->completion;
        length = 60; memcpy(b, p->handle, 16); put(b + 16, c->wall_ms, 8);
        put(b + 24, c->elapsed_us, 8); put(b + 32, c->outcome, 4); put(b + 36, c->status, 4);
        put(b + 40, c->has_revision, 4); if (c->has_revision) memcpy(b + 44, c->revision, 16);
    } else if (p->kind == YD_AUDIT_REPLY) {
        if (p->result > YD_AUDIT_IPC_ERROR || p->request_kind < 1 || p->request_kind > 3 ||
            !yd_audit_nonzero(p->incarnation, 16)) return false;
        bool begin = p->request_kind == YD_AUDIT_BEGIN && p->result == YD_AUDIT_ACK;
        if (begin != (p->sequence != 0) || begin != yd_audit_nonzero(p->handle, 16)) return false;
        length = 52; put(b, p->result, 4); put(b + 4, p->request_kind, 4);
        memcpy(b + 8, p->incarnation, 16); memcpy(b + 24, p->handle, 16); put(b + 40, p->sequence, 8);
    }
    memcpy(out, "YDAUIP01", 8); put(out + 8, 1, 4); put(out + 12, p->kind, 4);
    put(out + 16, p->id, 8); put(out + 24, length, 4);
    return true;
}
bool yd_audit_packet_decode(const unsigned char bytes[512], YDAuditPacket *out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!bytes || memcmp(bytes, "YDAUIP01", 8) || get(bytes + 8, 4) != 1 ||
        get(bytes + 28, 4)) return false;
    YDAuditPacket p = {.kind = (uint32_t)get(bytes + 12, 4), .id = get(bytes + 16, 8)};
    const unsigned char *b = bytes + 32;
    if (p.kind == YD_AUDIT_BEGIN) {
        size_t n = (size_t)get(b + 20, 4), s = (size_t)get(b + 152, 4);
        if (n > 128 || yd_audit_nonzero(b + 24 + n, 128 - n) || s > 128 ||
            yd_audit_nonzero(b + 156 + s, 128 - s)) return false;
        p.event.wall_ms = get(b, 8); p.event.transport = (uint32_t)get(b + 8, 4);
        p.event.authentication = (uint32_t)get(b + 12, 4); p.event.operation = (uint32_t)get(b + 16, 4);
        memcpy(p.event.actor, b + 24, n);
        memcpy(p.event.subject, b + 156, s);
    } else if (p.kind == YD_AUDIT_FINISH_REQUEST) {
        uint64_t flags = get(b + 40, 4);
        if (flags > 1) return false;
        memcpy(p.handle, b, 16); p.completion.wall_ms = get(b + 16, 8);
        p.completion.elapsed_us = get(b + 24, 8); p.completion.outcome = (uint32_t)get(b + 32, 4);
        p.completion.status = (uint32_t)get(b + 36, 4); p.completion.has_revision = flags != 0;
        memcpy(p.completion.revision, b + 44, 16);
    } else if (p.kind == YD_AUDIT_REPLY) {
        p.result = (uint32_t)get(b, 4); p.request_kind = (uint32_t)get(b + 4, 4);
        memcpy(p.incarnation, b + 8, 16); memcpy(p.handle, b + 24, 16); p.sequence = get(b + 40, 8);
    }
    unsigned char canonical[512];
    if (!yd_audit_packet_encode(&p, canonical) || memcmp(bytes, canonical, 512)) return false;
    *out = p; return true;
}
