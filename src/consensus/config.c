#include "config.h"
#include "application_worker.h"
#include "../security/access.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CONFIG_LIMIT (64U * 1024U)
bool yd_raft_id_parse(const char *text, unsigned char id[16]) {
    if (!text || strlen(text) != 32) return false;
    unsigned char out[16] = {0}, nonzero = 0;
    for (unsigned i = 0; i < 32; i++) {
        unsigned char c = (unsigned char)text[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        unsigned value = c <= '9' ? c - '0' : c - 'a' + 10;
        out[i / 2] |= (unsigned char)(value << (i % 2 ? 0 : 4));
    }
    for (unsigned i = 0; i < 16; i++) nonzero |= out[i];
    if (!nonzero) return false;
    memcpy(id, out, 16); return true;
}
static bool fields(const YDValue *v, const char *const allowed[], size_t count) {
    if (!v || v->type != YD_MAP) return false;
    for (size_t i = 0; i < v->count; i++) {
        size_t j = 0;
        while (j < count && strcmp(v->keys[i], allowed[j])) j++;
        if (j == count) return false;
    }
    return true;
}
static const char *string(const YDValue *v) { return v && v->type == YD_STRING ? v->scalar : NULL; }
static const char *path(const YDValue *v) {
    const char *s = string(v);
    if (!s || s[0] != '/' || strlen(s) > 4096) return NULL;
    for (size_t i = 0; s[i]; i++) if ((unsigned char)s[i] < 32 || s[i] == 127) return NULL;
    return s;
}
static bool number(const YDValue *map, const char *key, size_t low, size_t high, size_t *out) {
    const YDValue *v = yd_get(map, key);
    if (!v || v->type != YD_INT || v->number < low || v->number > high) return false;
    *out = (size_t)v->number; return true;
}
static bool optional(const YDValue *map, const char *key, size_t low, size_t high, size_t *out) {
    return !yd_get(map, key) || number(map, key, low, high, out);
}
/* Keep YAML thresholds exactly representable even on platforms where long
 * double has double precision. The private C policy can use all uint64_t. */
static bool bytes(const YDValue *map, const char *key, uint64_t low, uint64_t *out) {
    const YDValue *v = yd_get(map, key);
    if (!v || v->type != YD_INT || v->number < low || v->number > 1125899906842624ULL)
        return false;
    *out = (uint64_t)v->number;
    return true;
}
void yd_raft_settings_free(YDRaftSettings *s) {
    if (s) { yd_free(s->model); free(s); }
}
YDRaftSettings *yd_raft_settings_load(const char *file, char *error, size_t length) {
    size_t size = 0;
    char *text = yd_access_read_private(file, CONFIG_LIMIT, &size);
    YDValue *m = text ? yd_parse_sized((unsigned char *)text, size, CONFIG_LIMIT, error, length) : NULL;
    free(text);
    YDRaftSettings *s = calloc(1, sizeof(*s));
    if (!s) { yd_free(m); goto invalid; }
    s->model = m;
    static const char *const root[] = {"cluster", "node", "journal_dir", "peer_tls", "peers", "timing",
                                      "journal_cache_bytes", "command_bytes", "request_timeout_ms", "checkpoints", "compaction", "application_compaction", "initial_voters", "native_capabilities"};
    static const char *const tls[] = {"cert_file", "key_file", "ca_file", "crl_file"};
    static const char *const peer[] = {"id", "name", "address", "port"};
    static const char *const timing[] = {"heartbeat_ms", "election_min_ms", "election_max_ms", "rpc_ms"};
    static const char *const checkpoints[] = {"entries", "interval_ms", "timeout_ms"};
    static const char *const compaction[] = {"minimum_bytes", "minimum_saved_bytes", "interval_ms", "attempts"};
    size_t node, timeout = 5000, native_capabilities = 0;
    const YDValue *t = yd_get(m, "peer_tls"), *peers = yd_get(m, "peers"), *clock = yd_get(m, "timing");
    if (!fields(m, root, sizeof(root)/sizeof(*root)) ||
        !yd_raft_id_parse(string(yd_get(m, "cluster")), s->raft.cluster) ||
        !number(m, "node", 1, YD_RAFT_VOTERS, &node) ||
        !(s->raft.journal_root = path(yd_get(m, "journal_dir"))) || !fields(t, tls, 4) ||
        !(s->certificate = path(yd_get(t, "cert_file"))) || !(s->key = path(yd_get(t, "key_file"))) ||
        !(s->ca = path(yd_get(t, "ca_file"))) ||
        (yd_get(t, "crl_file") && !(s->crl_file = path(yd_get(t, "crl_file")))) ||
        !peers || peers->type != YD_ARRAY ||
        peers->count < 3 || peers->count > YD_RAFT_VOTERS || !(peers->count & 1)) goto fail;
    s->raft.node = (unsigned)node; s->raft.voters = (unsigned)peers->count;
    const YDValue *initial = yd_get(m, "initial_voters");
    if (initial) {
        if (initial->type != YD_ARRAY || initial->count < 3 || initial->count > peers->count) goto fail;
        for (size_t i = 0; i < initial->count; i++) {
            const YDValue *id = initial->items[i];
            if (!id || id->type != YD_INT || id->number < 1 || id->number > peers->count) goto fail;
            uint16_t bit = (uint16_t)(1U << (unsigned)id->number);
            if (s->raft.initial_voters & bit) goto fail;
            s->raft.initial_voters |= bit;
        }
    }
    for (size_t i = 0; i < peers->count; i++) {
        const YDValue *p = peers->items[i]; size_t id, port;
        if (!fields(p, peer, 4) || !number(p, "id", 1, peers->count, &id) ||
            s->raft.names[id] || !number(p, "port", 1, 65535, &port) ||
            !(s->raft.names[id] = string(yd_get(p, "name"))) ||
            !(s->raft.addresses[id] = string(yd_get(p, "address")))) goto fail;
        s->raft.ports[id] = (uint16_t)port;
    }
    size_t ticks[] = {50, 600, 1100, 250};
    if (clock && !fields(clock, timing, 4)) goto fail;
    for (unsigned i = 0; i < 4; i++)
        if (!optional(clock, timing[i], 1, 30000, &ticks[i])) goto fail;
    s->raft.timing = (YDRaftTiming){(unsigned)ticks[0], (unsigned)ticks[1], (unsigned)ticks[2], (unsigned)ticks[3]};
    s->raft.cache_bytes = 1024U * 1024U; s->raft.command_bytes = YD_LARGE_REQUEST_LIMIT;
    if (!optional(m, "journal_cache_bytes", 32768, 1024U*1024U*1024U, &s->raft.cache_bytes) ||
        !optional(m, "command_bytes", 1, YD_LARGE_REQUEST_LIMIT, &s->raft.command_bytes) ||
        !optional(m, "request_timeout_ms", 100, 30000, &timeout) ||
        !optional(m, "native_capabilities", 0, YD_DISK_CAP_SUPPORTED, &native_capabilities)) goto fail;
    s->raft.native_capabilities = (uint32_t)native_capabilities;
    if (!yd_raft_config_valid(&s->raft)) goto fail;
    s->request_timeout_ms = (unsigned)timeout;
    const YDValue *policy = yd_get(m, "checkpoints");
    size_t entries = 0, interval = 10000, admission = 1000;
    if (policy && (!fields(policy, checkpoints, 3) ||
        !number(policy, "entries", 0, 1000000000, &entries) ||
        !optional(policy, "interval_ms", 100, 3600000, &interval) ||
        !optional(policy, "timeout_ms", 100, 30000, &admission) ||
        (entries && s->raft.command_bytes < 256))) goto fail;
    s->checkpoints = (YDRaftCheckpointPolicy){entries, (unsigned)interval, (unsigned)admission};
    policy = yd_get(m, "compaction");
    uint64_t minimum = 0, saved = 1024U * 1024U;
    interval = 60000;
    size_t attempts = 3;
    if (policy && (!fields(policy, compaction, 4) || !bytes(policy, "minimum_bytes", 0, &minimum) ||
        (yd_get(policy, "minimum_saved_bytes") && !bytes(policy, "minimum_saved_bytes", 1, &saved)) ||
        !optional(policy, "interval_ms", 100, 3600000, &interval) ||
        !optional(policy, "attempts", 1, 16, &attempts))) goto fail;
    s->compaction = (YDRaftCompactionPolicy){minimum, saved, (unsigned)interval, (unsigned)attempts};
    policy = yd_get(m, "application_compaction");
    static const char *const application[] = {"minimum_source_bytes", "image_bytes", "archive_bytes",
        "restore_bytes", "maximum_work_bytes", "maximum_retained_bytes", "minimum_free_bytes",
        "minimum_saved_bytes", "interval_ms", "admission_ms", "work_ms"};
    YDRaftApplicationCompactionPolicy *operation = &s->application_compaction.operation;
    interval = 60000; admission = 1000;
    size_t work = 30000;
    if (policy) {
        if (!fields(policy, application, sizeof(application)/sizeof(*application)) ||
            !bytes(policy, "minimum_source_bytes", 0, &operation->minimum_source_bytes) ||
            !optional(policy, "interval_ms", 100, 3600000, &interval) ||
            !optional(policy, "admission_ms", 100, 30000, &admission) ||
            !optional(policy, "work_ms", 100, 3600000, &work)) goto fail;
        struct { const char *key; uint64_t low, *value; } limits[] = {
            {"image_bytes", 8192, &operation->limits.image_bytes},
            {"archive_bytes", 8448, &operation->limits.archive_bytes},
            {"restore_bytes", 8192, &operation->limits.restore_bytes},
            {"maximum_work_bytes", 1, &operation->limits.maximum_work_bytes},
            {"maximum_retained_bytes", 1, &operation->limits.maximum_retained_bytes},
            {"minimum_free_bytes", 0, &operation->limits.minimum_free_bytes},
            {"minimum_saved_bytes", 1, &operation->limits.minimum_saved_bytes}
        };
        for (size_t i = 0; i < sizeof(limits)/sizeof(*limits); i++) {
            if (yd_get(policy, limits[i].key)) {
                if (!bytes(policy, limits[i].key, limits[i].low, limits[i].value)) goto fail;
            } else if (operation->minimum_source_bytes) goto fail;
        }
    }
    operation->admission_ms = (unsigned)admission;
    operation->work_ms = (unsigned)work;
    s->application_compaction.interval_ms = (unsigned)interval;
    if (operation->minimum_source_bytes &&
        !yd_raft_application_worker_policy_valid(s->application_compaction)) goto fail;
    return s;
fail:
    yd_raft_settings_free(s);
invalid:
    snprintf(error, length, "invalid private replica-set configuration"); return NULL;
}
