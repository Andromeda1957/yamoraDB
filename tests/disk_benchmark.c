#define _POSIX_C_SOURCE 200809L
#include "../src/disk_query.h"
#include "../src/disk_bulk.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
static double seconds(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}
static long resident_peak_kib(void) {
    static long sampled_peak = -1;
    FILE *status = fopen("/proc/self/status", "r");
    if (!status)
        return -1;
    char line[256];
    long peak = -1;
    while (fgets(line, sizeof(line), status))
        if (sscanf(line, "VmHWM: %ld kB", &peak) == 1)
            break;
    fclose(status);
    if (peak > sampled_peak)
        sampled_peak = peak;
    return sampled_peak;
}
static int failure(YDDisk *disk, const char *message) {
    fprintf(stderr, "benchmark failed: %s\n", message);
    yd_disk_close(disk);
    return 1;
}
int main(int argc, char **argv) {
    if (argc != 3)
        return 2;
    unsigned count = (unsigned)strtoul(argv[2], NULL, 10);
    if (count < 128 || count > 10000000)
        return 2;
    char error[512] = {0};
    const size_t budget = 4U * 1024U * 1024U;
    YDDisk *disk = yd_disk_open(argv[1], true, budget, error, sizeof(error));
    if (!disk)
        return failure(NULL, error);
    const char *config =
        "{indexes: [{collection: items, name: number, fields: [number], unique: true}]}";
    YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
    if (!txn ||
        !yd_disk_indexes_replace(txn, (const unsigned char *)config, strlen(config), error,
                                 sizeof(error)) ||
        !yd_disk_commit(txn, error, sizeof(error)))
        return failure(disk, error);
    double started = seconds();
    for (unsigned b = 0; b < count; b += 128) {
        YDWrite writes[128] = {0};
        char ids[128][32], bodies[128][256];
        unsigned n = count - b < 128 ? count - b : 128;
        for (unsigned j = 0; j < n; j++) {
            unsigned i = b + j;
            snprintf(ids[j], sizeof(ids[j]), "d%09u", i);
            snprintf(bodies[j], sizeof(bodies[j]), "number: %u\nname: document-%u\nactive: true\n",
                     i, i);
            writes[j] = (YDWrite){.collection = "items",
                                  .document = ids[j],
                                  .body = (unsigned char *)bodies[j],
                                  .length = strlen(bodies[j])};
        }
        txn = yd_disk_begin(disk, error, sizeof(error));
        if (!txn || !yd_disk_apply(txn, writes, n, error, sizeof(error)) ||
            !yd_disk_commit(txn, error, sizeof(error)))
            return failure(disk, error);
        if ((b / 128) % 400 == 0) {
            fprintf(stderr, "inserted=%u elapsed=%.3f rss_peak_kib=%ld\n", b + n,
                    seconds() - started, resident_peak_kib());
            fflush(stderr);
        }
    }
    double ingest = seconds() - started;
    YDDiskView view = yd_disk_view(disk);
    if (view.documents != (uint64_t)count + 1)
        return failure(disk, "document count mismatch");
    char request[256];
    snprintf(request, sizeof(request),
             "{filter: {number: {$gte: %u}}, sort: {number: 1}, limit: 10, explain: true}",
             count - 20);
    YDValue *spec = yd_parse((const unsigned char *)request, strlen(request), error, sizeof(error));
    size_t size = 0;
    started = seconds();
    char *json =
        spec ? yd_disk_query(disk, &view, "items", spec, &size, error, sizeof(error)) : NULL;
    double query = seconds() - started;
    yd_free(spec);
    if (!json)
        return failure(disk, error);
    if (!strstr(json, "\"matched\":20") || !strstr(json, "\"documents_examined\":20")) {
        free(json);
        return failure(disk, "range query did not examine exactly 20 records");
    }
    free(json);
    YDDiskStats before = yd_disk_stats(disk);
    char id[32];
    snprintf(id, sizeof(id), "d%09u", count / 2);
    const unsigned char replacement[] = "number: -1\nname: updated\nactive: false\n";
    YDWrite write = {.collection = "items",
                     .document = id,
                     .body = replacement,
                     .length = sizeof(replacement) - 1};
    txn = yd_disk_begin(disk, error, sizeof(error));
    started = seconds();
    if (!txn || !yd_disk_apply(txn, &write, 1, error, sizeof(error)) ||
        !yd_disk_commit(txn, error, sizeof(error)))
        return failure(disk, error);
    double update = seconds() - started;
    YDDiskStats after = yd_disk_stats(disk);
    if (after.pages_written - before.pages_written > 128)
        return failure(disk, "one update rewrote too many tree pages");
    view = yd_disk_view(disk);
    uint64_t end = view.end, revision = view.revision;
    yd_disk_close(disk);
    started = seconds();
    disk = yd_disk_open(argv[1], false, budget, error, sizeof(error));
    double reopen = seconds() - started;
    if (!disk)
        return failure(NULL, error);
    view = yd_disk_view(disk);
    YDDiskDocument doc;
    if (view.revision != revision ||
        yd_disk_document_get(disk, &view, "items", id, &doc, error, sizeof(error)) != 1)
        return failure(disk, error);
    if (doc.length != sizeof(replacement) - 1 || memcmp(doc.body, replacement, doc.length))
        return failure(disk, "restart lost update");
    yd_disk_document_free(&doc);
    printf(
        "{\"documents\":%u,\"cache_budget\":%zu,\"cache_allocated\":%llu,\"file_bytes\":%llu,"
        "\"source_bytes\":%llu,\"ingest_seconds\":%.6f,\"documents_per_second\":%.3f,\"range_query_"
        "seconds\":%.6f,\"range_examined\":20,\"update_seconds\":%.6f,\"update_pages_written\":%"
        "llu,\"update_bytes_written\":%llu,\"reopen_seconds\":%.6f,\"peak_rss_kib\":%ld}\n",
        count, budget, (unsigned long long)after.cache_bytes, (unsigned long long)end,
        (unsigned long long)view.bytes, ingest, count / ingest, query, update,
        (unsigned long long)(after.pages_written - before.pages_written),
        (unsigned long long)(after.bytes_written - before.bytes_written), reopen,
        resident_peak_kib());
    yd_disk_close(disk);
    return 0;
}
