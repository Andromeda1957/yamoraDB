#define _POSIX_C_SOURCE 200809L
#include "../src/aggregate.h"
#include "../src/aggregate_spill.h"
#include "../src/disk_aggregate.h"
#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int corrupt(const char *root) {
    char error[512] = {0};
    YDDisk *disk = yd_disk_open(root, true, 65536, error, sizeof(error));
    if (!disk)
        return 1;
    YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
    const char *body = "value: 7\n";
    YDWrite write = {.collection = "other",
                     .document = "one",
                     .body = (const unsigned char *)body,
                     .length = strlen(body)};
    bool ok = txn && yd_disk_apply(txn, &write, 1, error, sizeof(error));
    if (ok)
        ok = yd_disk_commit(txn, error, sizeof(error));
    else
        yd_disk_abort(txn);
    YDDiskView view = yd_disk_view(disk);
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t kn = yd_disk_document_key(key, "other", "one");
    uint64_t record;
    ok = ok && yd_disk_get(disk, &view, key, kn, &record, error, sizeof(error)) == 1;
    txn = ok ? yd_disk_begin(disk, error, sizeof(error)) : NULL;
    kn = yd_disk_document_key(key, "selected", "one");
    ok = txn && yd_disk_put(txn, key, kn, record, error, sizeof(error));
    if (ok)
        ok = yd_disk_commit(txn, error, sizeof(error));
    else
        yd_disk_abort(txn);
    const char *request = "{pipeline: [{$count: n}]}";
    YDValue *spec =
        yd_parse_request((const unsigned char *)request, strlen(request), error, sizeof(error));
    view = yd_disk_view(disk);
    size_t n;
    char *json = ok && spec
                     ? yd_disk_aggregate(disk, &view, "selected", spec, &n, error, sizeof(error))
                     : NULL;
    bool rejected = ok && spec && !json && strstr(error, "key/record mismatch");
    free(json);
    yd_free(spec);
    yd_disk_close(disk);
    if (!rejected)
        fprintf(stderr, "corrupt primary reference accepted: %s\n", error);
    return rejected ? 0 : 1;
}

/* One store of 1024 documents, with or without the indexes the planner may
 * choose. Every fifth document lacks group; tags repeat a value (multikey). */
static YDDisk *seed(const char *path, bool indexed, char *error, size_t length) {
    YDDisk *disk = yd_disk_open(path, true, 65536, error, length);
    if (!disk)
        return NULL;
    for (unsigned b = 0; b < 16; b++) {
        YDWrite writes[64] = {0};
        char ids[64][32], bodies[64][256];
        for (unsigned j = 0; j < 64; j++) {
            unsigned i = b * 64 + j;
            snprintf(ids[j], sizeof(ids[j]), "d%04u", i);
            int n = snprintf(bodies[j], sizeof(bodies[j]),
                             "number: %u\nrank: %u\nfraction: %.17g\ntags: [a, t%u, a]\n", i,
                             (i * 389U) % 1024U, i * 0.1 + 1e-3, i % 3);
            if (i % 5)
                snprintf(bodies[j] + n, sizeof(bodies[j]) - (size_t)n, "group: %u\n", i % 7);
            writes[j] = (YDWrite){.collection = "items",
                                  .document = ids[j],
                                  .body = (unsigned char *)bodies[j],
                                  .length = strlen(bodies[j])};
        }
        YDDiskTxn *txn = yd_disk_begin(disk, error, length);
        if (!txn || !yd_disk_apply(txn, writes, 64, error, length) ||
            !yd_disk_commit(txn, error, length)) {
            if (txn)
                yd_disk_abort(txn);
            yd_disk_close(disk);
            return NULL;
        }
    }
    if (indexed) {
        const char *spec = "{indexes: [{collection: items, name: number, fields: [number]}, "
                           "{collection: items, name: rank, fields: [rank]}, "
                           "{collection: items, name: group, fields: [group]}, "
                           "{collection: items, name: tags, fields: [tags]}, "
                           "{collection: items, name: compound, fields: [group, number]}]}";
        YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, length);
        if (!txn ||
            !yd_disk_indexes_replace(txn, (const unsigned char *)spec, strlen(spec), error,
                                     length) ||
            !yd_disk_commit(txn, error, length)) {
            if (txn)
                yd_disk_abort(txn);
            yd_disk_close(disk);
            return NULL;
        }
    }
    return disk;
}

/* For each request, print the indexed store's envelope, then the unindexed
 * store's, one line each; a failed request prints "ERROR message". */
static int index_input(const char *root, const char *requests) {
    char error[512] = {0}, indexed_path[PATH_MAX], plain_path[PATH_MAX];
    snprintf(indexed_path, sizeof(indexed_path), "%s/indexed", root);
    snprintf(plain_path, sizeof(plain_path), "%s/plain", root);
    YDValue *list =
        yd_parse_request((const unsigned char *)requests, strlen(requests), error, sizeof(error));
    YDDisk *stores[2] = {seed(indexed_path, true, error, sizeof(error)), NULL};
    if (stores[0])
        stores[1] = seed(plain_path, false, error, sizeof(error));
    if (!list || list->type != YD_ARRAY || !stores[0] || !stores[1]) {
        fprintf(stderr, "%s\n", error);
        yd_free(list);
        for (int s = 0; s < 2; s++)
            if (stores[s])
                yd_disk_close(stores[s]);
        return 1;
    }
    for (size_t i = 0; i < list->count; i++)
        for (int s = 0; s < 2; s++) {
            YDDiskView view = yd_disk_view(stores[s]);
            size_t n = 0;
            char *json = yd_disk_aggregate(stores[s], &view, "items", list->items[i], &n, error,
                                           sizeof(error));
            if (json)
                printf("%s\n", json);
            else
                printf("ERROR %s\n", error);
            free(json);
        }
    yd_free(list);
    yd_disk_close(stores[0]);
    yd_disk_close(stores[1]);
    return 0;
}

/* Stream synthetic models without retaining an input array or writing fixtures. */
static bool feed(YDAggregate *a, size_t count, size_t groups, size_t width, char *error,
                 size_t length) {
    char *text = width ? malloc(width + 1) : NULL;
    if (width && !text)
        return false;
    char *keys[] = {"key", "value", "fraction"};
    YDValue key = {0}, value = {.type = YD_INT}, fraction = {.type = YD_FLOAT};
    YDValue *items[] = {&key, &value, &fraction};
    YDValue document = {.type = YD_MAP, .keys = keys, .items = items, .count = 3};
    bool ok = true;
    for (size_t i = 0; ok && i < count; i++) {
        char key_number[32], number[32];
        snprintf(number, sizeof(number), "%zu", i);
        value.scalar = number;
        value.number = i;
        /* Order-sensitive floating sums prove replay order, not just totals. */
        fraction.number = (long double)i * 0.1L + 0.001L;
        snprintf(key_number, sizeof(key_number), "%zu", i % groups);
        if (width) {
            memset(text, 'x', width);
            memcpy(text, key_number, strlen(key_number));
            text[width] = 0;
            key = (YDValue){.type = YD_STRING, .scalar = text};
        } else
            key = (YDValue){.type = YD_INT, .scalar = key_number, .number = i % groups};
        ok = yd_aggregate_feed(a, &document, error, length);
    }
    free(text);
    return ok;
}

/* Names currently present in the spill directory. */
static size_t directory_entries(const char *directory) {
    DIR *listing = opendir(directory);
    size_t count = 0;
    struct dirent *entry;
    while (listing && (entry = readdir(listing)))
        count += strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..");
    if (listing)
        closedir(listing);
    return count;
}

/* Count this process's descriptors on files inside the spill directory and
 * report whether any holds a run of 16 'x' bytes, the synthetic key text, or
 * is still linked or readable by group or others. */
static void spill_files(const char *directory, size_t *files, bool *plaintext, bool *exposed) {
    *files = 0;
    *plaintext = false;
    *exposed = false;
    DIR *fds = opendir("/proc/self/fd");
    if (!fds)
        return;
    size_t dn = strlen(directory);
    struct dirent *entry;
    while ((entry = readdir(fds))) {
        if (entry->d_name[0] == '.')
            continue;
        char link[sizeof("/proc/self/fd/") + sizeof(entry->d_name)], target[PATH_MAX + 32];
        snprintf(link, sizeof(link), "/proc/self/fd/%s", entry->d_name);
        ssize_t n = readlink(link, target, sizeof(target) - 1);
        if (n <= 0)
            continue;
        target[n] = 0;
        if (strncmp(target, directory, dn) || target[dn] != '/')
            continue;
        (*files)++;
        int fd = atoi(entry->d_name);
        struct stat st;
        if (fstat(fd, &st) || st.st_nlink || (st.st_mode & 077))
            *exposed = true;
        unsigned char block[65536];
        off_t at = 0;
        size_t run = 0;
        ssize_t got;
        while ((got = pread(fd, block, sizeof(block), at)) > 0) {
            for (ssize_t i = 0; i < got; i++) {
                run = block[i] == 'x' ? run + 1 : 0;
                if (run >= 16)
                    *plaintext = true;
            }
            at += got;
        }
    }
    closedir(fds);
}

static int hold_order(const YDValue *left, const YDValue *right, void *context) {
    (void)left;
    (void)right;
    (void)context;
    return 0;
}

/* Consume server-wide spill bytes from another live request. */
static YDSpill *hold_spill(unsigned long long bytes, char *error, size_t length) {
    YDSpill *spill = yd_spill_open(0, error, length);
    YDSpillHooks hooks = {.compare = hold_order};
    YDSpillSorter *sorter = spill ? yd_spill_sorter_new(spill, &hooks, 0, error, length) : NULL;
    char filler[1024];
    memset(filler, 'h', sizeof(filler) - 1);
    filler[sizeof(filler) - 1] = 0;
    bool ok = sorter != NULL;
    while (ok && yd_spill_bytes(spill) < bytes) {
        YDValue text = {.type = YD_STRING, .scalar = filler}, *items[] = {&text};
        YDValue record = {.type = YD_ARRAY, .items = items, .count = 1};
        YDValue *owned = yd_clone(&record);
        ok = owned && yd_spill_sorter_add(sorter, owned, error, length) &&
             yd_spill_sorter_flush(sorter, 0, error, length);
    }
    yd_spill_sorter_free(sorter);
    if (!ok) {
        yd_spill_close(spill);
        return NULL;
    }
    return spill;
}

static int run(int argc, char **argv, const char *spill_directory) {
    char error[512] = {0};
    const char *pipeline = argv[argc - 4];
    size_t count = strtoul(argv[argc - 3], NULL, 10), groups = strtoul(argv[argc - 2], NULL, 10),
           width = strtoul(argv[argc - 1], NULL, 10);
    if (!groups || count > 5000000 || width > 65536)
        return 1;
    YDSpill *held = NULL;
    if (spill_directory && strcmp(spill_directory, "-") &&
        !yd_aggregate_spill_configure(spill_directory, strtoull(argv[3], NULL, 10),
                                      strtoull(argv[4], NULL, 10), strtoul(argv[5], NULL, 10),
                                      error, sizeof(error))) {
        fprintf(stderr, "%s\n", error);
        return 2;
    }
    if (spill_directory && strtoull(argv[7], NULL, 10) &&
        !(held = hold_spill(strtoull(argv[7], NULL, 10), error, sizeof(error)))) {
        fprintf(stderr, "%s\n", error);
        return 2;
    }
    YDValue *spec =
        yd_parse_request((const unsigned char *)pipeline, strlen(pipeline), error, sizeof(error));
    YDAggregate *a = spec ? yd_aggregate_new(spec, error, sizeof(error)) : NULL;
    bool ok = a != NULL;
    if (ok && spill_directory)
        ok = yd_aggregate_allow_disk_use(a, strtoull(argv[6], NULL, 10), error, sizeof(error));
    if (ok)
        ok = feed(a, count, groups, width, error, sizeof(error));
    fprintf(stderr, "state_bytes=%zu\n", yd_aggregate_memory(a));
    size_t size;
    char *output = ok ? yd_aggregate_json(a, &size, error, sizeof(error)) : NULL;
    if (output)
        fwrite(output, 1, size, stdout);
    else
        fprintf(stderr, "%s\n", error);
    if (spill_directory && strcmp(spill_directory, "-")) {
        size_t files = 0;
        bool plaintext = false, exposed = false;
        spill_files(spill_directory, &files, &plaintext, &exposed);
        char *explain = a ? yd_aggregate_explain_json(a, error, sizeof(error)) : NULL;
        fprintf(stderr, "spill_files=%zu plaintext=%d exposed=%d entries=%zu\nexplain=%s\n", files,
                plaintext, exposed, directory_entries(spill_directory), explain ? explain : "null");
        free(explain);
    }
    free(output);
    yd_aggregate_free(a);
    yd_spill_close(held);
    yd_free(spec);
    if (spill_directory && strcmp(spill_directory, "-")) {
        size_t files = 0;
        bool plaintext = false, exposed = false;
        spill_files(spill_directory, &files, &plaintext, &exposed);
        fprintf(stderr, "closed_files=%zu in_use=%llu\n", files, yd_aggregate_spill_in_use());
        yd_aggregate_spill_shutdown();
    }
    return output ? 0 : 2;
}

/* PIPELINE COUNT GROUPS WIDTH reduces in memory. --spill DIR TOTAL REQUEST
 * MEMORY MAXBYTES HOLD PIPELINE COUNT GROUPS WIDTH configures a private spill
 * directory ("-" leaves disk use unconfigured) and allows disk use. */
int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "--corrupt"))
        return corrupt(argv[2]);
    if (argc == 4 && !strcmp(argv[1], "--index-input"))
        return index_input(argv[2], argv[3]);
    if (argc == 12 && !strcmp(argv[1], "--spill"))
        return run(argc, argv, argv[2]);
    if (argc != 5)
        return 1;
    return run(argc, argv, NULL);
}
