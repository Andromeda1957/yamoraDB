#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/application.h"
#include "../src/consensus/application_internal.h"
#include "../src/disk_changes.h"
#include "../src/disk_internal.h"
#include "../src/disk_log.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#define REQUIRE(x)                                                                                 \
    do {                                                                                           \
        if (!(x)) {                                                                                \
            fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error);                            \
            return 2;                                                                              \
        }                                                                                          \
    } while (0)
static char error[512];
static const unsigned char cluster[16] = {1, 2, 3, 4};
static const char target[] = "/v1/collections/config/documents/node";
static const unsigned char source[] = "# exact source\r\ncount: 0\r\nname: 'first' # keep\r\n";
static unsigned sync_calls, fail_sync;
int __real_fsync(int fd);
int __wrap_fsync(int fd) {
    if (++sync_calls == fail_sync) {
        errno = EIO;
        return -1;
    }
    return __real_fsync(fd);
}
static YDRaftWrite write_request(unsigned id, const char *method, const char *path,
                                 const unsigned char *body, size_t size) {
    YDRaftWrite w = {.method = method, .target = path, .body = body, .size = size};
    w.id[0] = (unsigned char)id;
    return w;
}
static YDRaftApplication *open_app(const char *path) {
    return yd_raft_application_open(path, cluster, 32768, error, sizeof(error));
}
static bool apply(YDRaftApplication *a, uint64_t index, uint64_t term, YDRaftProposal *p) {
    YDRaftEntry e = {.index = index,
                     .term = term,
                     .kind = p ? YD_RAFT_COMMAND : YD_RAFT_NOOP,
                     .command = p ? p->command : NULL,
                     .size = p ? p->size : 0};
    return yd_raft_application_apply(a, &e, error, sizeof(error));
}
static bool document(YDRaftApplication *a, const unsigned char *bytes, size_t size) {
    YDDisk *disk = yd_raft_application_disk(a);
    YDDiskView view = yd_disk_view(disk);
    YDDiskDocument doc;
    int found = yd_disk_document_get(disk, &view, "config", "node", &doc, error, sizeof(error));
    bool valid =
        bytes ? found == 1 && doc.length == size && !memcmp(doc.body, bytes, size) : found == 0;
    yd_disk_document_free(&doc);
    return valid;
}
static int basic(const char *root) {
    char paths[3][4096];
    YDRaftApplication *nodes[3];
    for (unsigned i = 0; i < 3; i++) {
        snprintf(paths[i], sizeof(paths[i]), "%s/node%u", root, i);
        REQUIRE(!mkdir(paths[i], 0700));
        nodes[i] = open_app(paths[i]);
        REQUIRE(nodes[i] && apply(nodes[i], 1, 1, NULL));
    }
    YDRaftWrite put = write_request(1, "PUT", target, source, sizeof(source) - 1);
    YDRaftProposal p;
    uint64_t generation = yd_disk_view(yd_raft_application_disk(nodes[0])).generation;
    REQUIRE(yd_raft_application_prepare(nodes[0], &put, &p, error, sizeof(error)) == 1 &&
            p.reply.status == 201);
    REQUIRE(document(nodes[0], NULL, 0));
    REQUIRE(yd_disk_view(yd_raft_application_disk(nodes[0])).generation == generation);
    char token[53] = {0};
    for (unsigned i = 0; i < 3; i++) {
        REQUIRE(apply(nodes[i], 2, 1, &p));
        REQUIRE(document(nodes[i], source, sizeof(source) - 1));
        YDDisk *disk = yd_raft_application_disk(nodes[i]);
        YDDiskView view = yd_disk_view(disk);
        YDDiskLog log;
        REQUIRE(yd_disk_log_load(disk, &view, &log, error, sizeof(error)) == 1);
        char actual[53];
        yd_disk_log_token(&log, log.last, actual);
        if (!i)
            memcpy(token, actual, sizeof(token));
        REQUIRE(!strcmp(token, actual));
        YDDiskReply receipt;
        REQUIRE(yd_raft_application_receipt(nodes[i], &put, &receipt, error, sizeof(error)) == 1);
        REQUIRE(receipt.status == 201 && receipt.length == p.reply.length &&
                !memcmp(receipt.body, p.reply.body, receipt.length));
        yd_disk_reply_free(&receipt);
    }
    yd_raft_proposal_free(&p);
    yd_raft_application_close(nodes[0]);
    nodes[0] = open_app(paths[0]);
    REQUIRE(nodes[0]);
    REQUIRE(yd_raft_application_prepare(nodes[0], &put, &p, error, sizeof(error)) == 0 &&
            !p.command && p.reply.status == 201);
    yd_raft_proposal_free(&p);
    put.body = (const unsigned char *)"count: 99\n";
    put.size = strlen((const char *)put.body);
    REQUIRE(yd_raft_application_prepare(nodes[0], &put, &p, error, sizeof(error)) == 0 &&
            p.reply.status == 409);
    yd_raft_proposal_free(&p);
    const unsigned char patch[] = "{\"$inc\":{\"count\":1}}";
    YDRaftWrite increment = write_request(2, "PATCH", target, patch, sizeof(patch) - 1);
    REQUIRE(yd_raft_application_prepare(nodes[0], &increment, &p, error, sizeof(error)) == 1);
    const unsigned char updated[] = "# exact source\r\ncount: 1\r\nname: 'first' # keep\r\n";
    for (unsigned i = 0; i < 3; i++) {
        REQUIRE(apply(nodes[i], 3, 2, &p));
        REQUIRE(apply(nodes[i], 3, 2, &p)); /* Exact replay at same position. */
        REQUIRE(apply(nodes[i], 4, 2, &p)); /* Duplicate request at later log index. */
        REQUIRE(document(nodes[i], updated, sizeof(updated) - 1));
    }
    yd_raft_proposal_free(&p);
    const char indexes[] = "{\"indexes\":[{\"collection\":\"config\",\"name\":\"count\",\"fields\":"
                           "[\"count\"],\"unique\":true}]}";
    YDRaftWrite catalog =
        write_request(3, "PUT", "/v1/indexes", (const unsigned char *)indexes, strlen(indexes));
    REQUIRE(yd_raft_application_prepare(nodes[1], &catalog, &p, error, sizeof(error)) == 1);
    for (unsigned i = 0; i < 3; i++)
        REQUIRE(apply(nodes[i], 5, 2, &p));
    yd_raft_proposal_free(&p);
    const char transaction[] = "{\"operations\":[{\"collection\":\"config\",\"document\":\"node\","
                               "\"patch\":{\"$inc\":{\"count\":1}}},{\"collection\":\"config\","
                               "\"document\":\"other\",\"put\":\"count: 3\\n\"}]}";
    YDRaftWrite batch = write_request(4, "POST", "/v1/transactions",
                                      (const unsigned char *)transaction, strlen(transaction));
    REQUIRE(yd_raft_application_prepare(nodes[2], &batch, &p, error, sizeof(error)) == 1);
    for (unsigned i = 0; i < 3; i++)
        REQUIRE(apply(nodes[i], 6, 2, &p));
    yd_raft_proposal_free(&p);
    const unsigned char collision[] = "count: 2\n";
    YDRaftWrite clash = write_request(5, "PUT", "/v1/collections/config/documents/clash", collision,
                                      sizeof(collision) - 1);
    REQUIRE(yd_raft_application_prepare(nodes[0], &clash, &p, error, sizeof(error)) == 0 &&
            p.reply.status == 409);
    yd_raft_proposal_free(&p);
    YDRaftWrite deletion = write_request(6, "DELETE", target, NULL, 0);
    REQUIRE(yd_raft_application_prepare(nodes[0], &deletion, &p, error, sizeof(error)) == 1 &&
            p.reply.status == 204);
    for (unsigned i = 0; i < 3; i++)
        REQUIRE(apply(nodes[i], 7, 2, &p));
    YDRaftProposal deletion_command = p;
    put = write_request(7, "PUT", target, source, sizeof(source) - 1);
    REQUIRE(yd_raft_application_prepare(nodes[1], &put, &p, error, sizeof(error)) == 1);
    for (unsigned i = 0; i < 3; i++) {
        REQUIRE(apply(nodes[i], 8, 2, &p));
        REQUIRE(apply(nodes[i], 9, 2, &deletion_command));
        REQUIRE(document(nodes[i], source, sizeof(source) - 1));
    }
    yd_raft_proposal_free(&p);
    yd_raft_proposal_free(&deletion_command);
    YDDiskReply feed = {0};
    for (unsigned i = 0; i < 3; i++) {
        YDDiskView view = yd_disk_view(yd_raft_application_disk(nodes[i]));
        /* The native index catalog is itself one reserved system document. */
        REQUIRE(view.documents == 3 && view.generation == 11);
        YDDiskReply actual =
            yd_disk_changes_request(yd_raft_application_disk(nodes[i]), &view, "/v1/changes");
        REQUIRE(actual.status == 200);
        if (!i)
            feed = actual;
        else {
            REQUIRE(actual.length == feed.length && !memcmp(actual.body, feed.body, actual.length));
            yd_disk_reply_free(&actual);
        }
        YDDiskIndexes *ix =
            yd_disk_indexes_load(yd_raft_application_disk(nodes[i]), &view, error, sizeof(error));
        REQUIRE(ix && ix->count == 1);
        yd_disk_indexes_free(ix);
        yd_raft_application_close(nodes[i]);
        REQUIRE(!yd_disk_open(paths[i], true, 32768, error, sizeof(error)));
        REQUIRE(!yd_disk_open(paths[i], false, 32768, error, sizeof(error)));
        unsigned char wrong[16] = {9};
        REQUIRE(!yd_raft_application_open(paths[i], wrong, 32768, error, sizeof(error)));
        nodes[i] = open_app(paths[i]);
        REQUIRE(nodes[i] && yd_raft_application_position(nodes[i]).index == 9);
        yd_raft_application_close(nodes[i]);
    }
    yd_disk_reply_free(&feed);
    return 0;
}
static int rejected(const char *root) {
    YDRaftApplication *a = open_app(root);
    REQUIRE(a && apply(a, 1, 1, NULL));
    const char *targets[] = {"/v1/index-builds",
                             "/v1/replication/begin",
                             "/v1/changes",
                             "/v1/query/config",
                             target,
                             target};
    const char *methods[] = {"POST", "POST", "GET", "POST", "PATCH", "PUT"};
    for (unsigned i = 0; i < 6; i++) {
        YDRaftWrite w =
            write_request(i + 1, methods[i], targets[i], (const unsigned char *)"not: [valid", 11);
        YDRaftProposal p;
        REQUIRE(yd_raft_application_prepare(a, &w, &p, error, sizeof(error)) == 0);
        REQUIRE(p.reply.status >= 400 && !p.command);
        yd_raft_proposal_free(&p);
        REQUIRE(yd_raft_application_position(a).index == 1 && document(a, NULL, 0));
    }
    yd_raft_application_close(a);
    return 0;
}
static int faults(const char *root) {
    for (unsigned fault = 1; fault <= 8; fault++) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/fault%u", root, fault);
        REQUIRE(!mkdir(path, 0700));
        YDRaftApplication *a = open_app(path);
        REQUIRE(a && apply(a, 1, 1, NULL));
        YDRaftWrite put = write_request(1, "PUT", target, source, sizeof(source) - 1);
        YDRaftProposal p;
        REQUIRE(yd_raft_application_prepare(a, &put, &p, error, sizeof(error)) == 1);
        REQUIRE(apply(a, 2, 1, &p));
        yd_raft_proposal_free(&p);
        const unsigned char patch[] = "{\"$inc\":{\"count\":1}}";
        YDRaftWrite increment = write_request(2, "PATCH", target, patch, sizeof(patch) - 1);
        REQUIRE(yd_raft_application_prepare(a, &increment, &p, error, sizeof(error)) == 1);
        const unsigned char updated[] = "# exact source\r\ncount: 1\r\nname: 'first' # keep\r\n";
        yd_raft_application_close(a);
        if (fault <= 2) {
            a = open_app(path);
            REQUIRE(a);
            sync_calls = 0;
            fail_sync = fault;
            REQUIRE(!apply(a, 3, 1, &p));
            fail_sync = 0;
            REQUIRE(!apply(a, 3, 1, &p));
            yd_raft_application_close(a);
        } else {
            pid_t child = fork();
            REQUIRE(child >= 0);
            if (!child) {
                a = open_app(path);
                if (!a)
                    _exit(5);
                char stage[8];
                snprintf(stage, sizeof(stage), "%u", fault - 2);
                if (setenv("YAMORA_DISK_KILL_AT", stage, 1))
                    _exit(6);
                (void)apply(a, 3, 1, &p);
                _exit(7);
            }
            int status;
            REQUIRE(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
                    WTERMSIG(status) == SIGKILL);
        }
        a = open_app(path);
        REQUIRE(a);
        uint64_t index = yd_raft_application_position(a).index;
        REQUIRE(index == 2 || index == 3);
        YDDiskReply receipt;
        int found = yd_raft_application_receipt(a, &increment, &receipt, error, sizeof(error));
        REQUIRE(found == (index == 3 ? 1 : 0));
        yd_disk_reply_free(&receipt);
        REQUIRE(document(a, index == 3 ? updated : source, sizeof(source) - 1));
        REQUIRE(apply(a, 3, 1, &p));
        REQUIRE(document(a, updated, sizeof(updated) - 1));
        yd_raft_application_close(a);
        yd_raft_proposal_free(&p);
    }
    return 0;
}
static int invalid(const char *root) {
    for (unsigned mutation = 0; mutation < 12; mutation++) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/bad%u", root, mutation);
        REQUIRE(!mkdir(path, 0700));
        YDRaftApplication *a = open_app(path);
        REQUIRE(a && apply(a, 1, 1, NULL));
        YDRaftWrite put = write_request(1, "PUT", target, source, sizeof(source) - 1);
        YDRaftProposal p;
        REQUIRE(yd_raft_application_prepare(a, &put, &p, error, sizeof(error)) == 1);
        YDRaftEntry e = {
            .index = 2, .term = 1, .kind = YD_RAFT_COMMAND, .command = p.command, .size = p.size};
        switch (mutation) {
        case 0:
            e.index = 3;
            break;
        case 1:
            e.term = 0;
            break;
        case 2:
            e.kind = (YDRaftKind)-1;
            break;
        case 3:
            p.command[0] ^= 1;
            break;
        case 4:
            p.command[88] = 1;
            break;
        case 5:
            p.command[24] ^= 1;
            break;
        case 6:
            p.command[56] ^= 1;
            break;
        case 7:
            p.command[64] ^= 1;
            break;
        case 8:
            memset(p.command + 72, 255, 8);
            break;
        case 9:
            memset(p.command + 80, 255, 8);
            break;
        case 10:
            p.command[p.size - 1] ^= 1;
            break;
        case 11:
            e.size--;
            break;
        }
        REQUIRE(!yd_raft_application_apply(a, &e, error, sizeof(error)));
        REQUIRE(yd_raft_application_position(a).index == 1 && document(a, NULL, 0));
        REQUIRE(!apply(a, 2, 1, NULL)); /* Fenced until restart. */
        yd_raft_application_close(a);
        yd_raft_proposal_free(&p);
    }
    return 0;
}
static int large(const char *root) {
    YDRaftApplication *a = open_app(root);
    REQUIRE(a && apply(a, 1, 1, NULL));
    size_t size = 3U * 1024U * 1024U;
    unsigned char *body = malloc(size);
    REQUIRE(body);
    memset(body, 'x', size);
    const char prefix[] = "# exact large source\r\ncount: 0\r\ntext: ";
    memcpy(body, prefix, sizeof(prefix) - 1);
    body[size - 2] = '\r';
    body[size - 1] = '\n';
    YDRaftWrite put = write_request(1, "PUT", target, body, size);
    YDRaftProposal p;
    REQUIRE(yd_raft_application_prepare(a, &put, &p, error, sizeof(error)) == 1);
    REQUIRE(document(a, NULL, 0) && apply(a, 2, 1, &p));
    REQUIRE(document(a, body, size));
    yd_raft_application_close(a);
    a = open_app(root);
    REQUIRE(a);
    YDRaftProposal retry;
    REQUIRE(yd_raft_application_prepare(a, &put, &retry, error, sizeof(error)) == 0);
    REQUIRE(retry.reply.status == 201 && apply(a, 3, 1, &p));
    REQUIRE(document(a, body, size));
    yd_raft_proposal_free(&retry);
    yd_raft_proposal_free(&p);
    yd_raft_application_close(a);
    free(body);
    return 0;
}
static bool rewrite(YDDisk *disk, const unsigned char *key, size_t kn, unsigned mutation,
                    bool receipt) {
    uint64_t offset = 0;
    YDDiskView view = yd_disk_view(disk);
    if (yd_disk_get(disk, &view, key, kn, &offset, error, sizeof(error)) != 1)
        return false;
    size_t n = 0;
    unsigned char *p = yd_disk_record(disk, &view, offset, &n, error, sizeof(error));
    if (!p || n < 96) {
        free(p);
        return false;
    }
    if (!receipt) {
        switch (mutation) {
        case 0:
            p[0] ^= 1;
            break;
        case 1:
            p[8] ^= 1;
            break;
        case 2:
            p[80] = 1;
            break;
        case 3:
            yd_disk_set64(p + 24, UINT64_MAX);
            break;
        case 4:
            yd_disk_set64(p + 24, 0);
            break;
        case 5:
            yd_disk_set64(p + 32, 0);
            break;
        case 6:
            p[40] ^= 1;
            break;
        case 7:
            memset(p + 48, 0, 32);
            break;
        }
    } else {
        switch (mutation) {
        case 0:
            p[0] ^= 1;
            break;
        case 1:
            p[64] ^= 1;
            break;
        case 2:
            yd_disk_set64(p + 40, 3);
            break;
        case 3:
            yd_disk_set64(p + 48, 2);
            break;
        case 4:
            yd_disk_set64(p + 56, UINT64_MAX);
            break;
        case 5:
            p[80 + 34] = 1;
            break;
        case 6:
            p[80 + 16] = 'g';
            break;
        }
    }
    uint32_t crc = yd_disk_crc(p, n);
    unsigned char encoded[4];
    for (unsigned i = 0; i < 4; i++)
        encoded[i] = (unsigned char)(crc >> (i * 8));
    bool valid = pwrite(disk->fd, p, n, (off_t)(offset + 16)) == (ssize_t)n &&
                 pwrite(disk->fd, encoded, 4, (off_t)(offset + 12)) == 4 && !fsync(disk->fd);
    free(p);
    return valid;
}
static int corrupt(const char *root) {
    for (unsigned type = 0; type < 2; type++) {
        for (unsigned mutation = 0; mutation < (type ? 7U : 8U); mutation++) {
            char path[4096];
            snprintf(path, sizeof(path), "%s/corrupt%u-%u", root, type, mutation);
            REQUIRE(!mkdir(path, 0700));
            YDRaftApplication *a = open_app(path);
            REQUIRE(a && apply(a, 1, 1, NULL));
            YDRaftWrite put = write_request(1, "PUT", target, source, sizeof(source) - 1);
            YDRaftProposal p;
            REQUIRE(yd_raft_application_prepare(a, &put, &p, error, sizeof(error)) == 1);
            REQUIRE(apply(a, 2, 1, &p));
            yd_raft_proposal_free(&p);
            unsigned char key[20] = {0, 'Y', 'R', type ? 'R' : 'A'};
            if (type)
                key[4] = 1;
            REQUIRE(rewrite(yd_raft_application_disk(a), key, type ? 20 : 4, mutation, type));
            yd_raft_application_close(a);
            a = open_app(path);
            if (!type)
                REQUIRE(!a);
            else {
                REQUIRE(a);
                YDDiskReply reply;
                REQUIRE(yd_raft_application_receipt(a, &put, &reply, error, sizeof(error)) == -1);
                yd_disk_reply_free(&reply);
                REQUIRE(!apply(a, 3, 1, NULL));
                yd_raft_application_close(a);
            }
        }
    }
    return 0;
}

typedef struct {
    YDRaftApplication *application;
    YDRaftProposal *proposal;
    bool applied, unlocked;
} Handoff;
static void *apply_handoff(void *context) {
    Handoff *h = context;
    h->applied = apply(h->application, 2, 1, h->proposal);
    YDDisk *disk = yd_raft_application_disk(h->application);
    h->unlocked = !pthread_mutex_trylock(&disk->writer);
    if (h->unlocked) pthread_mutex_unlock(&disk->writer);
    return NULL;
}
static int handoff(const char *root) {
    YDRaftApplication *a = open_app(root);
    REQUIRE(a && apply(a, 1, 1, NULL));
    YDDisk *disk = yd_raft_application_disk(a);
    pthread_mutexattr_t attr;
    REQUIRE(!pthread_mutexattr_init(&attr));
    REQUIRE(!pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK));
    REQUIRE(!pthread_mutex_destroy(&disk->writer));
    REQUIRE(!pthread_mutex_init(&disk->writer, &attr));
    REQUIRE(!pthread_mutexattr_destroy(&attr));
    YDRaftWrite put = write_request(1, "PUT", target, source, sizeof(source) - 1);
    YDDiskTxn *txn = NULL;
    YDDiskReply reply = yd_disk_api_prepare(disk, put.method, put.target,
        put.body, put.size, NULL, NULL, &txn);
    REQUIRE(txn && reply.status == 201);
    /* A builder-produced exclusive tree has this ownership state. */
    if (!txn->locked) {
        REQUIRE(!pthread_mutex_lock(&disk->writer));
        txn->locked = true;
    }
    txn->exclusive = true;
    REQUIRE(yd_raft_application_stage(a, &put, txn, &reply));
    yd_disk_reply_free(&reply);
    YDRaftProposal proposal;
    REQUIRE(yd_raft_application_prepare(a, &put, &proposal, error, sizeof(error)) == 1);
    Handoff h = {.application = a, .proposal = &proposal};
    pthread_t thread;
    REQUIRE(!pthread_create(&thread, NULL, apply_handoff, &h));
    REQUIRE(!pthread_join(thread, NULL));
    REQUIRE(h.applied && h.unlocked && document(a, source, sizeof(source) - 1));
    yd_raft_proposal_free(&proposal);
    yd_raft_application_close(a);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3)
        return 1;
    if (!strcmp(argv[2], "handoff"))
        return handoff(argv[1]);
    if (!strcmp(argv[2], "large"))
        return large(argv[1]);
    if (!strcmp(argv[2], "corrupt"))
        return corrupt(argv[1]);
    if (!strcmp(argv[2], "basic"))
        return basic(argv[1]);
    if (!strcmp(argv[2], "rejected"))
        return rejected(argv[1]);
    if (!strcmp(argv[2], "faults"))
        return faults(argv[1]);
    if (!strcmp(argv[2], "invalid"))
        return invalid(argv[1]);
    return 1;
}
