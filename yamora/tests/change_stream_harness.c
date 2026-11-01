#define _POSIX_C_SOURCE 200809L
#include "../src/transport/change_stream.h"
#include "../src/disk_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static YDDisk *database;
static FILE *wire;
static bool injected;
static bool put(unsigned n) {
    char text[64], error[256];
    int size = snprintf(text, sizeof(text), "v: %u\n", n);
    YDWrite write = {.collection="items", .document="one", .body=(const unsigned char *)text, .length=(size_t)size};
    YDDiskTxn *txn = yd_disk_begin(database, error, sizeof(error));
    if (!txn) return false;
    if (!yd_disk_apply(txn, &write, 1, error, sizeof(error))) { yd_disk_abort(txn); return false; }
    return yd_disk_commit(txn, error, sizeof(error));
}
bool yd_connection_send(YDConnection *connection, const void *data, size_t size) {
    (void)connection;
    if (fwrite(data, 1, size, wire) != size) return false;
    const char prefix[] = "{\"transactions\":[";
    if (!injected && size >= sizeof(prefix)-1 && !memcmp(data,prefix,sizeof(prefix)-1)) {
        injected = true;
        /* Retain only one commit. The initial page remains pinned and valid,
         * while its resume position expires before the next page is built. */
        return put(2) && put(3) && put(4);
    }
    return true;
}
int main(int argc, char **argv) {
    if (argc!=2) return 1;
    char error[256];
    database = yd_disk_open(argv[1], true, 32768, error, sizeof(error));
    if (!database || !put(1)) return 2;
    YDDiskLog log;
    YDDiskView view = yd_disk_view(database);
    if (yd_disk_log_load(database,&view,&log,error,sizeof(error))!=1) return 3;
    char token[53], target[256];
    yd_disk_log_token(&log,log.last,token);
    snprintf(target,sizeof(target),"/v1/changes/stream?after=%s&duration_ms=1000&heartbeat_ms=100",token);
    YDDiskReply failed = {0};
    YDChangeStream *stream = yd_change_stream_open(database,target,&failed);
    if (!stream) return 4;
    wire = stdout;
    volatile sig_atomic_t running = 1;
    YDConnection connection = {0}; size_t bytes=0;
    bool valid = yd_change_stream_send(stream,&connection,&running,&bytes);
    yd_change_stream_free(stream); yd_disk_close(database);
    return valid && injected && bytes ? 0 : 5;
}
