/* Exercise the real HTTP formatter without a daemon or a mutable controller. */
#define main yd_unused_daemon_main
#include "../src/daemon.c"
#undef main
#include <limits.h>

YDRaftClusterStatus yd_raft_cluster_status(YDRaftCluster *cluster) {
    (void)cluster;
    return (YDRaftClusterStatus){
        .raft = {.node = UINT_MAX, .leader = UINT_MAX, .term = UINT64_MAX,
            .role = YD_RAFT_FAILED, .voters = UINT_MAX, .last = UINT64_MAX, .committed = UINT64_MAX},
        .applied = {.index = UINT64_MAX}, .failed = true,
        .checkpoints = {true, true, UINT64_MAX, UINT64_MAX, UINT64_MAX},
        .compaction = {true, true, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX,
            UINT64_MAX, UINT64_MAX, UINT64_MAX, INT_MAX},
        .application_compaction = {
            .enabled = true, .running = true, .published = true, .pending = true,
            .blocked = true, .timed_out = true, .history_full = true,
            .attempted = UINT64_MAX, .reconciled = UINT64_MAX, .publications = UINT64_MAX,
            .retired = UINT64_MAX, .retained = SIZE_MAX, .stop = YD_RAFT_APPLICATION_WORKER_STOPPED,
            .result = INT_MAX, .selection = INT_MAX, .admission = INT_MAX,
            .source_bytes = UINT64_MAX, .saved_bytes = UINT64_MAX,
            .retained_bytes = UINT64_MAX, .reserved_bytes = UINT64_MAX,
            .image_high_water = UINT64_MAX, .archive_high_water = UINT64_MAX,
            .restore_high_water = UINT64_MAX}
    };
}
bool yd_connection_send(YDConnection *connection, const void *bytes, size_t length) {
    (void)connection;
    return fwrite(bytes, 1, length, stdout) == length;
}
YDRaftClusterStorage yd_raft_cluster_storage(YDRaftCluster *cluster) {
    (void)cluster; return (YDRaftClusterStorage){0};
}
YDDiskView yd_disk_view(YDDisk *disk) { (void)disk; return (YDDiskView){0}; }
void yd_disk_revision(const YDDiskView *view, char output[17]) {
    (void)view; memcpy(output, "0000000000000000", 17);
}
int main(int argc, char **argv) {
    (void)argv;
    YamlDBSnapshot snapshot = {0};
    memcpy(snapshot.revision, "0000000000000000", 17);
    Server server = {0};
    server.engine.snapshot = &snapshot;
    YDConnection connection = {0};
    Request request = {0};
    serve_cluster_status(&server, &connection, &request, argc == 1);
    return ferror(stdout) ? 1 : 0;
}
