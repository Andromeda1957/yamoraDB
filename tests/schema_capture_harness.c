/* Reuse the actual three-voter seed and cleanup, including its real policy
 * publication/replacement. This fixture creates no alternate Raft authority. */
#ifndef YAMORA_SCHEMA_CAPTURE_SEED
#define YAMORA_SCHEMA_CAPTURE_SEED "cluster_backup_fixture.c"
#endif
#define main schema_capture_seed_main
#include YAMORA_SCHEMA_CAPTURE_SEED
#undef main
#include "consensus/application_copy.h"

int main(int argc, char **argv) {
    if (argc != 4 || (strcmp(argv[2], "3") && strcmp(argv[2], "7"))) return 2;
    bool application = !strcmp(argv[3], "application");
    bool checkpoint = !strcmp(argv[3], "checkpoint");
    bool image_checkpoint = !strcmp(argv[3], "image-checkpoint");
    bool snapshot = !strcmp(argv[3], "snapshot");
    bool backup = !strcmp(argv[3], "backup");
    if (!application && !checkpoint && !image_checkpoint && !snapshot && !backup) return 2;
    int original;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &original)) return 2;
    capabilities = !strcmp(argv[2], "3") ? 3 : 7;
    bool seeded = seed(argv[1]);
    YDRaftApplicationCapture *source_capture = NULL;
    YDRaftApplicationImage *copied = NULL;
    bool prepared = seeded;
    if (prepared && image_checkpoint) {
        char destination[4096];
        source_capture = yd_raft_application_capture(apps[0], 32768, error, sizeof(error));
        int directory = source_capture && directory_new(destination, argv[1], "copied-image")
            ? open(destination, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
        copied = directory >= 0 ? yd_raft_application_copy(source_capture, directory, 32768,
            NULL, NULL, error, sizeof(error)) : NULL;
        prepared = copied != NULL;
        if (directory >= 0 && close(directory)) prepared = false;
    }
    YDRaftApplicationCapture *captured = NULL;
    YDDiskCheckpoint *physical = NULL;
    YDRaftCheckpoint position = {0};
    YDRaftSnapshot *image = NULL;
    YDRaftBackup *bundle = NULL;
    bool adopted = false, caller_state = false, identity = false;
    if (prepared && !pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)) {
        if (application)
            captured = yd_raft_application_capture(apps[0], 32768, error, sizeof(error));
        else if (checkpoint)
            physical = yd_raft_application_checkpoint(apps[0], &position, error, sizeof(error));
        else if (image_checkpoint)
            physical = yd_raft_application_image_checkpoint(copied, &position, error, sizeof(error));
        else if (snapshot)
            image = yd_raft_snapshot_open(apps[0], 3, error, sizeof(error));
        else
            bundle = yd_raft_backup_capture(nodes[0], apps[0], nodes[0]->configuration_base,
                32768, error, sizeof(error));
        int returned;
        if (!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &returned))
            caller_state = returned == PTHREAD_CANCEL_ENABLE;
        adopted = captured || physical || image || bundle;
        if (captured) {
            YDRaftApplicationCopyInfo info = yd_raft_application_capture_info(captured);
            identity = info.checkpoint.capabilities == capabilities &&
                info.source.capabilities == capabilities && info.source.format == 8;
        } else if (physical) {
            YDDiskView view = yd_disk_checkpoint_view(physical);
            identity = position.capabilities == capabilities &&
                view.capabilities == capabilities && view.format == 8 &&
                view.generation == position.applied.index + 2;
        } else if (image) {
            unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST];
            YDRaftSnapshotInfo info;
            identity = yd_raft_snapshot_seal(image, NULL, NULL, error, sizeof(error)) &&
                yd_raft_snapshot_manifest(image, manifest) &&
                yd_raft_snapshot_decode(manifest, sizeof(manifest), cluster, 3, &info,
                    error, sizeof(error)) &&
                info.view.capabilities == capabilities && info.view.format == 8;
        } else identity = bundle != NULL;
    }
    /* Always clean first, including an ordinary NULL-factory RED. A failing
     * assertion must not be manufactured from a leaked seed or sanitizer exit. */
    (void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    yd_raft_application_capture_close(captured);
    yd_disk_checkpoint_close(physical);
    yd_raft_snapshot_close(image);
    yd_raft_backup_close(bundle);
    yd_raft_application_image_close(copied);
    yd_raft_application_capture_close(source_capture);
    close_all();
    yd_disk_reply_free(&policy_original);
    int restored = pthread_setcancelstate(original, NULL);
    if (!prepared) {
        fprintf(stderr, "schema capture seed or copied image setup failed: %s\n", error);
        return 2;
    }
    if (!adopted || !caller_state || !identity || restored) {
        fprintf(stderr, "schema capture assertion [%s capabilities=%u]: "
            "adopted=%d caller_state_preserved=%d identity=%d restored=%d (%s)\n",
            argv[3], capabilities, adopted, caller_state, identity, restored, error);
        return 1;
    }
    printf("schema capture GREEN [%s capabilities=%u]: caller state and identity preserved\n",
        argv[3], capabilities);
    return 0;
}
