/* Standalone behavioral driver; only tests link its fsync fault/crash hook. */
#define _POSIX_C_SOURCE 200809L
#include "../src/journal.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int __real_fsync(int descriptor);
int __wrap_fsync(int descriptor)
{
    static unsigned long calls;
    calls++;
    const char *fail = getenv("YAMLDB_TEST_FAIL_FSYNC_CALL");
    if (fail != NULL && calls == strtoul(fail, NULL, 10)) {
        errno = EIO;
        return -1;
    }
    int result = __real_fsync(descriptor);
    const char *stop = getenv("YAMLDB_TEST_STOP_FSYNC_CALL");
    if (result == 0 && stop != NULL && calls == strtoul(stop, NULL, 10)) {
        (void)puts("STOPPED");
        (void)fflush(stdout);
        for (;;) {
            (void)pause();
        }
    }
    return result;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        return 2;
    }
    char error[256] = {0};
    bool committed = false;
    bool success = false;
    if (strcmp(argv[2], "recover-rw") == 0 || strcmp(argv[2], "recover-ro") == 0) {
        success = yd_journal_recover(argv[1], strcmp(argv[2], "recover-rw") == 0,
                                     error, sizeof(error));
    } else {
        YDWrite writes[4] = {
            {.collection = "items", .document = "alpha", .body = (const unsigned char *)"value: new-alpha\n", .length = 17},
            {.collection = "items", .document = "beta", .body = (const unsigned char *)"value: new-beta\n", .length = 16},
            {.collection = "items", .document = "gone"},
        };
        size_t count = 3;
        YDWrite *allocated = NULL;
        unsigned char *body = NULL;
        if (strcmp(argv[2], "one") == 0 && argc == 5) {
            writes[0].collection = argv[3];
            writes[0].document = argv[4];
            count = 1;
        } else if (strcmp(argv[2], "collections") == 0) {
            writes[0] = (YDWrite){.collection = "new-empty", .kind = YD_WRITE_CREATE_COLLECTION};
            writes[1] = (YDWrite){.collection = "old-empty", .kind = YD_WRITE_DELETE_COLLECTION};
            count = 2;
        } else if (strcmp(argv[2], "many") == 0 && argc == 4) {
            count = (size_t)strtoul(argv[3], NULL, 10);
            if (count > YD_JOURNAL_OPERATION_LIMIT + 1u) {
                return 2;
            }
            allocated = calloc(count, sizeof(*allocated));
            if (allocated == NULL) {
                return 2;
            }
            for (size_t index = 0; index < count; index++) {
                allocated[index] = (YDWrite){.collection = "empty", .kind = YD_WRITE_CREATE_COLLECTION};
            }
        } else if (strcmp(argv[2], "oversized") == 0) {
            writes[0].length = YD_JOURNAL_BODY_LIMIT + 1u;
            count = 1;
        } else if (strcmp(argv[2], "bad-body") == 0) {
            writes[0].body = (const unsigned char *)"value:\0bad";
            writes[0].length = 10;
            count = 1;
        } else if (strcmp(argv[2], "zero") == 0) {
            count = 0;
        } else if (strcmp(argv[2], "large") == 0 || strcmp(argv[2], "over-total") == 0) {
            const size_t length = 256u * 1024u;
            body = malloc(length);
            if (body == NULL) {
                return 2;
            }
            memset(body, 'a', length);
            writes[0].body = body;
            writes[0].length = length;
            writes[1].body = body;
            writes[1].length = length;
            count = 2;
            if (strcmp(argv[2], "over-total") == 0) {
                count = YD_JOURNAL_BODY_LIMIT / length + 1u;
                allocated = calloc(count, sizeof(*allocated));
                if (allocated == NULL) {
                    free(body);
                    return 2;
                }
                for (size_t index = 0; index < count; index++) {
                    allocated[index] = writes[0];
                }
            }
        } else if (strcmp(argv[2], "commit") != 0) {
            return 2;
        }
        success = yd_journal_commit(argv[1], allocated == NULL ? writes : allocated,
                                    count, &committed, error, sizeof(error));
        free(allocated);
        free(body);
    }
    (void)printf("success=%d committed=%d error=%s\n", success, committed, error);
    return success ? 0 : 1;
}
