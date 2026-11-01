#define _GNU_SOURCE
#include "audit_custody.h"
#include "audit_helper_codec.h"
#include "audit_codec.h"
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define CHECK(label, condition) do { if (!(condition)) { fprintf(stderr, "ASSERTION:%s\n", label); _Exit(2); } } while (0)
static bool zero(const void *p, size_t n) { return !yd_audit_nonzero(p, n); }
static bool replace_published_inode;
int __real_renameat(int, const char *, int, const char *);
int __wrap_renameat(int source, const char *name, int destination, const char *target) {
    int r = __real_renameat(source, name, destination, target);
    if (r || !replace_published_inode) return r;
    replace_published_inode = false;
    int input = openat(destination, target, O_RDONLY | O_NOFOLLOW);
    unsigned char bytes[128];
    if (input < 0 || pread(input, bytes, 128, 0) != 128) _Exit(3);
    close(input);
    int output = openat(destination, "replacement.tmp", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (output < 0 || pwrite(output, bytes, 128, 0) != 128 || fsync(output)) _Exit(3);
    close(output);
    if (__real_renameat(destination, "replacement.tmp", destination, target)) _Exit(3);
    return 0;
}
int main(int argc, char **argv) {
    CHECK("USAGE", argc >= 2);
    if (!strcmp(argv[1], "wire")) {
        YDAuditPacket p = {.kind = YD_AUDIT_BEGIN, .id = 0x0102030405060708ULL,
            .event = {.wall_ms = 42, .transport = YD_AUDIT_HTTP, .authentication = YD_AUDIT_STATIC,
                .operation = YD_AUDIT_QUERY, .actor = "local-name"}}, out;
        unsigned char bytes[512], original[512];
        CHECK("PACKET_ENCODE", yd_audit_packet_encode(&p, bytes));
        CHECK("PACKET_INDEPENDENT_FRAME", !memcmp(bytes, "YDAUIP01\1\0\0\0\2\0\0\0\10\7\6\5\4\3\2\1\230\0\0\0", 28) &&
            bytes[32] == 42 && bytes[40] == YD_AUDIT_HTTP && bytes[44] == YD_AUDIT_STATIC &&
            bytes[48] == YD_AUDIT_QUERY && bytes[52] == 10 && !memcmp(bytes + 56, "local-name", 10) && zero(bytes + 66, 446));
        memcpy(original, bytes, 512);
        CHECK("PACKET_ROUNDTRIP", yd_audit_packet_decode(bytes, &out) && out.id == p.id && !strcmp(out.event.actor, "local-name"));
        const unsigned invalid[] = {0, 8, 12, 24, 28, 55, 66, 183, 184, 511};
        for (unsigned i = 0; i < sizeof(invalid) / sizeof(*invalid); i++) {
            memcpy(bytes, original, 512); bytes[invalid[i]] ^= 0x80;
            memset(&out, 0xaa, sizeof(out));
            CHECK("PACKET_INVALID_CLEARS_ALL_OUTPUT", !yd_audit_packet_decode(bytes, &out) && zero(&out, sizeof(out)));
        }
        for (unsigned category = YD_AUDIT_AWS; category <= YD_AUDIT_KERBEROS; category++) {
            p.event.authentication = category;
            CHECK("EXTERNAL_AUTH_CATEGORY", yd_audit_packet_encode(&p, bytes) &&
                yd_audit_packet_decode(bytes, &out) && out.event.authentication == category);
        }
        /* Runtime access management BEGIN is longer and carries its subject;
         * nothing else may, so an older helper rejects the new length. */
        YDAuditPacket managed = {.kind = YD_AUDIT_BEGIN, .id = 3,
            .event = {.wall_ms = 43, .transport = YD_AUDIT_HTTP, .authentication = YD_AUDIT_ADMIN_WRITE,
                .operation = YD_AUDIT_ACCESS_ROLE_PUT, .subject = "app-readers"}};
        CHECK("SUBJECT_PACKET_FRAME", yd_audit_packet_encode(&managed, bytes) && bytes[24] == 28 &&
            bytes[25] == 1 && bytes[52] == 0 && zero(bytes + 56, 128) && bytes[184] == 11 &&
            !memcmp(bytes + 188, "app-readers", 11) && zero(bytes + 199, 313));
        memcpy(original, bytes, 512);
        CHECK("SUBJECT_PACKET_ROUNDTRIP", yd_audit_packet_decode(bytes, &out) &&
            !strcmp(out.event.subject, "app-readers") && !out.event.actor[0] &&
            out.event.operation == YD_AUDIT_ACCESS_ROLE_PUT);
        const unsigned subject_invalid[] = {24, 25, 184, 188, 199, 315};
        for (unsigned i = 0; i < sizeof(subject_invalid) / sizeof(*subject_invalid); i++) {
            memcpy(bytes, original, 512); bytes[subject_invalid[i]] ^= 0x80;
            memset(&out, 0xaa, sizeof(out));
            CHECK("SUBJECT_PACKET_INVALID_CLEARS_ALL_OUTPUT",
                !yd_audit_packet_decode(bytes, &out) && zero(&out, sizeof(out)));
        }
        managed.event.subject[0] = 0;
        CHECK("SUBJECT_REQUIRED_FOR_MANAGEMENT", !yd_audit_packet_encode(&managed, bytes));
        managed.event.operation = YD_AUDIT_QUERY; memcpy(managed.event.subject, "x", 2);
        CHECK("SUBJECT_DENIED_FOR_ORDINARY_OPERATION", !yd_audit_packet_encode(&managed, bytes));
        managed.event.operation = YD_AUDIT_OPERATION_LAST + 1;
        CHECK("UNKNOWN_OPERATION_DENIED", !yd_audit_packet_encode(&managed, bytes));
        p = (YDAuditPacket){.kind = YD_AUDIT_FINISH_REQUEST, .id = 2, .handle = {1},
            .completion = {.outcome = YD_AUDIT_UNKNOWN, .has_revision = true, .revision = "0123456789abcdef"}};
        CHECK("FINISH_WIRE", yd_audit_packet_encode(&p, bytes) && yd_audit_packet_decode(bytes, &out) &&
            out.completion.outcome == YD_AUDIT_UNKNOWN && out.completion.has_revision);
        p.completion.revision[0] = 'X'; CHECK("FINISH_INVALID_REVISION", !yd_audit_packet_encode(&p, bytes));
        YDAuditHead h = {.version = 1, .key_id = {1}, .stream_id = {2}, .segment_id = {3}, .segment = 4, .sequence = 5, .mac = {6}}, decoded;
        unsigned char anchor[128];
        CHECK("ANCHOR_FRAME", yd_audit_anchor_encode(&h, anchor) && !memcmp(anchor, "YDAUAN01\1\0\0\0\200\0\0\0", 16) &&
            anchor[16] == 1 && anchor[32] == 2 && anchor[48] == 3 && anchor[64] == 4 && anchor[72] == 5 && anchor[80] == 6);
        CHECK("ANCHOR_ROUNDTRIP", yd_audit_anchor_decode(anchor, &decoded) && yd_audit_head_equal(&h, &decoded));
        anchor[127] = 1;
        CHECK("ANCHOR_RESERVED_DENIED", !yd_audit_anchor_decode(anchor, &decoded) && zero(&decoded, sizeof(decoded)));
    } else if (!strcmp(argv[1], "custody")) {
        CHECK("USAGE", argc == 3);
        uid_t daemon = geteuid() == 1000 ? 1001 : 1000;
        char key_path[4096], alias[4096], link_path[4096];
        snprintf(key_path, sizeof(key_path), "%s/key", argv[2]);
        snprintf(alias, sizeof(alias), "%s/alias", argv[2]);
        snprintf(link_path, sizeof(link_path), "%s/link", argv[2]);
        unsigned char key[32], actual[32]; memset(key, 0x42, 32);
        int fd = open(key_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        CHECK("KEY_FIXTURE", fd >= 0 && write(fd, key, 32) == 32 && !fsync(fd)); close(fd);
        CHECK("KEY_PROTECTED_READ_CONTROL", yd_audit_protected_key(key_path, daemon, actual) && !memcmp(key, actual, 32));
        CHECK("KEY_ALIAS_FIXTURE", !symlink("key", alias));
        memset(actual, 0xaa, 32);
        CHECK("KEY_SYMLINK_DENIED_AND_CLEARED", !yd_audit_protected_key(alias, daemon, actual) && zero(actual, 32));
        CHECK("KEY_LINK_FIXTURE", !link(key_path, link_path));
        CHECK("KEY_HARDLINK_DENIED", !yd_audit_protected_key(key_path, daemon, actual));
        CHECK("KEY_UNLINK_FIXTURE", !unlink(link_path));
        CHECK("KEY_MODE_FIXTURE", !chmod(key_path, 0644));
        CHECK("KEY_PUBLIC_READ_DENIED", !yd_audit_protected_key(key_path, daemon, actual));
        CHECK("KEY_MODE_RESTORE", !chmod(key_path, 0600));
        CHECK("KEY_WRONG_PEER_DENIED", !yd_audit_protected_key(key_path, geteuid(), actual));
        CHECK("DIRECTORY_ALIAS_FIXTURE", !unlink(alias) && !symlink(argv[2], alias));
        CHECK("ANCESTOR_SYMLINK_DENIED", yd_audit_protected_directory(alias, daemon) == -1);
        CHECK("ANCESTOR_MODE_FIXTURE", !chmod(argv[2], 0777));
        CHECK("UNPROTECTED_ANCESTOR_DENIED", !yd_audit_protected_key(key_path, daemon, actual));
        CHECK("ANCESTOR_MODE_RESTORE", !chmod(argv[2], 0700));
        CHECK("KEY_PROTECTED_READ_RESTORED", yd_audit_protected_key(key_path, daemon, actual) && !memcmp(key, actual, 32));
    } else {
        CHECK("USAGE", argc == 3);
        uid_t daemon = geteuid() == 1000 ? 1001 : 1000;
        YDAuditHead head = {.version = 1, .key_id = {1}, .stream_id = {2}, .segment_id = {3}, .segment = 1, .sequence = 1, .mac = {4}}, current;
        YDAuditAnchor *a = yd_audit_anchor_open(argv[2], daemon, true, &current);
        CHECK("ANCHOR_EXPLICIT_EMPTY_CREATE", a && zero(&current, sizeof(current)));
        CHECK("ANCHOR_DURABLE_PUBLISH", yd_audit_anchor_publish(a, &head));
        CHECK("ANCHOR_OWNER_EXCLUSION", !yd_audit_anchor_open(argv[2], daemon, false, &current));
        yd_audit_anchor_close(a);
        a = yd_audit_anchor_open(argv[2], daemon, false, &current);
        CHECK("ANCHOR_DURABLE_RESUME", a && yd_audit_head_equal(&head, &current));
        CHECK("ANCHOR_NO_ROLLBACK_OR_DUPLICATE", !yd_audit_anchor_publish(a, &head));
        head.sequence++; head.mac[0]++;
        if (!strcmp(argv[1], "publication-rebind")) {
            replace_published_inode = true;
            CHECK("ANCHOR_PUBLICATION_BINDS_CREATED_INODE", !yd_audit_anchor_publish(a, &head));
            CHECK("ANCHOR_REBIND_POISONS_OWNER", !yd_audit_anchor_publish(a, &head));
            yd_audit_anchor_close(a); puts("AUDIT_HELPER_OK"); return 0;
        }
        CHECK("ANCHOR_NEXT_PUBLICATION", yd_audit_anchor_publish(a, &head));
        char path[4096]; snprintf(path, sizeof(path), "%s/anchor-v1.yda", argv[2]);
        int fd = open(path, O_WRONLY | O_NOFOLLOW | O_CLOEXEC); unsigned char byte = 42;
        CHECK("FIXTURE_TAMPER", fd >= 0 && pwrite(fd, &byte, 1, 80) == 1 && !fsync(fd)); close(fd);
        head.sequence++;
        CHECK("ANCHOR_CHANGED_BYTES_POISON", !yd_audit_anchor_publish(a, &head));
        CHECK("ANCHOR_POISON_NO_RETRY", !yd_audit_anchor_publish(a, &head));
        yd_audit_anchor_close(a);
        snprintf(path, sizeof(path), "%s/anchor-next-orphan.tmp", argv[2]);
        fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600); CHECK("FIXTURE_ORPHAN", fd >= 0); close(fd);
        CHECK("ANCHOR_ORPHAN_REFUSES_RESTART", !yd_audit_anchor_open(argv[2], daemon, false, &current));
    }
    puts("AUDIT_HELPER_OK"); return 0;
}
