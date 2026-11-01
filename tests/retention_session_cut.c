#define _GNU_SOURCE
#include "disk_internal.h"
#include "journal_scope.h"
#include "retention_session_owner.h"
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Integration only: a caller-supplied CLEAN hash is data, not lifecycle proof.
 */
#define CHECK(x, name)                                                         \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "SESSION_CUT_ASSERT:%s\n", name);                        \
      _Exit(2);                                                                \
    }                                                                          \
  } while (0)
static bool inside_cut, fail_sync, fail_control, control_triggered;
static unsigned control_reads;
static struct stat control_identity;
ssize_t __real_pread(int, void *, size_t, off_t);
ssize_t __wrap_pread(int fd, void *bytes, size_t size, off_t offset) {
  struct stat s;
  if (inside_cut && fail_control && !offset && !fstat(fd, &s) &&
      s.st_dev == control_identity.st_dev && s.st_ino == control_identity.st_ino &&
      ++control_reads == 5) {
    control_triggered = true; errno = EIO; return -1;
  }
  return __real_pread(fd, bytes, size, offset);
}
int __real_fcntl(int, int, ...);
int __wrap_fcntl(int fd, int command, ...) {
  va_list args; va_start(args, command);
  int result;
  if (command == F_OFD_SETLK || command == F_OFD_SETLKW || command == F_OFD_GETLK) {
    struct flock *lock = va_arg(args, struct flock *);
    CHECK(!(inside_cut && lock->l_type == F_RDLCK &&
        (command == F_OFD_SETLK || command == F_OFD_SETLKW)),
        "NO_SHARED_LOCK_ATTEMPT_UNDER_CLEAN_CUT");
    result = __real_fcntl(fd, command, lock);
  } else if (command == F_GETFL || command == F_GETFD) result = __real_fcntl(fd, command);
  else result = __real_fcntl(fd, command, va_arg(args, int));
  va_end(args); return result;
}
int __real_yd_retention_gate_enter(YDRetentionGate *);
int __wrap_yd_retention_gate_enter(YDRetentionGate *gate) {
  CHECK(!inside_cut, "NO_SHARED_ADMISSION_UNDER_CLEAN_CUT");
  return __real_yd_retention_gate_enter(gate);
}
int __real_fsync(int);
int __wrap_fsync(int fd) {
  if (inside_cut && fail_sync) {
    fail_sync = false;
    errno = EIO;
    return -1;
  }
  return __real_fsync(fd);
}
typedef struct {
  YDDisk *journal;
  YDRetentionGate *gate;
  YDRaftJournalScope *scope;
  YDRaftRetentionSessionOwner *owner;
  YDRaftRetentionSessionRecord expected, output;
  YDRaftRetentionSessionResult result;
  YDRetentionCut cut;
  int probe;
  bool failure, gate_failure;
  unsigned calls;
} Context;
static void excluded(Context *c) {
  struct flock lock = {.l_type = F_RDLCK, .l_whence = SEEK_SET, .l_len = 1};
  errno = 0;
  int result = __real_fcntl(c->probe, F_OFD_SETLK, &lock);
  CHECK(result == -1 && (errno == EAGAIN || errno == EACCES),
        "INDEPENDENT_PRODUCER_STAYS_EXCLUDED");
  CHECK(yd_retention_gate_cut_validate(c->gate, c->cut),
        "OWNED_CUT_REMAINS_VALID");
}
static YDRaftJournalScopeInfo scope_info(YDRaftJournalScope *scope) {
  YDRaftJournalScopeSnapshot *snapshot = yd_raft_journal_scope_snapshot(scope);
  YDRaftJournalScopeInfo info;
  CHECK(snapshot && yd_raft_journal_scope_snapshot_info(snapshot, &info),
        "SCOPE_SNAPSHOT");
  yd_raft_journal_scope_snapshot_close(snapshot);
  return info;
}
static bool publish_clean(void *opaque) {
  Context *c = opaque;
  c->calls++;
  excluded(c);
  YDRaftJournalScopeInfo during = scope_info(c->scope);
  CHECK(during.active == 1 && !during.complete,
        "PUBLICATION_IS_TRACKED_IN_PROGRESS");
  unsigned char root[32] = {1};
  fail_sync = c->failure;
  memset(&c->output, 0xa5, sizeof(c->output));
  fail_control = c->gate_failure;
  control_reads = 0;
  c->result = yd_raft_retention_session_update_cut(
      c->owner, c->journal, c->cut, &c->expected, YD_RAFT_RETENTION_SESSION_CLEAN, root,
      0, &c->output, NULL, 0);
  int update_errno = errno;
  if (c->gate_failure) {
    CHECK(control_triggered && c->result == YD_RAFT_RETENTION_SESSION_CHANGED,
          "CONTROL_FAILURE_REFUSES_BEFORE_PUBLICATION");
    unsigned char zero[sizeof(c->output)] = {0};
    CHECK(!memcmp(&c->output, zero, sizeof(c->output)), "UNCERTAIN_OUTPUT_CLEARED");
    return false;
  }
  if (c->failure) {
    CHECK(c->result == YD_RAFT_RETENTION_SESSION_UNCERTAIN &&
              update_errno == EIO && !fail_sync,
          "ACTUAL_UPDATE_RETAINS_UNCERTAIN_RESULT");
    unsigned char zero[sizeof(c->output)] = {0};
    CHECK(!memcmp(&c->output, zero, sizeof(c->output)),
          "UNCERTAIN_OUTPUT_CLEARED");
    return false;
  }
  CHECK(c->result == YD_RAFT_RETENTION_SESSION_PUBLISHED &&
            c->output.state == YD_RAFT_RETENTION_SESSION_CLEAN,
        "REAL_CLEAN_PUBLISHED_UNDER_OWNED_CUT");
  CHECK(yd_raft_retention_session_validate(c->owner),
        "CLEAN_BINDINGS_VALID_UNDER_CUT");
  excluded(c);
  return true;
}
static bool under_cut(YDRetentionCut cut, void *opaque) {
  Context *c = opaque;
  c->cut = cut;
  inside_cut = true;
  bool result = yd_raft_journal_scope_cut_run(c->scope, cut, publish_clean, c);
  inside_cut = false;
  if (!c->failure && !c->gate_failure)
    excluded(c);
  return result;
}
int main(int argc, char **argv) {
  CHECK(argc == 3, "ARGUMENTS");
  int directory =
      open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  CHECK(directory >= 0, "PRIVATE_ROOT");
  Context c = {.failure = !strcmp(argv[2], "failure"),
               .gate_failure = !strcmp(argv[2], "gate-failure")};
  c.journal = yd_disk_open_at(directory, true, 32768, NULL, 0);
  unsigned char cluster[16] = {1};
  c.gate = yd_retention_gate_open(directory, cluster, 1, 3, true, NULL, 0);
  YDRaftRetentionBirth *birth = NULL;
  CHECK(
      c.journal && c.gate &&
          yd_raft_retention_birth_publish(c.journal, c.gate, &birth, NULL, 0) ==
              YD_RAFT_RETENTION_BIRTH_PUBLISHED,
      "ACTUAL_JOINT_BIRTH");
  CHECK(yd_raft_retention_session_create(c.journal, c.gate, birth, &c.owner,
                                         NULL, 0) ==
            YD_RAFT_RETENTION_SESSION_PUBLISHED,
        "ACTUAL_ACTIVE_OWNER");
  CHECK(yd_raft_retention_session_current(c.owner, &c.expected),
        "CURRENT_ACTIVE");
  yd_disk_retention_bind_new(c.journal, c.gate, false);
  c.scope = yd_raft_journal_scope_new();
  CHECK(c.scope, "SCOPE");
  yd_raft_journal_scope_retention(c.scope, c.gate);
  int session = openat(directory, YD_RAFT_RETENTION_SESSION_FILE,
                       O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  CHECK(session >= 0, "OBSERVED_SESSION_IDENTITY");
  YDRaftJournalBinding *bindings[3] = {
      yd_raft_journal_scope_file(c.scope, directory, YD_RETENTION_FILE,
                                 yd_retention_gate_descriptor(c.gate),
                                 YD_RAFT_JOURNAL_BINDING_CONTROL),
      yd_raft_journal_scope_file(c.scope, directory,
                                 YD_RAFT_RETENTION_BIRTH_FILE,
                                 yd_raft_retention_birth_descriptor(birth),
                                 YD_RAFT_JOURNAL_BINDING_BIRTH),
      yd_raft_journal_scope_file(c.scope, directory,
                                 YD_RAFT_RETENTION_SESSION_FILE, session,
                                 YD_RAFT_JOURNAL_BINDING_SESSION)};
  close(session);
  CHECK(bindings[0] && bindings[1] && bindings[2],
        "EXACT_METADATA_REGISTRATIONS");
  c.probe =
      openat(directory, YD_RETENTION_FILE, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
  CHECK(c.probe >= 0, "INDEPENDENT_GATE_DESCRIPTION");
  CHECK(!fstat(c.probe, &control_identity), "CONTROL_IDENTITY");
  YDRaftJournalScopeSnapshot *before = yd_raft_journal_scope_snapshot(c.scope);
  YDRaftJournalScopeInfo prior = scope_info(c.scope);
  CHECK(before && prior.complete && !prior.active && prior.count == 3,
        "QUIET_SCOPE_BEFORE_PUBLICATION");
  int result = yd_retention_gate_cut_run(c.gate, under_cut, &c, NULL, 0);
  CHECK(c.calls == 1 && !inside_cut, "ONE_REAL_UPDATE");
  YDRaftJournalScopeInfo after = scope_info(c.scope);
  CHECK(!after.active && after.revision == prior.revision + 2 &&
            !yd_raft_journal_scope_validate(before),
        "CUT_REVISION_BALANCED");
  if (c.failure || c.gate_failure) {
    CHECK(result == -1 && !after.complete && after.reasons &&
              !yd_raft_retention_session_validate(c.owner),
          "FAILURE_IS_STICKY_IN_BOTH_OWNERS");
    int retry = -1;
    CHECK(yd_retention_gate_try_cut(c.gate, &retry, NULL, 0) == -1 &&
              retry == -1,
          "UNCERTAIN_CLEAN_CANNOT_REGAIN_CUT");
  } else {
    CHECK(result == 1 && after.complete, "SUCCESSFUL_TRACKED_CLEAN");
    int producer = yd_retention_gate_enter(c.gate);
    CHECK(producer >= 0, "SHARED_ADMISSION_RESUMES_AFTER_CUT");
    close(producer);
    YDRaftRetentionSessionInfo original;
    YDRaftRetentionSessionRecord current;
    CHECK(yd_raft_retention_session_info(c.owner, &original) &&
              original.record.state == YD_RAFT_RETENTION_SESSION_ACTIVE &&
              yd_raft_retention_session_current(c.owner, &current) &&
              current.state == YD_RAFT_RETENTION_SESSION_CLEAN,
          "ORIGINAL_AND_CURRENT_STATES_STAY_DISTINCT");
  }
  yd_raft_journal_scope_snapshot_close(before);
  close(c.probe);
  for (unsigned i = 0; i < 3; i++)
    yd_raft_journal_binding_close(bindings[i]);
  yd_raft_journal_scope_close(c.scope);
  yd_raft_retention_session_close(c.owner);
  yd_raft_retention_birth_close(birth);
  yd_disk_close(c.journal);
  yd_retention_gate_close(c.gate);
  close(directory);
  return 0;
}
