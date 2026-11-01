#define _GNU_SOURCE
#include "raft_internal.h"
#include "retention_birth.h"
#include "retention_session_owner.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct YDRaftJournalScope {
    atomic_uint references;
    pid_t creator_process; /* Immutable; foreign-PID cut/constructor entry must not lock. */
    pthread_mutex_t lock;
    uint64_t revision, active, next;
    unsigned reasons;
    size_t count;
    YDRaftJournalBinding *bindings[YD_RAFT_JOURNAL_BINDINGS];
    YDRetentionGate *retention;
    int retention_lease;
    bool exposed, cut_active;
    uint64_t constructor;
    pthread_t constructor_thread;
    struct stat constructor_root;
    unsigned char constructor_identity[18];
    bool guarding;
};
struct YDRaftJournalBinding {
    atomic_uint references;
    YDRaftJournalScope *scope;
    YDRaftJournalBindingInfo info;
    int directory, object;
};
struct YDRaftJournalScopeSnapshot {
    YDRaftJournalScope *scope;
    YDRaftJournalScopeInfo info;
    YDRaftJournalBinding *bindings[YD_RAFT_JOURNAL_BINDINGS];
};
static void advance(YDRaftJournalScope *scope) {
    if (scope->revision == UINT64_MAX) scope->reasons |= YD_RAFT_JOURNAL_REVISION_OVERFLOW;
    else scope->revision++;
}
static void mark(YDRaftJournalScope *scope, unsigned reason) {
    if (!scope) return;
    pthread_mutex_lock(&scope->lock);
    scope->reasons |= reason;
    advance(scope);
    pthread_mutex_unlock(&scope->lock);
}
YDRaftJournalScope *yd_raft_journal_scope_new(void) {
    YDRaftJournalScope *scope = calloc(1, sizeof(*scope));
    if (!scope) return NULL;
    if (pthread_mutex_init(&scope->lock, NULL)) { free(scope); return NULL; }
    atomic_init(&scope->references, 1);
    scope->creator_process = getpid();
    scope->revision = 1;
    scope->retention_lease = -1;
    return scope;
}
YDRaftJournalScope *yd_raft_journal_scope_retain(YDRaftJournalScope *scope) {
    if (scope) {
        pthread_mutex_lock(&scope->lock);
        scope->exposed = true;
        atomic_fetch_add_explicit(&scope->references, 1, memory_order_relaxed);
        pthread_mutex_unlock(&scope->lock);
    }
    return scope;
}
/* Never wrap/reuse identity, including across scopes and constructor stacks. */
static atomic_uint_fast64_t constructor_serial = 0;
static uint64_t next_constructor(void) {
    uint_fast64_t prior = atomic_load_explicit(&constructor_serial, memory_order_relaxed);
    do {
        if (prior == UINT64_MAX) return 0;
    } while (!atomic_compare_exchange_weak_explicit(&constructor_serial, &prior, prior + 1,
        memory_order_relaxed, memory_order_relaxed));
    return prior + 1;
}
static bool fresh(const YDRaftJournalScope *scope) {
    return scope->revision == 1 && !scope->exposed && !scope->active &&
        !scope->count && !scope->next && !scope->reasons && !scope->retention;
}
void yd_raft_journal_scope_retention(YDRaftJournalScope *scope, YDRetentionGate *gate) {
    if (!scope || !gate) return;
    int saved = errno;
    pthread_mutex_lock(&scope->lock);
    bool valid = fresh(scope);
    if (valid) scope->retention = yd_retention_gate_retain(gate);
    if (!valid || !scope->retention) {
        scope->reasons |= YD_RAFT_JOURNAL_TRACKING_FAILED;
        advance(scope);
        valid = false;
    }
    pthread_mutex_unlock(&scope->lock);
    if (!valid) yd_retention_gate_disable(gate);
    errno = saved;
}
/* A fork child inherits pthread identity and possibly a held mutex. Only read
 * immutable creator PID before rejecting it; never consume/mark copied state,
 * touch gate authority, or acquire inherited mutexes/refcounts in that child. */
static bool constructor_process(const YDRaftJournalScope *scope) {
    return scope && scope->creator_process == getpid();
}
YDRaftJournalConstructor yd_raft_journal_scope_constructor_begin(YDRaftJournalScope *scope) {
    YDRaftJournalConstructor token = {0};
    if (!constructor_process(scope)) return token;
    int saved = errno;
    pthread_mutex_lock(&scope->lock);
    if (fresh(scope)) {
        token.opaque = scope->constructor = next_constructor();
        scope->constructor_thread = pthread_self();
    }
    pthread_mutex_unlock(&scope->lock);
    yd_raft_journal_scope_begin(scope);
    errno = saved;
    return token;
}
void yd_raft_journal_scope_constructor_invalidate(YDRaftJournalScope *scope) {
    if (!constructor_process(scope)) return;
    pthread_mutex_lock(&scope->lock);
    scope->constructor = 0;
    scope->guarding = false;
    pthread_mutex_unlock(&scope->lock);
}
void yd_raft_journal_scope_constructor_guard(YDRaftJournalScope *scope,
    YDRaftJournalConstructor token, int directory, const unsigned char cluster[16],
    unsigned node, unsigned voters) {
    if (!constructor_process(scope)) return;
    int saved = errno;
    struct stat root;
    bool valid = cluster && !fstat(directory, &root);
    pthread_mutex_lock(&scope->lock);
    if (valid && token.opaque && scope->constructor == token.opaque) {
        scope->constructor_root = root;
        memcpy(scope->constructor_identity, cluster, 16);
        scope->constructor_identity[16] = (unsigned char)node;
        scope->constructor_identity[17] = (unsigned char)voters;
        scope->guarding = true;
    }
    pthread_mutex_unlock(&scope->lock);
    errno = saved;
}
static bool constructing(const YDRaftJournalScope *scope, YDRaftJournalConstructor token) {
    return token.opaque && scope->constructor == token.opaque && scope->guarding &&
        pthread_equal(scope->constructor_thread, pthread_self()) &&
        scope->revision == 2 && scope->active == 1 && !scope->count &&
        !scope->next && !scope->reasons && !scope->retention;
}
bool yd_raft_journal_scope_retention_constructing(YDRaftJournalScope *scope,
    YDRaftJournalConstructor token, YDRetentionGate *gate) {
    if (scope && !constructor_process(scope)) return false;
    int saved = errno;
    bool valid = false;
    YDRetentionGate *owned = NULL;
    int lease = -1;
    YDRetentionGateBinding binding;
    bool bound = yd_retention_gate_binding(gate, &binding);
    if (scope) {
        pthread_mutex_lock(&scope->lock);
        valid = bound && constructing(scope, token) &&
            binding.root.st_dev == scope->constructor_root.st_dev &&
            binding.root.st_ino == scope->constructor_root.st_ino &&
            !memcmp(binding.header + 8, scope->constructor_identity, 18);
        /* Consume even on refusal; state cannot recreate this identity. */
        scope->constructor = 0;
        pthread_mutex_unlock(&scope->lock);
    }
    if (valid) {
        owned = yd_retention_gate_retain(gate);
        lease = owned ? yd_retention_gate_enter(owned) : -1;
        pthread_mutex_lock(&scope->lock);
        /* Recheck after blocking admission: even a balanced concurrent
         * transition changes revision. No producer I/O runs under this lock. */
        valid = lease >= 0 && scope->revision == 2 && scope->active == 1 &&
            !scope->count && !scope->next && !scope->reasons && !scope->retention;
        if (valid) {
            scope->retention = owned;
            scope->retention_lease = lease;
            owned = NULL;
            lease = -1;
        }
        pthread_mutex_unlock(&scope->lock);
    }
    if (!valid) {
        mark(scope, YD_RAFT_JOURNAL_TRACKING_FAILED);
        yd_retention_gate_disable(gate);
    }
    if (lease >= 0) close(lease);
    yd_retention_gate_close(owned);
    errno = saved;
    return valid;
}
void yd_raft_journal_scope_close(YDRaftJournalScope *scope) {
    if (scope && atomic_fetch_sub_explicit(&scope->references, 1, memory_order_acq_rel) == 1) {
        if (scope->retention_lease >= 0) close(scope->retention_lease);
        yd_retention_gate_close(scope->retention);
        pthread_mutex_destroy(&scope->lock);
        free(scope);
    }
}
void yd_raft_journal_scope_begin(YDRaftJournalScope *scope) {
    if (!scope) return;
    int saved = errno;
    pthread_mutex_lock(&scope->lock);
    YDRetentionGate *gate = yd_retention_gate_retain(scope->retention);
    advance(scope);
    if (scope->active == UINT64_MAX) scope->reasons |= YD_RAFT_JOURNAL_TRANSITION_INVALID;
    else scope->active++;
    pthread_mutex_unlock(&scope->lock);
    int admission = gate ? yd_retention_gate_enter(gate) : -1;
    bool admitted = admission >= 0;
    pthread_mutex_lock(&scope->lock);
    if (scope->retention_lease < 0) {
        scope->retention_lease = admission;
        admission = -1;
    }
    if (gate && !admitted) scope->reasons |= YD_RAFT_JOURNAL_TRACKING_FAILED;
    pthread_mutex_unlock(&scope->lock);
    if (admission >= 0) close(admission);
    yd_retention_gate_close(gate);
    errno = saved;
}
void yd_raft_journal_scope_end(YDRaftJournalScope *scope) {
    if (!scope) return;
    int saved = errno;
    pthread_mutex_lock(&scope->lock);
    if (!scope->active) scope->reasons |= YD_RAFT_JOURNAL_TRANSITION_INVALID;
    else scope->active--;
    int admission = -1;
    if (!scope->active) {
        admission = scope->retention_lease;
        scope->retention_lease = -1;
    }
    advance(scope);
    pthread_mutex_unlock(&scope->lock);
    if (admission >= 0) close(admission);
    errno = saved;
}
void yd_raft_journal_scope_incomplete(YDRaftJournalScope *scope) {
    mark(scope, YD_RAFT_JOURNAL_TRACKING_FAILED);
}
static bool same(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
static bool trusted(const struct stat *s, bool directory) {
    return (directory ? S_ISDIR(s->st_mode) : S_ISREG(s->st_mode)) &&
        s->st_uid == geteuid() && !(s->st_mode & (S_IWGRP | S_IWOTH));
}
static bool component(const char *name, YDRaftJournalBindingKind kind) {
    if (!name) return false;
    if (kind == YD_RAFT_JOURNAL_BINDING_CONTROL) return !strcmp(name, YD_RETENTION_FILE);
    if (kind == YD_RAFT_JOURNAL_BINDING_BIRTH) return !strcmp(name, YD_RAFT_RETENTION_BIRTH_FILE);
    if (kind == YD_RAFT_JOURNAL_BINDING_SESSION) return !strcmp(name, YD_RAFT_RETENTION_SESSION_FILE);
    if (kind == YD_RAFT_JOURNAL_BINDING_FENCE) return !strcmp(name, ".yamora-initializing");
    const char *prefix = kind == YD_RAFT_JOURNAL_BINDING_RETAINED ? "old-" :
        kind == YD_RAFT_JOURNAL_BINDING_PREPARED ? ".prepared-journal-" : NULL;
    if (!prefix) return false;
    size_t n = strlen(prefix);
    if (strnlen(name, 80) != n + 32 || memcmp(name, prefix, n)) return false;
    for (unsigned i = 0; i < 32; i++)
        if (!((name[n + i] >= '0' && name[n + i] <= '9') ||
            (name[n + i] >= 'a' && name[n + i] <= 'f'))) return false;
    return true;
}
static void binding_release(YDRaftJournalBinding *binding) {
    if (!binding || atomic_fetch_sub_explicit(&binding->references, 1, memory_order_acq_rel) != 1)
        return;
    if (binding->directory >= 0) close(binding->directory);
    if (binding->object >= 0) close(binding->object);
    YDRaftJournalScope *scope = binding->scope;
    free(binding);
    yd_raft_journal_scope_close(scope);
}
static bool binding_valid(const YDRaftJournalBinding *binding) {
    struct stat object, directory, named;
    bool workspace = binding->info.kind == YD_RAFT_JOURNAL_BINDING_WORKSPACE;
    if (fstat(binding->object, &object) || !trusted(&object, workspace) ||
        object.st_dev != binding->info.device || object.st_ino != binding->info.inode)
        return false;
    if (workspace) return true;
    return !fstat(binding->directory, &directory) && trusted(&directory, true) &&
        directory.st_dev == binding->info.parent_device &&
        directory.st_ino == binding->info.parent_inode &&
        !fstatat(binding->directory, binding->info.name, &named, AT_SYMLINK_NOFOLLOW) &&
        trusted(&named, false) && same(&named, &object) &&
        (binding->info.kind != YD_RAFT_JOURNAL_BINDING_FENCE || object.st_size == 0);
}
static YDRaftJournalBinding *bind(YDRaftJournalScope *scope, int directory,
    const char *name, int expected, YDRaftJournalBindingKind kind) {
    if (!scope) return NULL;
    yd_raft_journal_scope_begin(scope);
    YDRaftJournalBinding *binding = calloc(1, sizeof(*binding));
    if (binding) {
        atomic_init(&binding->references, 1);
        binding->scope = yd_raft_journal_scope_retain(scope);
        binding->directory = binding->object = -1;
        binding->info.kind = kind;
    }
    struct stat parent, actual, wanted;
    bool workspace = kind == YD_RAFT_JOURNAL_BINDING_WORKSPACE;
    bool valid = binding && directory >= 0 && (workspace || component(name, kind));
    if (valid) {
        int retained = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (workspace) binding->object = retained;
        else binding->directory = retained;
        valid = retained >= 0 && !fstat(retained, &parent) && trusted(&parent, true);
        if (valid && !workspace) {
            binding->object = openat(retained, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
            valid = binding->object >= 0 && expected >= 0 && !fstat(expected, &wanted);
        }
        if (valid) valid = !fstat(binding->object, &actual) && trusted(&actual, workspace) &&
            (workspace || same(&actual, &wanted));
        if (valid) {
            binding->info.device = actual.st_dev;
            binding->info.inode = actual.st_ino;
            if (!workspace) {
                binding->info.parent_device = parent.st_dev;
                binding->info.parent_inode = parent.st_ino;
                memcpy(binding->info.name, name, strlen(name) + 1);
            }
            valid = binding_valid(binding);
        }
    }
    if (valid) {
        pthread_mutex_lock(&scope->lock);
        if (scope->count == YD_RAFT_JOURNAL_BINDINGS || scope->next == UINT64_MAX) {
            scope->reasons |= scope->count == YD_RAFT_JOURNAL_BINDINGS ?
                YD_RAFT_JOURNAL_BINDING_LIMIT : YD_RAFT_JOURNAL_REVISION_OVERFLOW;
            valid = false;
        } else {
            binding->info.id = ++scope->next;
            scope->bindings[scope->count++] = binding;
        }
        pthread_mutex_unlock(&scope->lock);
    } else mark(scope, YD_RAFT_JOURNAL_TRACKING_FAILED);
    if (!valid) { binding_release(binding); binding = NULL; }
    yd_raft_journal_scope_end(scope);
    return binding;
}
YDRaftJournalBinding *yd_raft_journal_scope_workspace(YDRaftJournalScope *scope, int directory) {
    return bind(scope, directory, NULL, -1, YD_RAFT_JOURNAL_BINDING_WORKSPACE);
}
YDRaftJournalBinding *yd_raft_journal_scope_file(YDRaftJournalScope *scope, int directory,
    const char *name, int expected, YDRaftJournalBindingKind kind) {
    if (kind == YD_RAFT_JOURNAL_BINDING_WORKSPACE) {
        mark(scope, YD_RAFT_JOURNAL_TRACKING_FAILED);
        return NULL;
    }
    return bind(scope, directory, name, expected, kind);
}
void yd_raft_journal_binding_close(YDRaftJournalBinding *binding) {
    if (!binding) return;
    YDRaftJournalScope *scope = binding->scope;
    yd_raft_journal_scope_begin(scope);
    pthread_mutex_lock(&scope->lock);
    for (size_t i = 0; i < scope->count; i++) if (scope->bindings[i] == binding) {
        scope->bindings[i] = scope->bindings[--scope->count];
        break;
    }
    pthread_mutex_unlock(&scope->lock);
    yd_raft_journal_scope_end(scope);
    binding_release(binding);
}
static bool unchanged(const YDRaftJournalScopeSnapshot *snapshot) {
    YDRaftJournalScope *scope = snapshot->scope;
    pthread_mutex_lock(&scope->lock);
    bool valid = snapshot->info.complete && !scope->active && !scope->reasons &&
        scope->revision == snapshot->info.revision;
    pthread_mutex_unlock(&scope->lock);
    return valid;
}
bool yd_raft_journal_scope_validate(const YDRaftJournalScopeSnapshot *snapshot) {
    if (!snapshot || !unchanged(snapshot)) return false;
    for (size_t i = 0; i < snapshot->info.count; i++)
        if (!binding_valid(snapshot->bindings[i])) return false;
    return unchanged(snapshot);
}
YDRaftJournalScopeSnapshot *yd_raft_journal_scope_snapshot(YDRaftJournalScope *scope) {
    if (!scope) return NULL;
    YDRaftJournalScopeSnapshot *snapshot = calloc(1, sizeof(*snapshot));
    if (!snapshot) return NULL;
    snapshot->scope = yd_raft_journal_scope_retain(scope);
    pthread_mutex_lock(&scope->lock);
    snapshot->info.revision = scope->revision;
    snapshot->info.active = scope->active;
    snapshot->info.reasons = scope->reasons;
    snapshot->info.complete = !scope->active && !scope->reasons;
    snapshot->info.count = scope->count;
    for (size_t i = 0; i < scope->count; i++) {
        YDRaftJournalBinding *binding = scope->bindings[i];
        atomic_fetch_add_explicit(&binding->references, 1, memory_order_relaxed);
        snapshot->bindings[i] = binding;
        snapshot->info.bindings[i] = binding->info;
    }
    pthread_mutex_unlock(&scope->lock);
    if (snapshot->info.complete && !yd_raft_journal_scope_validate(snapshot)) {
        snapshot->info.complete = false;
        snapshot->info.reasons |= YD_RAFT_JOURNAL_BINDING_CHANGED;
    }
    return snapshot;
}
bool yd_raft_journal_scope_snapshot_info(const YDRaftJournalScopeSnapshot *snapshot,
    YDRaftJournalScopeInfo *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!snapshot || !out) return false;
    *out = snapshot->info;
    return true;
}
int yd_raft_journal_scope_workspace_directory(const YDRaftJournalScopeSnapshot *snapshot,
    size_t index) {
    return snapshot && index < snapshot->info.count &&
        snapshot->info.bindings[index].kind == YD_RAFT_JOURNAL_BINDING_WORKSPACE
        ? snapshot->bindings[index]->object : -1;
}
void yd_raft_journal_scope_snapshot_close(YDRaftJournalScopeSnapshot *snapshot) {
    if (!snapshot) return;
    for (size_t i = 0; i < snapshot->info.count; i++) binding_release(snapshot->bindings[i]);
    yd_raft_journal_scope_close(snapshot->scope);
    free(snapshot);
}

typedef struct {
    YDRaftJournalScope *scope;
    YDRetentionGate *gate;
    YDRetentionCut cut;
    uint64_t revision;
    bool success, result;
} ScopeCutCleanup;
static void scope_cut_cleanup(void *context) {
    ScopeCutCleanup *owned = context;
    YDRaftJournalScope *scope = owned->scope;
    int saved = errno;
    pthread_mutex_lock(&scope->lock);
    bool unchanged = scope->cut_active && scope->active == 1 &&
        scope->revision == owned->revision && !scope->reasons;
    if (scope->active) scope->active--;
    else scope->reasons |= YD_RAFT_JOURNAL_TRANSITION_INVALID;
    scope->cut_active = false;
    advance(scope);
    if (!unchanged) scope->reasons |= YD_RAFT_JOURNAL_TRANSITION_INVALID;
    if (!owned->success || !unchanged) scope->reasons |= YD_RAFT_JOURNAL_TRACKING_FAILED;
    owned->result = owned->success && unchanged && !scope->reasons;
    pthread_mutex_unlock(&scope->lock);
    if (!owned->result) (void)yd_retention_gate_cut_fail(owned->gate, owned->cut);
    yd_retention_gate_close(owned->gate);
    yd_raft_journal_scope_close(scope);
    errno = saved;
}
bool yd_raft_journal_scope_cut_run(YDRaftJournalScope *scope, YDRetentionCut cut,
    bool (*update)(void *), void *context) {
    if (!scope || scope->creator_process != getpid()) return false;
    int saved = errno, cancellation;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation);
    yd_raft_journal_scope_retain(scope);
    pthread_mutex_lock(&scope->lock);
    YDRetentionGate *gate = yd_retention_gate_retain(scope->retention);
    pthread_mutex_unlock(&scope->lock);
    bool valid = update && yd_retention_gate_cut_validate(gate, cut);
    ScopeCutCleanup owned = {scope, gate, cut, 0, false, false};
    pthread_mutex_lock(&scope->lock);
    valid = valid && scope->retention == gate && !scope->active &&
        !scope->cut_active && scope->retention_lease < 0 && !scope->reasons &&
        scope->revision <= UINT64_MAX - 2;
    if (valid) {
        advance(scope);
        scope->active++;
        scope->cut_active = true;
        owned.revision = scope->revision;
    } else {
        scope->reasons |= YD_RAFT_JOURNAL_TRACKING_FAILED | YD_RAFT_JOURNAL_TRANSITION_INVALID;
        if (scope->revision > UINT64_MAX - 2)
            scope->reasons |= YD_RAFT_JOURNAL_REVISION_OVERFLOW;
        advance(scope);
    }
    pthread_mutex_unlock(&scope->lock);
    if (!valid) {
        (void)yd_retention_gate_cut_fail(gate, cut);
        yd_retention_gate_close(gate);
        yd_raft_journal_scope_close(scope);
        errno = saved;
        pthread_setcancelstate(cancellation, NULL);
        return false;
    }
    pthread_cleanup_push(scope_cut_cleanup, &owned);
    pthread_setcancelstate(cancellation, NULL);
    bool completed = update(context);
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    owned.success = completed && yd_retention_gate_cut_validate(gate, cut);
    pthread_cleanup_pop(1);
    pthread_setcancelstate(cancellation, NULL);
    return owned.result;
}
