#ifndef YAMORA_RETENTION_GATE_H
#define YAMORA_RETENTION_GATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

typedef struct YDRetentionGate YDRetentionGate;
#define YD_RETENTION_FILE ".yamora-retention"
typedef struct {
    struct stat root, control;
    unsigned char header[128];
} YDRetentionGateBinding;
/* Copies constructor-time immutable binding, clearing out on invalid input.
 * No I/O or validation; disabled gates still copy their ORIGINAL binding.
 * This snapshot supplies no enrollment, birth or deletion authority. */
bool yd_retention_gate_binding(const YDRetentionGate *, YDRetentionGateBinding *out);

/* Private Linux/local-filesystem primitive, not provenance or deletion authority.
 * directory is borrowed; the gate independently reopens and pins its root.
 * create is permitted only for a native disk O_EXCL-created by this startup.
 * Existing/unknown/partial controls are never rewritten, replaced or removed. */
YDRetentionGate *yd_retention_gate_open(int directory, const unsigned char cluster[16],
                                      unsigned node, unsigned voters, bool create,
                                      char *error, size_t length);
/* Immutable constructor fact: true only for this successful open's own O_EXCL
 * control creation. Existing controls (even create=true) and NULL return false.
 * This does not establish journal creation or durable restart provenance. */
bool yd_retention_gate_created(const YDRetentionGate *);
/* Each concurrent caller must already hold a live reference. Immutable getters
 * and retain/close are safe across threads; final close requires joined users. */
YDRetentionGate *yd_retention_gate_retain(YDRetentionGate *);
void yd_retention_gate_close(YDRetentionGate *);
/* Owned independently opened shared OFD descriptor, or -1 (disables cuts).
 * May block behind a cut. Call outside native root/writer/observation locks.
 * Clones use F_DUPFD_CLOEXEC; release originals/clones by close ONLY. */
int yd_retention_gate_enter(YDRetentionGate *);
/* Never blocks. 1: owned exclusive OFD descriptor in *cut; 0: busy; -1: invalid
 * or I/O error. Initializes *cut to -1. Release the cut by close ONLY. */
int yd_retention_gate_try_cut(YDRetentionGate *, int *cut, char *error, size_t length);
bool yd_retention_gate_validate(YDRetentionGate *);
/* Callback-local, process-local identity. Zero is invalid. No raw descriptor
 * can be adopted. Trusted cooperative code only, not an authentication token. */
typedef struct { uint64_t opaque; } YDRetentionCut;
typedef bool (*YDRetentionCutBody)(YDRetentionCut, void *);
/* Nonblocking acquisition; 1 completed, 0 busy (no callback), -1 failed.
 * Owns a hidden independent exclusive OFD through callback/final validation.
 * No backend/leaf locks may surround this call. Callbacks may not longjmp.
 * Cancellation/pthread_exit poison and release the owned cut. Failure fallback
 * may wait ONLY AFTER exclusive close. No disposal/restart authority. */
int yd_retention_gate_cut_run(YDRetentionGate *, YDRetentionCutBody, void *,
    char *error, size_t length);
/* Exact gate/thread/PID/live callback plus original binding/healthy gate.
 * Never acquires shared admission; observed binding failure is sticky. */
bool yd_retention_gate_cut_validate(YDRetentionGate *, YDRetentionCut);
/* Exact ownership check, including on an already poisoned gate. Atomic sticky
 * disable only: no allocation, fd operation, I/O or shared lock. */
bool yd_retention_gate_cut_fail(YDRetentionGate *, YDRetentionCut);

/* Sticky. Attempts persistent base shared lock, waiting behind an existing cut.
 * Call outside leaf locks and without owning a cut. The base lock survives
 * until the last gate reference closes. No allocation/new fd is needed. */
void yd_retention_gate_disable(YDRetentionGate *);
/* Borrowed descriptors; registration/stat only. Never lock/unlock/close these. */
int yd_retention_gate_directory(const YDRetentionGate *);
int yd_retention_gate_descriptor(const YDRetentionGate *);

#endif
