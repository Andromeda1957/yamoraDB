#ifndef YAMORA_DISK_VALIDATION_H
#define YAMORA_DISK_VALIDATION_H
#include "disk.h"
typedef enum {
    YD_VALIDATE_APPLICATION,
    YD_VALIDATE_COLLECTION,
    YD_VALIDATE_DOCUMENT,
    YD_VALIDATE_INDEX,
    YD_VALIDATE_HISTORY,
    YD_VALIDATE_OPERATION
} YDDiskValidationPhase;
/* Cooperative, synchronous checks before each graph key, document, index entry,
 * history frame and frame operation. Individual bounded records (including YAML
 * parsing/index expansion), tree traversals and syscalls remain indivisible.
 * Callbacks must not reenter the operation or acquire owner/runtime locks.
 * Keep this operation-local state alive through the call; cancelled is scan-owned
 * output, not an asynchronous flag. Read external atomic stop flags in callbacks.
 * Cancellation is sticky; use a fresh state to retry. NULL state/progress
 * preserves complete validation. */
typedef struct {
    bool (*progress)(void *context, YDDiskValidationPhase phase);
    void *context;
    bool cancelled;
} YDDiskValidation;
static inline bool yd_disk_validation_step(YDDiskValidation *state, YDDiskValidationPhase phase) {
    if (!state)
        return true;
    if (!state->cancelled && state->progress && !state->progress(state->context, phase))
        state->cancelled = true;
    return !state->cancelled;
}
#endif
