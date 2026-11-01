#define _POSIX_C_SOURCE 200809L
#include "disk_internal.h"
#include <errno.h>
#include <string.h>

static _Thread_local bool activating;
YDSchemaBarrierResult yd_disk_schema_activate_at(int source, int destination,
    uint64_t maximum, uint64_t *work, YDDiskSchemaActivationValidator validator,
    void *context, YDSchemaBarrierPrepared *out, char *error, size_t length) {
    int saved = errno;
    YDSchemaBarrierResult result;
    if (!validator || activating) {
        if (out) memset(out, 0, sizeof(*out));
        yd_disk_error(error, length, "schema activation requires a complete application validator");
        result = YD_SCHEMA_BARRIER_INVALID;
    } else {
        activating = true;
        result = yd_disk_schema_copy_at(source, destination, maximum, work,
            validator, context, out, error, length);
        activating = false;
    }
    errno = saved;
    return result;
}
