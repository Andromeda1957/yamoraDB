#ifndef YAMORA_NAME_H
#define YAMORA_NAME_H

#include <stdbool.h>
#include <string.h>

#define YAMLDB_NAME_LIMIT 128

/* Shared ASCII namespace rule; no document, snapshot or storage dependency. */
static inline bool yd_name_valid(const char *value)
{
    size_t length = strlen(value);

    if (length == 0 || length > YAMLDB_NAME_LIMIT) {
        return false;
    }
    for (size_t index = 0; index < length; index++) {
        char byte = value[index];
        if (!((byte >= 'a' && byte <= 'z') ||
              (byte >= '0' && byte <= '9') ||
              byte == '-')) {
            return false;
        }
    }
    return true;
}

#endif
