#include "../src/value.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool armed;
static size_t largest;
void *__real_malloc(size_t size);
void *__wrap_malloc(size_t size) {
    if (armed && size > largest) largest = size;
    if (armed && size > 4U * 1024U * 1024U) return NULL;
    return __real_malloc(size);
}
static bool marks(void) {
    unsigned char body[32768] = "\xef\xbb\xbf";
    size_t used = 3, starts[300], ends[300];
    for (unsigned i = 0; i < 300; i++) {
        used += (size_t)snprintf((char *)body + used, sizeof(body) - used, "# café🙂 padding %u\r\nk%03u: ", i, i);
        starts[i] = used;
        used += (size_t)snprintf((char *)body + used, sizeof(body) - used, "\"é🙂ßa\"");
        ends[i] = used;
        body[used++] = '\r'; body[used++] = '\n';
    }
    char error[256];
    YDValue *value = yd_parse_request(body, used, error, sizeof(error));
    bool ok = value != NULL;
    for (unsigned i = 0; ok && i < 300; i++) {
        char key[16]; snprintf(key, sizeof(key), "k%03u", i);
        const YDValue *field = yd_get(value, key);
        ok = field && field->start == starts[i] && field->end == ends[i] &&
             field->type == YD_STRING && !strcmp(field->scalar, "é🙂ßa");
    }
    if (!ok) fprintf(stderr, "Unicode source marks across sparse checkpoints: %s\n", value ? "offset mismatch" : error);
    yd_free(value); return ok;
}
int main(void) {
    size_t size = 1536U * 1024U;
    unsigned char *body = malloc(size);
    if (!body) return 1;
    const unsigned char prefix[] = "\xef\xbb\xbf# Unicode offsets\r\nname: Straße\r\ntext: ";
    memcpy(body, prefix, sizeof(prefix) - 1);
    memset(body + sizeof(prefix) - 1, 'x', size - sizeof(prefix));
    body[size - 1] = '\n';
    char error[256];
    armed = true;
    YDValue *value = yd_parse_request(body, size, error, sizeof(error));
    armed = false;
    const YDValue *name = yd_get(value, "name"), *text = yd_get(value, "text");
    bool ok = value && name && text && name->type == YD_STRING && text->type == YD_STRING &&
              !strcmp(name->scalar, "Straße") && name->end <= text->start &&
              text->end == size - 1 && body[text->start] == 'x' &&
              largest < 2U * 1024U * 1024U;
    if (!ok) fprintf(stderr, "bounded marks: allocation=%zu error=%s\n", largest, value ? "offset mismatch" : error);
    yd_free(value); free(body);
    ok = ok && marks();
    return ok ? 0 : 2;
}
