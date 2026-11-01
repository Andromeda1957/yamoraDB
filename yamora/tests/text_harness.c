#include "../src/text.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    size_t limit = argc == 2 ? strtoul(argv[1], NULL, 10) : YD_TEXT_DOCUMENT_TERMS;
    unsigned char *input = malloc(YD_DOCUMENT_LIMIT + 1);
    if (!input)
        return 1;
    size_t n = fread(input, 1, YD_DOCUMENT_LIMIT + 1, stdin);
    char error[512] = {0};
    YDText *text = yd_text_new(limit);
    bool ok = n <= YD_DOCUMENT_LIMIT && text && yd_text_add(text, input, n, error, sizeof(error));
    if (ok) {
        yd_text_finish(text);
        YDValue *values = calloc(text->count ? text->count : 1, sizeof(YDValue));
        YDValue **items = calloc(text->count ? text->count : 1, sizeof(YDValue *));
        ok = values && items;
        if (ok) {
            for (size_t i = 0; i < text->count; i++) {
                values[i] = (YDValue){.type = YD_STRING, .scalar = text->terms[i]};
                items[i] = &values[i];
            }
            YDValue list = {.type = YD_ARRAY, .items = items, .count = text->count};
            size_t size;
            char *json = yd_json(&list, &size);
            ok = json != NULL;
            if (json)
                fwrite(json, 1, size, stdout);
            free(json);
        }
        free(values);
        free(items);
    }
    if (!ok)
        fprintf(stderr, "%s\n", error);
    yd_text_free(text);
    free(input);
    return ok ? 0 : 2;
}
