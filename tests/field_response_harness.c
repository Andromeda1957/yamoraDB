#define _POSIX_C_SOURCE 200809L
#include "../src/security/field_response.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool allocation_fault, serialization_fault;
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
char *__real_strdup(const char *);
char *__real_yd_json_sized(const YDValue *, size_t *, size_t);
void *__wrap_malloc(size_t n) { return allocation_fault ? NULL : __real_malloc(n); }
void *__wrap_calloc(size_t n, size_t s) { return allocation_fault ? NULL : __real_calloc(n, s); }
void *__wrap_realloc(void *p, size_t n) { return allocation_fault ? NULL : __real_realloc(p, n); }
char *__wrap_strdup(const char *s) { return allocation_fault ? NULL : __real_strdup(s); }
char *__wrap_yd_json_sized(const YDValue *v, size_t *n, size_t cap) {
    return serialization_fault ? NULL : __real_yd_json_sized(v, n, cap);
}
static char *read_file(const char *path, size_t *size) {
    FILE *file = fopen(path, "rb");
    if (!file || fseek(file, 0, SEEK_END)) { if (file) fclose(file); return NULL; }
    long n = ftell(file);
    if (n < 0 || (unsigned long)n > YD_FIELD_RESPONSE_LIMIT || fseek(file, 0, SEEK_SET)) {
        fclose(file); return NULL;
    }
    char *body = malloc((size_t)n + 1);
    if (!body) { fclose(file); return NULL; }
    if (fread(body, 1, (size_t)n, file) != (size_t)n || ferror(file)) {
        free(body); fclose(file); return NULL;
    }
    fclose(file); body[n] = 0; *size = (size_t)n; return body;
}
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "binary")) {
        static const uint16_t statuses[] = {200, 403, 503};
        for (size_t i = 0; i < sizeof(statuses)/sizeof(statuses[0]); i++) {
            YDBinaryResponseMessage message = {.status = statuses[i], .body_length = 2,
                .representation_length = 2, .present = YD_BINARY_RESPONSE_ETAG | YD_BINARY_RESPONSE_ID};
            strcpy(message.content_type, "application/json");
            strcpy(message.revision, "abcdef0123456789");
            strcpy(message.etag, "\"1122334455667788\"");
            memset(message.request_id, 7, sizeof(message.request_id));
            yd_field_response_binary_metadata(&message);
            if (message.etag[0]) return 7;
            unsigned char bytes[YD_BINARY_METADATA_LIMIT];
            size_t size;
            YDBinaryResponseMessage decoded;
            if (!yd_binary_response_message_encode(&message, bytes, sizeof(bytes), &size) ||
                !yd_binary_response_message_decode(bytes, size, &decoded)) return 3;
            printf("%s %u %u %u %u %llu %llu\n", decoded.revision,
                !!(decoded.present & YD_BINARY_RESPONSE_ETAG), decoded.etag[0] == 0,
                decoded.request_id[0], decoded.status, (unsigned long long)decoded.body_length,
                (unsigned long long)decoded.representation_length);
        }
        return 0;
    }
    if (argc < 3) return 2;
    size_t size;
    char *body = read_file(argv[2], &size);
    if (!body) return 4;
    if (!strncmp(argv[1], "headers", 7)) {
        size_t capacity = size + (!strcmp(argv[1], "headers-unterminated") ? 0 : 1);
        bool ok = yd_field_response_headers(body, capacity);
        printf("%s\n", ok ? "OK" : "FAIL");
        if (ok) fwrite(body, 1, strlen(body), stdout);
        else for (size_t i = 0; i < capacity; i++) if (body[i]) return 5;
    } else {
        char *original = body, error[128];
        allocation_fault = argc > 3 && !strcmp(argv[3], "allocate");
        serialization_fault = argc > 3 && !strcmp(argv[3], "serialize");
        if (argc > 3 && !strcmp(argv[3], "oversize")) size = YD_FIELD_RESPONSE_LIMIT + (size_t)1;
        YDFieldResponseKind kind = !strcmp(argv[1], "json") ? YD_FIELD_RESPONSE_JSON :
            !strcmp(argv[1], "source") ? YD_FIELD_RESPONSE_SOURCE : (YDFieldResponseKind)0;
        bool ok = yd_field_response_body(kind, &body, &size, error, sizeof(error));
        allocation_fault = false; serialization_fault = false;
        if (!ok && (body || size)) return 6;
        printf("%s %u\n", ok ? "OK" : "FAIL",
            ok && kind == YD_FIELD_RESPONSE_SOURCE && body == original);
        if (ok) fwrite(body, 1, size, stdout);
    }
    free(body); return 0;
}
