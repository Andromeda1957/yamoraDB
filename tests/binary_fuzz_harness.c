/* Optional libFuzzer entry point for the native binary trust boundary. */
#include "../src/binary.h"
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const unsigned char *input, size_t length)
{
    YDValue *decoded = yd_value_decode(input, length, YD_DOCUMENT_LIMIT);
    yd_free(decoded);
    unsigned char *source = NULL;
    size_t source_length = 0;
    decoded = NULL;
    (void)yd_binary_unpack(input, length, &source, &source_length, &decoded);
    free(source); yd_free(decoded);

    if (length == 0 || length > YD_DOCUMENT_LIMIT) return 0;
    char error[256];
    YDValue *parsed = yd_parse(input, length, error, sizeof(error));
    if (parsed == NULL) return 0;
    size_t encoded_length = 0;
    unsigned char *encoded = yd_value_encode(parsed, &encoded_length);
    if (encoded == NULL) { yd_free(parsed); return 0; }
    decoded = yd_value_decode(encoded, encoded_length, length);
    if (decoded == NULL || !yd_equal(parsed, decoded)) abort();
    yd_free(decoded); free(encoded);

    size_t packed_length = 0;
    unsigned char *packed = yd_binary_pack(input, length, &packed_length, error, sizeof(error));
    if (packed != NULL) {
        source = NULL; decoded = NULL;
        if (!yd_binary_unpack(packed, packed_length, &source, &source_length, &decoded) ||
            source_length != length || memcmp(source, input, length) || !yd_equal(parsed, decoded)) abort();
        free(source); yd_free(decoded); free(packed);
    }
    yd_free(parsed); return 0;
}
