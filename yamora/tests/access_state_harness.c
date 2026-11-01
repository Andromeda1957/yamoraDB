/* Stored runtime access state from standard input: strict parse, then the
 * canonical encoding. Prints INVALID, or VALID with the version, counts and
 * whether re-encoding reproduced the input exactly. */
#include "../src/security/access_state.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    static unsigned char input[256 * 1024];
    size_t length = fread(input, 1, sizeof(input), stdin);
    if (ferror(stdin) || !feof(stdin)) return 2;
    YDAccessState *state = yd_access_state_parse(input, length);
    if (!state) {
        puts("INVALID");
        return 0;
    }
    size_t size = 0;
    char *encoded = yd_access_state_encode(state, &size);
    if (!encoded) return 3;
    printf("VALID %llu %zu %zu %s\n", (unsigned long long)state->version, state->role_count,
        state->principal_count,
        size == length && !memcmp(encoded, input, length) ? "canonical" : "rewritten");
    free(encoded);
    yd_access_state_free(state);
    return 0;
}
