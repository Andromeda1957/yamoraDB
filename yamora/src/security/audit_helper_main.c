#include "audit_helper.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>
static bool number(const char *s, uint64_t *out) {
    if (!s || !*s || (*s == '0' && s[1])) return false;
    uint64_t n = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9' || n > (UINT64_MAX - (unsigned)(*s - '0')) / 10) return false;
        n = n * 10 + (unsigned)(*s - '0');
    }
    *out = n; return true;
}
static int hex(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; }
int main(int argc, char **argv) {
    YDAuditHelperOptions o = {0}; unsigned seen = 0;
    static const char *names[] = {"--key-file", "--key-id", "--audit-dir", "--anchor-dir", "--socket",
        "--daemon-uid", "--mode", "--segment-records", "--segments", "--max-bytes", "--pending"};
    for (int i = 1; i < argc; i += 2) {
        unsigned n = 0;
        while (n < 11 && strcmp(argv[i], names[n])) n++;
        if (n == 11 || i + 1 == argc || seen & (1U << n)) goto invalid;
        seen |= 1U << n;
        const char *value = argv[i + 1]; uint64_t v = 0;
        switch (n) {
            case 0: o.key_file = value; break;
            case 1:
                if (strlen(value) != 32) goto invalid;
                for (unsigned j = 0; j < 16; j++) {
                    int a = hex(value[j * 2]), b = hex(value[j * 2 + 1]);
                    if (a < 0 || b < 0) goto invalid;
                    o.key_id[j] = (unsigned char)((a << 4) | b);
                }
                break;
            case 2: o.audit_directory = value; break;
            case 3: o.anchor_directory = value; break;
            case 4: o.socket = value; break;
            case 6:
                if (strcmp(value, "create") && strcmp(value, "resume")) goto invalid;
                o.create = !strcmp(value, "create"); break;
            default:
                if (!number(value, &v)) goto invalid;
                if (n == 5) { if (!v || v > UINT_MAX) goto invalid; o.daemon_uid = (uid_t)v; }
                if (n == 7) o.limits.segment_records = v;
                if (n == 8) o.limits.segments = v;
                if (n == 9) o.limits.bytes = v;
                if (n == 10) { if (v > UINT32_MAX) goto invalid; o.limits.pending = (uint32_t)v; }
        }
    }
    if (seen != 2047) goto invalid;
    return yd_audit_helper_run(&o);
invalid:
    fputs("invalid audit helper configuration\n", stderr); return 2;
}
