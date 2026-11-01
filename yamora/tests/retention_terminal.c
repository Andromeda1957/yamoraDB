#define _GNU_SOURCE
#include "retention_terminal.h"
#define OPENSSL_API_COMPAT 0x10100000L
#include <openssl/sha.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Instrument the actual digest calls. Each thread owns its fault/trace state.
 * Faults return failure AFTER doing the real work, including Final's output. */
static _Thread_local unsigned fail_call, calls;
static _Thread_local bool recording, trace_overflow, partial_final;
static _Thread_local size_t trace_size;
static _Thread_local unsigned char trace[YD_RETENTION_TERMINAL_SIZE];
int __real_SHA256_Init(SHA256_CTX *context);
int __real_SHA256_Update(SHA256_CTX *context, const void *bytes, size_t size);
int __real_SHA256_Final(unsigned char *hash, SHA256_CTX *context);
int __wrap_SHA256_Init(SHA256_CTX *context) {
    int result = __real_SHA256_Init(context);
    return ++calls == fail_call ? 0 : result;
}
int __wrap_SHA256_Update(SHA256_CTX *context, const void *bytes, size_t size) {
    if (recording) {
        if (size > sizeof(trace) - trace_size) trace_overflow = true;
        else { memcpy(trace + trace_size, bytes, size); trace_size += size; }
    }
    int result = __real_SHA256_Update(context, bytes, size);
    return ++calls == fail_call ? 0 : result;
}
int __wrap_SHA256_Final(unsigned char *hash, SHA256_CTX *context) {
    if (partial_final) {
        memset(hash,0xab,13);
        calls++;
        return 0;
    }
    int result = __real_SHA256_Final(hash, context);
    return ++calls == fail_call ? 0 : result;
}

static int failed(const char *name) {
    fprintf(stderr, "TERMINAL_ASSERT:%s\n", name);
    return 2;
}
#define CHECK(condition, name) do { if (!(condition)) return failed(name); } while (0)

static void standard(YDRetentionTerminalInput *input) {
    memset(input, 0, sizeof(*input));
    input->root_device = UINT64_C(0x0102030405060708);
    input->root_inode = UINT64_C(0x1112131415161718);
    input->journal_inode = UINT64_C(0x2122232425262728);
    input->file_size = 12345;
    input->fence_version = input->producer_protocol = 1;
    for (unsigned i = 0; i < 32; i++) input->incarnation[i] = (unsigned char)(i + 1);
    for (unsigned i = 0; i < sizeof(input->headers); i++)
        input->headers[i] = (unsigned char)(i * 37 + 11);
}
static bool zeros(const unsigned char *bytes, size_t size) {
    for (size_t i = 0; i < size; i++) if (bytes[i]) return false;
    return true;
}
static int vectors(void) {
    YDRetentionTerminalInput input;
    unsigned char hash[32];
    const unsigned char expected[32] = {
        0x8b,0x08,0xea,0x9a,0x0a,0x67,0x6f,0xd4,
        0x9a,0x4b,0x7e,0xf7,0x6f,0x15,0xaf,0xcf,
        0xf7,0xc8,0xce,0x6c,0x7b,0xdd,0xf0,0x00,
        0xab,0x22,0x1e,0xf4,0x73,0x76,0xe9,0x7e
    };
    standard(&input);
    CHECK(yd_retention_terminal_hash(&input, hash), "POSITIVE_HASH_REQUIRED");
    CHECK(!memcmp(hash, expected, sizeof(hash)), "LITERAL_STANDARD_DIGEST");
    memset(&input, 0, sizeof(input));
    input.root_inode = input.journal_inode = 1;
    input.file_size = 8192;
    input.fence_version = input.producer_protocol = 1;
    input.incarnation[0] = 1;
    const unsigned char minimum[32] = {
        0x7e,0x86,0xa2,0x8c,0x3f,0x5e,0xc0,0x0c,
        0xe5,0xc3,0x48,0x68,0x54,0x1a,0x0b,0xfc,
        0x82,0xd9,0x4e,0xf8,0xa3,0xa4,0x2b,0xe1,
        0x8a,0x11,0xbe,0xcc,0x2d,0x9c,0xdd,0xe4
    };
    CHECK(yd_retention_terminal_hash(&input, hash), "MINIMUM_DEVICE_ZERO_ACCEPTED");
    CHECK(!memcmp(hash, minimum, 32), "LITERAL_MINIMUM_DIGEST");
    input.root_device = input.root_inode = input.journal_device = input.journal_inode = UINT64_MAX;
    input.file_size = INT64_MAX;
    input.incarnation[0] = 0;
    input.incarnation[31] = 1;
    memset(input.headers, 255, sizeof(input.headers));
    const unsigned char maximum[32] = {
        0x9d,0x41,0xe5,0x33,0x0b,0x25,0xb2,0x47,
        0xf1,0x0e,0x66,0x06,0x9d,0xff,0xb4,0x59,
        0x68,0x9f,0x9d,0x71,0xc2,0x81,0x57,0xb1,
        0x4f,0x60,0x00,0x4f,0x62,0xc7,0xbf,0x3a
    };
    CHECK(yd_retention_terminal_hash(&input, hash), "MAXIMUM_UNALIGNED_EXTENT_ACCEPTED");
    CHECK(!memcmp(hash, maximum, 32), "LITERAL_MAXIMUM_DIGEST");
    return 0;
}

/* Independent literal standard prefix. Raw input is deliberately not a valid
 * native header: hashing it must succeed without minting validation authority. */
static const unsigned char expected_prefix[100] = {
    0x59,0x41,0x4d,0x4f,0x52,0x41,0x2d,0x54,0x45,0x52,0x4d,0x52,0x4f,0x4f,0x54,0x00,
    1,0,0,0, 1,0,0,0, 1,0,0,0,
    8,7,6,5,4,3,2,1, 0x18,0x17,0x16,0x15,0x14,0x13,0x12,0x11,
    0,0,0,0,0,0,0,0, 0x28,0x27,0x26,0x25,0x24,0x23,0x22,0x21,
    0x39,0x30,0,0,0,0,0,0,
    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
    17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32
};
static int wire(const char *field) {
    YDRetentionTerminalInput input, before;
    unsigned char hash[32];
    standard(&input);
    memcpy(&before, &input, sizeof(before));
    recording = true;
    CHECK(yd_retention_terminal_hash(&input, hash), "WIRE_HASH_REQUIRED");
    recording = false;
    CHECK(!trace_overflow && trace_size == YD_RETENTION_TERMINAL_SIZE, "CANONICAL_LENGTH");
    struct { const char *name; size_t offset, size; const char *assertion; } fields[] = {
        {"domain",0,16,"WIRE_DOMAIN"}, {"version",16,4,"WIRE_VERSION"},
        {"fence-wire",20,4,"WIRE_FENCE"}, {"protocol-wire",24,4,"WIRE_PROTOCOL"},
        {"root-device-wire",28,8,"WIRE_ROOT_DEVICE"},
        {"root-inode-wire",36,8,"WIRE_ROOT_INODE"},
        {"journal-device-wire",44,8,"WIRE_JOURNAL_DEVICE"},
        {"journal-inode-wire",52,8,"WIRE_JOURNAL_INODE"},
        {"extent-wire",60,8,"WIRE_EXTENT"}, {"birth-wire",68,32,"WIRE_BIRTH"}
    };
    for (unsigned i = 0; i < sizeof(fields)/sizeof(fields[0]); i++)
        if (!strcmp(field, fields[i].name)) {
            CHECK(!memcmp(trace + fields[i].offset, expected_prefix + fields[i].offset,
                fields[i].size), fields[i].assertion);
            CHECK(!memcmp(&before, &input, sizeof(input)), "WIRE_INPUT_UNCHANGED");
            return 0;
        }
    CHECK(!strcmp(field,"wire"), "WIRE_CASE_REQUIRED");
    CHECK(!memcmp(trace, expected_prefix, sizeof(expected_prefix)), "EXACT_CANONICAL_PREFIX");
    CHECK(!memcmp(trace + 100, input.headers, sizeof(input.headers)), "EXACT_ORDERED_RAW_PAIR");
    CHECK(!memcmp(&before, &input, sizeof(input)), "WIRE_INPUT_UNCHANGED");
    return 0;
}
static int invalid(const char *name) {
    for (unsigned variant = 0; variant < 3; variant++) {
        YDRetentionTerminalInput input, before;
        unsigned char hash[32];
        const char *witness = NULL;
        standard(&input);
        if (!strcmp(name,"fence")) {
            input.fence_version = variant == 0 ? 0 : variant == 1 ? 2 : UINT32_MAX;
            witness = "INVALID_FENCE";
        } else if (!strcmp(name,"protocol")) {
            input.producer_protocol = variant == 0 ? 0 : variant == 1 ? 2 : UINT32_MAX;
            witness = "INVALID_PROTOCOL";
        } else if (!strcmp(name,"root-inode")) {
            input.root_inode = 0; witness = "INVALID_ROOT_INODE";
        } else if (!strcmp(name,"journal-inode")) {
            input.journal_inode = 0; witness = "INVALID_JOURNAL_INODE";
        } else if (!strcmp(name,"birth")) {
            memset(input.incarnation,0,32); witness = "INVALID_BIRTH";
        } else if (!strcmp(name,"extent-low")) {
            input.file_size = variant == 0 ? 8191 : variant == 1 ? 0 : 4096;
            witness = "INVALID_EXTENT_LOW";
        } else if (!strcmp(name,"extent-high")) {
            input.file_size = variant == 0 ? (uint64_t)INT64_MAX + 1 : UINT64_MAX;
            witness = "INVALID_EXTENT_HIGH";
        }
        CHECK(witness, "INVALID_CASE_REQUIRED");
        memcpy(&before,&input,sizeof(input));
        memset(hash,0xa5,32);
        CHECK(!yd_retention_terminal_hash(&input,hash),witness);
        CHECK(zeros(hash,32), "INVALID_OUTPUT_CLEARED");
        CHECK(!memcmp(&before,&input,sizeof(input)), "INVALID_INPUT_UNCHANGED");
        CHECK(calls == 0, "INVALID_BEFORE_HASH_WORK");
    }
    return 0;
}
static int coverage(const char *name) {
    YDRetentionTerminalInput input, before;
    unsigned char original[32], changed[32];
    standard(&input);
    CHECK(yd_retention_terminal_hash(&input,original), "COVERAGE_HASH_REQUIRED");
    size_t first = !strcmp(name,"slot1") ? 4096 : 0;
    size_t last = first + 4096;
    const char *witness = first ? "SLOT1_EVERY_BYTE_BOUND" : "SLOT0_EVERY_BYTE_BOUND";
    for (size_t i = first; i < last; i++) {
        input.headers[i] ^= 1;
        memcpy(&before,&input,sizeof(input));
        CHECK(yd_retention_terminal_hash(&input,changed), "OPAQUE_BYTES_ACCEPTED");
        CHECK(memcmp(original,changed,32) != 0, witness);
        CHECK(!memcmp(&before,&input,sizeof(input)), "COVERAGE_INPUT_UNCHANGED");
        input.headers[i] ^= 1;
    }
    return 0;
}
static int order(void) {
    YDRetentionTerminalInput input;
    unsigned char hash[32], swapped[32], page[4096];
    standard(&input);
    /* The periodic standard pattern repeats across slots; make them distinct. */
    input.headers[4096] ^= 0x80;
    CHECK(yd_retention_terminal_hash(&input,hash), "ORDER_HASH_REQUIRED");
    memcpy(page,input.headers,4096);
    memcpy(input.headers,input.headers + 4096,4096);
    memcpy(input.headers + 4096,page,4096);
    CHECK(yd_retention_terminal_hash(&input,swapped), "ORDER_SWAP_HASH_REQUIRED");
    CHECK(memcmp(hash,swapped,32) != 0, "PHYSICAL_SLOT_ORDER_BOUND");
    return 0;
}
static int metadata_bits(void) {
    YDRetentionTerminalInput input;
    unsigned char original[32], changed[32];
    standard(&input);
    CHECK(yd_retention_terminal_hash(&input,original), "BITS_HASH_REQUIRED");
    uint64_t *fields[] = {&input.root_device,&input.root_inode,&input.journal_device,
        &input.journal_inode,&input.file_size};
    for (unsigned field = 0; field < 5; field++)
        for (unsigned bit = 0; bit < 64; bit++) {
            uint64_t saved = *fields[field];
            *fields[field] ^= UINT64_C(1) << bit;
            if (input.file_size >= 8192 && input.file_size <= INT64_MAX) {
                CHECK(yd_retention_terminal_hash(&input,changed), "VALID_METADATA_BIT_ACCEPTED");
                CHECK(memcmp(original,changed,32) != 0, "EVERY_METADATA_BIT_BOUND");
            }
            *fields[field] = saved;
        }
    for (unsigned bit = 0; bit < 256; bit++) {
        input.incarnation[bit/8] ^= (unsigned char)(1U << (bit%8));
        CHECK(yd_retention_terminal_hash(&input,changed), "VALID_BIRTH_BIT_ACCEPTED");
        CHECK(memcmp(original,changed,32) != 0, "EVERY_BIRTH_BIT_BOUND");
        input.incarnation[bit/8] ^= (unsigned char)(1U << (bit%8));
    }
    return 0;
}
static int padding(void) {
    YDRetentionTerminalInput a, b;
    unsigned char first[32], second[32];
    memset(&a,0xa5,sizeof(a)); memset(&b,0x5a,sizeof(b));
    a.root_device = b.root_device = 7;
    a.root_inode = b.root_inode = 8;
    a.journal_device = b.journal_device = 9;
    a.journal_inode = b.journal_inode = 10;
    a.file_size = b.file_size = 8193;
    a.fence_version = b.fence_version = 1;
    a.producer_protocol = b.producer_protocol = 1;
    memset(a.incarnation,1,32); memset(b.incarnation,1,32);
    memset(a.headers,11,sizeof(a.headers)); memset(b.headers,11,sizeof(b.headers));
    CHECK(yd_retention_terminal_hash(&a,first), "PADDING_FIRST_HASH_REQUIRED");
    CHECK(yd_retention_terminal_hash(&b,second), "PADDING_SECOND_HASH_REQUIRED");
    CHECK(!memcmp(first,second,32), "HOST_PADDING_IGNORED");
    return 0;
}
static int aliases(void) {
    YDRetentionTerminalInput input, expected, before;
    unsigned char hash[32];
    standard(&input);
    CHECK(yd_retention_terminal_hash(&input,hash), "ALIAS_REFERENCE_HASH_REQUIRED");
    /* Every possible 32-byte region, including typed fields and partial raw
     * page overlap; output is byte-aligned, input remains properly aligned. */
    for (size_t offset = 0; offset <= sizeof(input) - 32; offset++) {
        standard(&input);
        memcpy(&expected,&input,sizeof(input));
        memcpy((unsigned char *)&expected + offset,hash,32);
        CHECK(yd_retention_terminal_hash(&input,(unsigned char *)&input + offset),
            "ALIAS_SUCCESS_SNAPSHOT");
        CHECK(!memcmp(&input,&expected,sizeof(input)), "ALIAS_EXACT_OUTPUT_ONLY");
    }
    struct { unsigned char left[32]; YDRetentionTerminalInput value; unsigned char right[32]; }
        partial, partial_expected;
    for (unsigned side = 0; side < 2; side++) {
        memset(&partial,0xa5,sizeof(partial)); standard(&partial.value);
        memcpy(&partial_expected,&partial,sizeof(partial));
        size_t offset = side ? sizeof(partial) - 48 : 16;
        memcpy((unsigned char *)&partial_expected + offset,hash,32);
        CHECK(yd_retention_terminal_hash(&partial.value,(unsigned char *)&partial + offset),
            "PARTIAL_EDGE_ALIAS_SNAPSHOT");
        CHECK(!memcmp(&partial,&partial_expected,sizeof(partial)), "PARTIAL_EDGE_ALIAS_OUTPUT_ONLY");
    }
    standard(&input); input.root_inode = 0;
    memcpy(&expected,&input,sizeof(input)); memset(&expected,0,32);
    CHECK(!yd_retention_terminal_hash(&input,(unsigned char *)&input), "ALIAS_INVALID_REFUSED");
    CHECK(!memcmp(&input,&expected,sizeof(input)), "ALIAS_INVALID_CLEARED");
    standard(&input); memcpy(&before,&input,sizeof(input));
    fail_call = 4; calls = 0;
    CHECK(!yd_retention_terminal_hash(&input,input.headers + 17), "ALIAS_FAILED_FINAL_REFUSED");
    memset(before.headers + 17,0,32);
    CHECK(!memcmp(&input,&before,sizeof(input)), "ALIAS_FAILED_FINAL_CLEARED");
    return 0;
}
static int boundaries(void) {
    long page_value = sysconf(_SC_PAGESIZE);
    CHECK(page_value > 0, "PAGE_SIZE_AVAILABLE");
    size_t page = (size_t)page_value;
    size_t pages = (sizeof(YDRetentionTerminalInput) + page - 1) / page;
    size_t length = (pages + 2) * page;
    unsigned char *mapping = mmap(NULL,length,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    CHECK(mapping != MAP_FAILED, "GUARD_MAPPING_AVAILABLE");
    CHECK(!mprotect(mapping,page,PROT_NONE), "FIRST_GUARD_AVAILABLE");
    CHECK(!mprotect(mapping + (pages+1)*page,page,PROT_NONE), "LAST_GUARD_AVAILABLE");
    YDRetentionTerminalInput *input = (void *)(mapping + (pages+1)*page - sizeof(*input));
    standard(input);
    CHECK(!mprotect(mapping + page,pages*page,PROT_READ), "READ_ONLY_INPUT_AVAILABLE");
    unsigned char out[34]; memset(out,0xa5,sizeof(out));
    CHECK(!yd_retention_terminal_hash((const void *)mapping,NULL), "NULL_OUTPUT_NO_INPUT_READ");
    CHECK(!yd_retention_terminal_hash(NULL,out+1), "NULL_INPUT_REFUSED");
    CHECK(out[0] == 0xa5 && out[33] == 0xa5 && zeros(out+1,32), "NULL_INPUT_EXACT_CLEAR");
    CHECK(!yd_retention_terminal_hash(NULL,NULL), "BOTH_NULL_REFUSED");
    CHECK(yd_retention_terminal_hash(input,out+1), "READ_ONLY_INPUT_ACCEPTED");
    CHECK(out[0] == 0xa5 && out[33] == 0xa5, "EXACT_OUTPUT_BOUNDS");
    CHECK(!munmap(mapping,length), "GUARD_MAPPING_RELEASED");
    return 0;
}
static int faults(unsigned fault) {
    YDRetentionTerminalInput input, before;
    unsigned char hash[34];
    const char *names[] = {"", "HASH_INIT_FAILURE", "HASH_PREFIX_FAILURE",
        "HASH_HEADERS_FAILURE", "HASH_FINAL_FAILURE", "HASH_PARTIAL_FINAL_FAILURE"};
    standard(&input); memcpy(&before,&input,sizeof(input));
    partial_final = fault == 5;
    fail_call = partial_final ? 4 : fault; calls = 0; memset(hash,0xa5,sizeof(hash));
    CHECK(!yd_retention_terminal_hash(&input,hash+1),names[fault]);
    CHECK(zeros(hash+1,32), "FAILED_HASH_OUTPUT_CLEARED");
    CHECK(hash[0] == 0xa5 && hash[33] == 0xa5, "FAILED_HASH_EXACT_OUTPUT_BOUNDS");
    CHECK(!memcmp(&before,&input,sizeof(input)), "FAILED_HASH_INPUT_UNCHANGED");
    CHECK(calls == fail_call, "FAILED_HASH_STOPS_WORK");
    return 0;
}
typedef struct {
    const YDRetentionTerminalInput *input;
    const unsigned char *expected;
    bool okay;
} Worker;
static void *thread_hash(void *argument) {
    Worker *worker = argument;
    worker->okay = true;
    for (unsigned i = 0; i < 1500; i++) {
        unsigned char hash[32];
        if (!yd_retention_terminal_hash(worker->input,hash) || memcmp(hash,worker->expected,32)) {
            worker->okay = false; break;
        }
    }
    return NULL;
}
static int threads(void) {
    YDRetentionTerminalInput input, before;
    unsigned char expected[32];
    standard(&input); memcpy(&before,&input,sizeof(input));
    CHECK(yd_retention_terminal_hash(&input,expected), "THREAD_REFERENCE_REQUIRED");
    Worker workers[8]; pthread_t handles[8]; unsigned started = 0;
    for (unsigned i = 0; i < 8; i++) {
        workers[i] = (Worker){&input,expected,false};
        if (pthread_create(&handles[i],NULL,thread_hash,&workers[i])) break;
        started++;
    }
    bool joined = true, okay = started == 8;
    for (unsigned i = 0; i < started; i++) {
        if (pthread_join(handles[i],NULL)) joined = false;
        else if (!workers[i].okay) okay = false;
    }
    CHECK(joined, "ALL_THREADS_JOINED");
    CHECK(okay, "SHARED_IMMUTABLE_CONCURRENT_HASHES");
    CHECK(!memcmp(&before,&input,sizeof(input)), "THREAD_INPUT_UNCHANGED");
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 2) return failed("CASE_REQUIRED");
    const char *name = argv[1]; int result;
    if (!strcmp(name,"vectors")) result = vectors();
    else if (!strcmp(name,"slot0") || !strcmp(name,"slot1")) result = coverage(name);
    else if (!strcmp(name,"order")) result = order();
    else if (!strcmp(name,"metadata-bits")) result = metadata_bits();
    else if (!strcmp(name,"padding")) result = padding();
    else if (!strcmp(name,"aliases")) result = aliases();
    else if (!strcmp(name,"boundaries")) result = boundaries();
    else if (!strcmp(name,"threads")) result = threads();
    else if (!strncmp(name,"fault",5) && name[5] >= '1' && name[5] <= '5' && !name[6])
        result = faults((unsigned)(name[5] - '0'));
    else if (!strncmp(name,"invalid-",8)) result = invalid(name+8);
    else result = wire(name);
    if (!result) puts("TERMINAL_OK");
    return result;
}
