#define _POSIX_C_SOURCE 200809L
#include "security/envelope.h"
#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "contract failure at %d: %s\n", __LINE__, #x); return 1; } } while (0)
static const char *fault;
int __real_RAND_bytes(unsigned char *, int);
int __wrap_RAND_bytes(unsigned char *p, int n) {
    return fault && !strcmp(fault, "nonce") ? 0 : __real_RAND_bytes(p, n);
}
int __real_RAND_priv_bytes(unsigned char *, int);
int __wrap_RAND_priv_bytes(unsigned char *p, int n) {
    return fault && !strcmp(fault, "random-key") ? 0 : __real_RAND_priv_bytes(p, n);
}
EVP_CIPHER_CTX *__real_EVP_CIPHER_CTX_new(void);
EVP_CIPHER_CTX *__wrap_EVP_CIPHER_CTX_new(void) {
    return fault && !strcmp(fault, "context") ? NULL : __real_EVP_CIPHER_CTX_new();
}
int __real_EVP_EncryptInit_ex(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *, const unsigned char *, const unsigned char *);
int __wrap_EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *engine,
    const unsigned char *key, const unsigned char *iv) {
    return fault && !strcmp(fault, "encrypt-init") ? 0 : __real_EVP_EncryptInit_ex(ctx, type, engine, key, iv);
}
int __real_EVP_DecryptFinal_ex(EVP_CIPHER_CTX *, unsigned char *, int *);
int __wrap_EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *n) {
    return fault && !strcmp(fault, "tag") ? 0 : __real_EVP_DecryptFinal_ex(ctx, out, n);
}
static unsigned cleanse_count;
static void *monitored_release;
static size_t monitored_length;
void __real_free(void *);
void __wrap_free(void *data) {
    if (data && data == monitored_release) {
        for (size_t i = 0; i < monitored_length; ++i)
            if (((unsigned char *)data)[i]) {
                fputs("cleanse contract failure before release\n", stderr); _Exit(1);
            }
        monitored_release = NULL; monitored_length = 0;
    }
    __real_free(data);
}
void __real_OPENSSL_cleanse(void *, size_t);
void __wrap_OPENSSL_cleanse(void *data, size_t n) {
    __real_OPENSSL_cleanse(data, n);
    for (size_t i = 0; i < n; ++i)
        if (((unsigned char *)data)[i]) abort();
    ++cleanse_count;
}
static YDEnvelopeIdentity identity(void) {
    YDEnvelopeIdentity id = {.generation = 7, .kind = 3};
    memset(id.store_id, 0x51, sizeof(id.store_id));
    memset(id.object_id, 0xa2, sizeof(id.object_id));
    return id;
}
static const unsigned char authored[] = "# authored comment\nname: 'caf\xc3\xa9'\nnumber: 01\nbody: |\n  exact bytes\n";
static YDKeyProvider *local(const char *first, const char *second, bool wrong) {
    YDKeyEntry entries[2] = {{.id = first}, {.id = second}};
    memset(entries[0].bytes, wrong ? 0x19 : 0xc7, 32);
    memset(entries[1].bytes, 0x5a, 32);
    YDKeyProvider *provider = yd_key_provider_local(entries, second ? 2 : 1);
    OPENSSL_cleanse(entries, sizeof(entries));
    return provider;
}
static int opened(const YDKeyProvider *provider, const YDEnvelopeIdentity *id,
    const unsigned char *wire, size_t n, const unsigned char *wanted, size_t length) {
    unsigned char *plain = NULL; size_t used = 0;
    YDEnvelopeResult result = yd_envelope_open(provider, id, wire, n, &plain, &used);
    int okay = result == YD_ENVELOPE_OK && used == length && (!length || !memcmp(plain, wanted, length));
    monitored_release = plain; monitored_length = used ? used : 1;
    yd_envelope_free(plain, used); return okay;
}
static int rejected(const YDKeyProvider *provider, const YDEnvelopeIdentity *id,
    const unsigned char *wire, size_t n) {
    unsigned char *plain = (unsigned char *)1; size_t used = 123;
    YDEnvelopeResult result = yd_envelope_open(provider, id, wire, n, &plain, &used);
    return result != YD_ENVELOPE_OK && plain == NULL && used == 0;
}
static int lifecycle(void) {
    YDEnvelopeIdentity id = identity(), newer = id;
    YDKeyProvider *all = local("kek-v1", "kek-v2", false);
    YDKeyProvider *lost = local("kek-v2", NULL, false), *wrong = local("kek-v1", NULL, true);
    YDKeyProvider *restored = local("kek-v1", NULL, false);
    REQUIRE(all && lost && wrong && restored);
    unsigned char *wire = NULL, *second = NULL, *rotated = NULL;
    size_t length = 0, second_len = 0, rotated_len = 0;
    REQUIRE(yd_envelope_seal(all, "kek-v1", &id, authored, sizeof(authored) - 1U, &wire, &length) == YD_ENVELOPE_OK);
    REQUIRE(opened(all, &id, wire, length, authored, sizeof(authored) - 1U));
    REQUIRE(yd_envelope_seal(all, "kek-v1", &id, authored, sizeof(authored) - 1U, &second, &second_len) == YD_ENVELOPE_OK);
    REQUIRE(length == second_len && memcmp(wire, second, length));
    REQUIRE(rejected(lost, &id, wire, length));
    REQUIRE(rejected(wrong, &id, wire, length));
    REQUIRE(opened(restored, &id, wire, length, authored, sizeof(authored) - 1U));
    REQUIRE(yd_envelope_rotate(all, all, "kek-v2", &id, 8, wire, length, &rotated, &rotated_len) == YD_ENVELOPE_OK);
    newer.generation = 8;
    REQUIRE(opened(all, &newer, rotated, rotated_len, authored, sizeof(authored) - 1U));
    REQUIRE(rejected(restored, &newer, rotated, rotated_len));
    REQUIRE(rejected(all, &newer, wire, length));
    REQUIRE(rejected(all, &id, rotated, rotated_len));
    REQUIRE(opened(restored, &id, wire, length, authored, sizeof(authored) - 1U));
    /* The one-key replacement has the actual v2 material, not a new v1 key. */
    YDKeyEntry recovery = {.id = "kek-v2"}; memset(recovery.bytes, 0x5a, 32);
    YDKeyProvider *v2 = yd_key_provider_local(&recovery, 1);
    OPENSSL_cleanse(&recovery, sizeof(recovery));
    REQUIRE(v2 && opened(v2, &newer, rotated, rotated_len, authored, sizeof(authored) - 1U));
    unsigned char *failed = (unsigned char *)1; size_t failed_len = 55;
    REQUIRE(yd_envelope_rotate(all, all, "kek-v2", &id, 7, wire, length, &failed, &failed_len) == YD_ENVELOPE_ERROR);
    REQUIRE(!failed && !failed_len);
    REQUIRE(yd_envelope_rotate(all, lost, "absent", &id, 8, wire, length, &failed, &failed_len) != YD_ENVELOPE_OK);
    REQUIRE(!failed && !failed_len && opened(all, &id, wire, length, authored, sizeof(authored) - 1U));
    yd_envelope_free(wire, length); yd_envelope_free(second, second_len);
    yd_envelope_free(rotated, rotated_len);
    yd_key_provider_free(v2); yd_key_provider_free(all); yd_key_provider_free(lost);
    yd_key_provider_free(wrong); yd_key_provider_free(restored);
    REQUIRE(cleanse_count > 20);
    puts("lifecycle: exact YAML, fresh randomness, key loss/recovery, rotation/rollback, failed rotation preserved");
    return 0;
}
static int guards(void) {
    YDEnvelopeIdentity id = identity();
    YDKeyProvider *provider = local("kek-v1", NULL, false);
    REQUIRE(provider);
    unsigned char *wire = NULL; size_t length = 0;
    REQUIRE(yd_envelope_seal(provider, "kek-v1", &id, authored, sizeof(authored) - 1U, &wire, &length) == YD_ENVELOPE_OK);
    REQUIRE(opened(provider, &id, wire, length, authored, sizeof(authored) - 1U));
    for (size_t i = 0; i < length; ++i) {
        wire[i] ^= 1;
        REQUIRE(rejected(provider, &id, wire, length));
        wire[i] ^= 1;
    }
    for (size_t i = 0; i < length; ++i) REQUIRE(rejected(provider, &id, wire, i));
    YDEnvelopeIdentity changed = id;
    changed.store_id[0] ^= 1; REQUIRE(rejected(provider, &changed, wire, length));
    changed = id; changed.object_id[0] ^= 1; REQUIRE(rejected(provider, &changed, wire, length));
    changed = id; ++changed.kind; REQUIRE(rejected(provider, &changed, wire, length));
    changed = id; ++changed.generation; REQUIRE(rejected(provider, &changed, wire, length));
    unsigned char extra[YD_ENVELOPE_HEADER_BYTES + 8192] = {0};
    REQUIRE(length < sizeof(extra)); memcpy(extra, wire, length);
    REQUIRE(rejected(provider, &id, extra, length + 1));
    const char *faults[] = {"random-key", "nonce", "context", "encrypt-init"};
    for (size_t i = 0; i < sizeof(faults) / sizeof(faults[0]); ++i) {
        unsigned char *out = (unsigned char *)1; size_t n = 3;
        fault = faults[i];
        REQUIRE(yd_envelope_seal(provider, "kek-v1", &id, authored, sizeof(authored) - 1U, &out, &n) == YD_ENVELOPE_ERROR);
        REQUIRE(!out && !n); fault = NULL;
    }
    fault = "tag"; REQUIRE(rejected(provider, &id, wire, length)); fault = NULL;
    unsigned char *empty = NULL; size_t empty_len = 0;
    REQUIRE(yd_envelope_seal(provider, "kek-v1", &id, NULL, 0, &empty, &empty_len) == YD_ENVELOPE_OK);
    REQUIRE(opened(provider, &id, empty, empty_len, NULL, 0));
    yd_envelope_free(empty, empty_len); yd_envelope_free(wire, length); yd_key_provider_free(provider);
    puts("guards: every wire byte, all truncations, identity/generation, RNG/provider failures, empty payload");
    return 0;
}

/* Test-only real TLS/HTTP transport. It accepts only loopback and a generated
 * test CA; product adapters do not own credential/TLS transport policy. */
typedef struct { unsigned port; const char *ca; bool cancel_self; } HTTPFixture;
static YDKeyResult http_fixture(void *opaque, const char *path, const char *target,
    const unsigned char *body, size_t n, unsigned *status, unsigned char *response,
    size_t capacity, size_t *response_len) {
    HTTPFixture *fixture = opaque;
    if (fixture->cancel_self) {
        if (pthread_cancel(pthread_self())) return YD_KEY_ERROR;
        pthread_testcancel(); /* MUST remain pending while the caller owns data. */
    }
    int fd = -1;
    SSL_CTX *ctx = NULL; SSL *ssl = NULL;
    YDKeyResult result = YD_KEY_ERROR;
    unsigned char wire[YD_KEY_HTTP_MAX + 4096];
    char header[1024];
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons((uint16_t)fixture->port)};
    struct timeval timeout = {.tv_sec = 2};
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) ||
        connect(fd, (struct sockaddr *)&address, sizeof(address))) goto done;
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx || SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_load_verify_locations(ctx, fixture->ca, NULL) != 1) goto done;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    ssl = SSL_new(ctx);
    if (!ssl || SSL_set_fd(ssl, fd) != 1 || SSL_set1_host(ssl, "localhost") != 1 ||
        SSL_set_tlsext_host_name(ssl, "localhost") != 1 || SSL_connect(ssl) != 1 ||
        SSL_get_verify_result(ssl) != X509_V_OK) goto done;
    int hn = snprintf(header, sizeof(header),
        "POST %s HTTP/1.0\r\nHost: localhost\r\nX-Amz-Target: %s\r\nContent-Type: %s\r\n"
        "X-Fixture-Authorization: synthetic-only\r\nContent-Length: %zu\r\n\r\n", path, target,
        *target ? "application/x-amz-json-1.1" : "application/json", n);
    if (hn < 0 || (size_t)hn >= sizeof(header)) goto done;
    size_t sent = 0;
    if (SSL_write_ex(ssl, header, (size_t)hn, &sent) != 1 || sent != (size_t)hn ||
        SSL_write_ex(ssl, body, n, &sent) != 1 || sent != n) goto done;
    size_t used = 0, start = 0, wanted = 0;
    bool parsed = false;
    while (used < sizeof(wire) - 1) {
        size_t got = 0;
        if (SSL_read_ex(ssl, wire + used, sizeof(wire) - 1 - used, &got) != 1 || !got) break;
        used += got; wire[used] = 0;
        if (!parsed) {
            char *end = strstr((char *)wire, "\r\n\r\n");
            if (!end) continue;
            start = (size_t)(end - (char *)wire) + 4;
            unsigned parsed_status = 0;
            if (sscanf((char *)wire, "HTTP/1.0 %u", &parsed_status) != 1) goto done;
            char *length = strstr((char *)wire, "Content-Length: ");
            if (!length || length >= end || sscanf(length, "Content-Length: %zu", &wanted) != 1 ||
                wanted > capacity) goto done;
            *status = parsed_status; parsed = true;
        }
        if (parsed && used >= start + wanted) break;
    }
    if (!parsed || used != start + wanted) goto done;
    memcpy(response, wire + start, wanted); *response_len = wanted; result = YD_KEY_OK;
done:
    OPENSSL_cleanse(wire, sizeof(wire));
    SSL_free(ssl); SSL_CTX_free(ctx); if (fd >= 0) close(fd);
    return result;
}
static const char aws_id[] = "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555";
static int bounds(void) {
    YDEnvelopeIdentity id = identity(), zero = {0};
    YDKeyProvider *provider = local("kek-v1", NULL, false);
    REQUIRE(provider);
    YDKeyEntry entries[2] = {{.id = "duplicate"}, {.id = "duplicate"}};
    REQUIRE(!yd_key_provider_local(NULL, 1));
    REQUIRE(!yd_key_provider_local(entries, 0));
    REQUIRE(!yd_key_provider_local(entries, YD_KEY_RING_MAX + 1));
    REQUIRE(!yd_key_provider_local(entries, 2));
    entries[0].id = "path/../bad key";
    REQUIRE(!yd_key_provider_local(entries, 1));
    REQUIRE(!yd_key_provider_aws("arn:aws:kms:us-east-1:1:alias/mutable", NULL, NULL));
    unsigned char *out = (unsigned char *)1; size_t n = 9;
    REQUIRE(yd_envelope_seal(provider, "kek-v1", &id, (const unsigned char *)1,
        YD_ENVELOPE_PLAINTEXT_MAX + 1UL, &out, &n) == YD_ENVELOPE_ERROR);
    REQUIRE(!out && !n);
    REQUIRE(yd_envelope_seal(provider, "kek-v1", &zero, authored, sizeof(authored) - 1U, &out, &n) == YD_ENVELOPE_ERROR);
    REQUIRE(!out && !n);
    REQUIRE(yd_envelope_seal(provider, "bad id", &id, authored, sizeof(authored) - 1U, &out, &n) == YD_ENVELOPE_ERROR);
    REQUIRE(!out && !n);
    REQUIRE(rejected(provider, &id, (const unsigned char *)1, YD_ENVELOPE_WIRE_MAX + 1UL));
    unsigned char key[32], context[32] = {0}, wrapped[YD_KEY_WRAPPED_MAX]; size_t used = 91;
    memset(key, 0x44, sizeof(key)); memset(wrapped, 0x55, sizeof(wrapped));
    REQUIRE(yd_key_provider_wrap(provider, "missing", context, key, wrapped, &used) == YD_KEY_REJECTED);
    REQUIRE(!used);
    for (size_t i = 0; i < sizeof(wrapped); ++i) REQUIRE(!wrapped[i]);
    REQUIRE(yd_key_provider_unwrap(provider, "kek-v1", context, wrapped, sizeof(wrapped) + 1, key) == YD_KEY_REJECTED);
    for (size_t i = 0; i < sizeof(key); ++i) REQUIRE(!key[i]);
    OPENSSL_cleanse(entries, sizeof(entries)); yd_key_provider_free(provider);
    puts("bounds: configurations, sizes, output clearing and absent keys");
    return 0;
}
static int archive(const char *mode, const char *path) {
    YDEnvelopeIdentity id = identity();
    bool write = !strcmp(mode, "write");
    bool wrong = !strcmp(mode, "wrong");
    bool missing = !strcmp(mode, "missing");
    YDKeyProvider *provider = local(missing ? "unavailable" : "kek-v1", NULL, wrong);
    REQUIRE(provider);
    unsigned char *wire = NULL; size_t length = 0;
    if (write) {
        REQUIRE(yd_envelope_seal(provider, "kek-v1", &id, authored, sizeof(authored) - 1U, &wire, &length) == YD_ENVELOPE_OK);
        FILE *file = fopen(path, "wb"); REQUIRE(file);
        REQUIRE(fwrite(wire, 1, length, file) == length && fclose(file) == 0);
    } else {
        FILE *file = fopen(path, "rb"); REQUIRE(file);
        REQUIRE(fseek(file, 0, SEEK_END) == 0);
        long size = ftell(file);
        REQUIRE(size > 0 && size <= (long)YD_ENVELOPE_WIRE_MAX && fseek(file, 0, SEEK_SET) == 0);
        length = (size_t)size; wire = malloc(length); REQUIRE(wire);
        REQUIRE(fread(wire, 1, length, file) == length && fclose(file) == 0);
        REQUIRE((wrong || missing) ? rejected(provider, &id, wire, length) :
            opened(provider, &id, wire, length, authored, sizeof(authored) - 1U));
    }
    yd_envelope_free(wire, length); yd_key_provider_free(provider);
    puts("archive: independent-process persistence/recovery contract"); return 0;
}
static int provider_case(const char *kind, unsigned port, const char *ca, const char *mode) {
    HTTPFixture fixture = {.port = port, .ca = ca, .cancel_self = !strcmp(mode, "cancel")};
    bool aws = !strcmp(kind, "aws");
    bool history = !strcmp(mode, "history");
    YDKeyProvider *provider = aws ? yd_key_provider_aws(aws_id, http_fixture, &fixture) :
        yd_key_provider_vault("transit", "yamora-test", history ? 1 : 2, http_fixture, &fixture);
    REQUIRE(provider);
    YDKeyProvider *target = history ?
        yd_key_provider_vault("transit", "yamora-test", 2, http_fixture, &fixture) : provider;
    REQUIRE(target);
    YDEnvelopeIdentity id = identity();
    const char *key_id = aws ? aws_id : "yamora-test";
    unsigned char *wire = NULL; size_t length = 0;
    YDEnvelopeResult result = yd_envelope_seal(provider, key_id, &id, authored, sizeof(authored) - 1U, &wire, &length);
    if (!strcmp(mode, "deny")) {
        REQUIRE(result != YD_ENVELOPE_OK && !wire && !length);
    } else if (!strcmp(mode, "unwrap-deny")) {
        REQUIRE(result == YD_ENVELOPE_OK && rejected(provider, &id, wire, length));
    } else {
        REQUIRE(result == YD_ENVELOPE_OK && opened(provider, &id, wire, length, authored, sizeof(authored) - 1U));
        unsigned char *rotated = NULL; size_t rotated_len = 0;
        REQUIRE(yd_envelope_rotate(provider, target, key_id, &id, 8, wire, length, &rotated, &rotated_len) == YD_ENVELOPE_OK);
        YDEnvelopeIdentity next = id; next.generation = 8;
        REQUIRE(opened(target, &next, rotated, rotated_len, authored, sizeof(authored) - 1U));
        REQUIRE(opened(target, &id, wire, length, authored, sizeof(authored) - 1U));
        REQUIRE(rejected(provider, &next, wire, length));
        wire[88] ^= 1; /* Same identity, changed provider encryption context. */
        REQUIRE(rejected(provider, &id, wire, length)); wire[88] ^= 1;
        wire[length - 1] ^= 1;
        REQUIRE(rejected(provider, &id, wire, length)); wire[length - 1] ^= 1;
        wire[YD_ENVELOPE_HEADER_BYTES + strlen(key_id) + 15] ^= 1;
        REQUIRE(rejected(provider, &id, wire, length));
        yd_envelope_free(rotated, rotated_len);
    }
    yd_envelope_free(wire, length);
    if (target != provider) yd_key_provider_free(target);
    yd_key_provider_free(provider);
    puts(!strcmp(mode, "deny") || !strcmp(mode, "unwrap-deny") ? "provider: fail closed" :
        "provider: TLS fixture wrap/unwrap/rotate preserved bytes");
    return 0;
}
typedef struct {
    const YDKeyProvider *provider;
    const unsigned char *wire;
    size_t length;
    int completed;
} EnabledCase;
static void *enabled_caller(void *opaque) {
    EnabledCase *test = opaque;
    YDEnvelopeIdentity id = identity();
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)) return NULL;
    unsigned char *out = (unsigned char *)1; size_t n = 17;
    if (yd_envelope_seal(test->provider, "kek-v1", &id, authored, sizeof(authored) - 1U, &out, &n) != YD_ENVELOPE_ERROR ||
        out || n) return NULL;
    if (yd_envelope_open(test->provider, &id, test->wire, test->length, &out, &n) != YD_ENVELOPE_ERROR ||
        out || n) return NULL;
    if (yd_envelope_rotate(test->provider, test->provider, "kek-v1", &id, 8, test->wire,
        test->length, &out, &n) != YD_ENVELOPE_ERROR || out || n) return NULL;
    unsigned char key[32] = {0}, context[32] = {0}, wrapped[YD_KEY_WRAPPED_MAX] = {0};
    if (yd_key_provider_wrap(test->provider, "kek-v1", context, key, wrapped, &n) != YD_KEY_ERROR || n)
        return NULL;
    if (yd_key_provider_unwrap(test->provider, "kek-v1", context, wrapped, 60, key) != YD_KEY_ERROR)
        return NULL;
    for (size_t i = 0; i < sizeof(key); ++i) if (key[i]) return NULL;
    test->completed = 1; return NULL;
}
static int cancellation_contract(void) {
    YDKeyProvider *provider = local("kek-v1", NULL, false);
    REQUIRE(provider);
    YDEnvelopeIdentity id = identity();
    unsigned char *wire = NULL; size_t length = 0;
    REQUIRE(yd_envelope_seal(provider, "kek-v1", &id, authored, sizeof(authored) - 1U, &wire, &length) == YD_ENVELOPE_OK);
    EnabledCase test = {.provider = provider, .wire = wire, .length = length};
    pthread_t thread; void *result = NULL;
    REQUIRE(!pthread_create(&thread, NULL, enabled_caller, &test));
    REQUIRE(!pthread_join(thread, &result) && result == NULL && test.completed == 1);
    yd_envelope_free(wire, length); yd_key_provider_free(provider);
    puts("cancellation: enabled calls reject before sensitive ownership"); return 0;
}
typedef struct { const char *kind, *ca; unsigned port; int completed, after_enable; } CancelCase;
static void *pending_caller(void *opaque) {
    CancelCase *test = opaque;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL)) return NULL;
    test->completed = provider_case(test->kind, test->port, test->ca, "cancel") == 0;
    (void)pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_testcancel();
    test->after_enable = 1; return NULL;
}
static int pending_cancellation(const char *kind, unsigned port, const char *ca) {
    CancelCase test = {.kind = kind, .ca = ca, .port = port};
    pthread_t thread; void *result = NULL;
    REQUIRE(!pthread_create(&thread, NULL, pending_caller, &test));
    REQUIRE(!pthread_join(thread, &result) && result == PTHREAD_CANCELED &&
        test.completed == 1 && test.after_enable == 0);
    puts("cancellation: pending provider cancel delivered only after adopted buffers cleansed"); return 0;
}
int main(int argc, char **argv) {
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL)) return 2;
    if (argc == 2 && !strcmp(argv[1], "lifecycle")) return lifecycle();
    if (argc == 2 && !strcmp(argv[1], "guards")) return guards();
    if (argc == 2 && !strcmp(argv[1], "bounds")) return bounds();
    if (argc == 4 && !strcmp(argv[1], "archive")) return archive(argv[2], argv[3]);
    if (argc == 2 && !strcmp(argv[1], "cancel-contract")) return cancellation_contract();
    if (argc == 5 && !strcmp(argv[1], "provider-cancel"))
        return pending_cancellation(argv[2], (unsigned)strtoul(argv[3], NULL, 10), argv[4]);
    if (argc == 6 && !strcmp(argv[1], "provider"))
        return provider_case(argv[2], (unsigned)strtoul(argv[3], NULL, 10), argv[4], argv[5]);
    return 2;
}
