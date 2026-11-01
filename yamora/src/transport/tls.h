#ifndef YAMORA_TRANSPORT_TLS_H
#define YAMORA_TRANSPORT_TLS_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct YDTLS YDTLS;
/* NULL crl_file disables revocation. Otherwise CA trust is mandatory; the file
 * contains complete, direct issuer PEM CRLs, at most 1 MiB and 64 issuers. */
typedef struct {
    const char *crl_file;
} YDTLSOptions;
#define YD_TLS_CRL_MAX_BYTES (1024U * 1024U)
#define YD_TLS_CRL_MAX_COUNT 64U
typedef struct {
    int fd, timeout_ms;
    void *tls;
    bool failed;
    uint64_t write_deadline;
    void *binary_state; /* Private owned state; never copy a live connection. */
} YDConnection;
YDTLS *yd_tls_new(const char *certificate, const char *key, const char *client_ca, char *error,
                  size_t length);
/* Dedicated mutual TLS peer profile with a separate mandatory ALPN protocol. */
YDTLS *yd_tls_peer_new(const char *certificate, const char *key, const char *ca, char *error,
                       size_t length);
YDTLS *yd_tls_new_with_options(const char *certificate, const char *key, const char *client_ca,
                               const YDTLSOptions *options, char *error, size_t length);
YDTLS *yd_tls_peer_new_with_options(const char *certificate, const char *key, const char *ca,
                                    const YDTLSOptions *options, char *error, size_t length);
/* Separate mutual TLS profile for shard RPC, mandatory yamora-shard/1 ALPN.
 * A shard profile cannot establish a Raft or binary client connection. */
YDTLS *yd_tls_shard_new(const char *, const char *, const char *, char *, size_t);
YDTLS *yd_tls_shard_new_with_options(const char *, const char *, const char *,
    const YDTLSOptions *, char *, size_t);
bool yd_tls_is_shard(const YDTLS *);
bool yd_connection_shard_connect(YDConnection *, int, YDTLS *, const char *, int);
bool yd_tls_is_peer(const YDTLS *tls);
/* Server-only TLS 1.3, mandatory yamora-binary/1; optional client CA means mTLS. */
YDTLS *yd_tls_binary_new(const char *certificate, const char *key, const char *client_ca,
                         char *error, size_t length);
YDTLS *yd_tls_binary_new_with_options(const char *certificate, const char *key,
                                      const char *client_ca, const YDTLSOptions *options,
                                      char *error, size_t length);
bool yd_tls_is_binary(const YDTLS *tls);
bool yd_tls_reload(YDTLS *tls, char *error, size_t length);
void yd_tls_free(YDTLS *tls);
bool yd_connection_init(YDConnection *connection, int descriptor, YDTLS *tls, int timeout_ms);
bool yd_connection_peer_connect(YDConnection *connection, int descriptor, YDTLS *tls,
                                const char *expected_name, int timeout_ms);
bool yd_connection_peer_name(const YDConnection *connection, const char *expected_name);
#define YD_TLS_CLIENT_SHA256_SIZE 32U
typedef struct {
    bool verified;
    unsigned char leaf_sha256[YD_TLS_CLIENT_SHA256_SIZE];
} YDTLSClientIdentity;
typedef enum {
    YD_TLS_CLIENT_NONE,
    YD_TLS_CLIENT_VERIFIED,
    YD_TLS_CLIENT_ERROR
} YDTLSClientIdentityResult;
/* Serialized with this connection's I/O/close, never with another SSL owner.
 * VERIFIED copies the complete DER leaf's SHA-256 from a healthy, completed
 * inbound HTTP/binary mTLS handshake. NONE is plaintext or server-only TLS.
 * Raft/outbound/incomplete/failed TLS or extraction failures are ERROR.
 * Every non-VERIFIED result clears out; NULL arguments are ERROR. Evidence has
 * no borrowed pointers and survives profile reload/free and connection close.
 * Verification is the established handshake's snapshot, not live revocation.
 * out must be disjoint from connection. An empty/closed connection has no
 * identity. Only trusted native code may supply evidence to policy lookup. */
YDTLSClientIdentityResult yd_connection_client_identity(const YDConnection *connection,
                                                        YDTLSClientIdentity *out);
/* Serialized with connection I/O/close; established healthy inbound HTTP
 * TLS1.3 only. RFC9266 tls-exporter: 32 bytes, EXPORTER-Channel-Binding label,
 * empty context. Clears all 32 bytes on failure, no borrowed pointers. Binary,
 * peer/shard, outbound, plaintext, incomplete and closed/failed reject. Never
 * accept binding bytes supplied in a request or from a TLS-terminating proxy. */
bool yd_connection_channel_binding(const YDConnection *, unsigned char out[32]);
ssize_t yd_connection_read(YDConnection *connection, void *buffer, size_t size, uint64_t deadline);
bool yd_connection_send(YDConnection *connection, const void *buffer, size_t size);
typedef enum {
    YD_TLS_READY,      /* Handshake complete, or positive *transferred I/O progress. */
    YD_TLS_WANT_READ,  /* Wait for readability, even when writing. */
    YD_TLS_WANT_WRITE, /* Wait for writability, even when reading. */
    YD_TLS_EOF,        /* Authenticated TLS close_notify; sticky, not failed. */
    YD_TLS_ERROR       /* Terminal; connection->failed stays true until close. */
} YDTLSStep;
/* Fresh/closed, exclusively owned connection only. Creates owned TLS state and
 * sets O_NONBLOCK, but never handshakes or takes ownership of the fd. Failed
 * begin frees its allocations and leaves a close-safe, failed connection.
 * The profile may be freed after begin; serialize profile free against reload
 * and begin. Reload itself may run concurrently with begin/established I/O. */
bool yd_connection_binary_begin(YDConnection *connection, int descriptor, YDTLS *tls);
/* One SSL operation per step: no poll, sleep, replay or fresh implicit timeout.
 * deadline is nonzero absolute CLOCK_MONOTONIC milliseconds on EVERY call.
 * One I/O thread owns/serializes steps and close; do not mix legacy wrappers.
 * Read/write require completed handshake, non-NULL buffer/output and size > 0.
 * *transferred is cleared before validation and is positive only for READY.
 * Read buffer contents are unspecified outside its READY prefix.
 * After write WANT, retry with the SAME pointer, length and immutable bytes;
 * an owned snapshot enforces this contract. No reads until that write resolves.
 * After READY, advance by *transferred and submit ONLY remaining bytes, with
 * the operation's original deadline. Partial progress is not message completion.
 * Expiration/protocol/contract/allocation failures are sticky; no replay, since
 * a terminal error may follow transmission. EOF permits only close/repeated EOF.
 * Close frees TLS only, does not send close_notify, and never closes the fd. */
YDTLSStep yd_connection_handshake_step(YDConnection *connection, uint64_t deadline);
YDTLSStep yd_connection_read_step(YDConnection *connection, void *buffer, size_t size,
                                  uint64_t deadline, size_t *transferred);
YDTLSStep yd_connection_write_step(YDConnection *connection, const void *buffer, size_t size,
                                   uint64_t deadline, size_t *transferred);
/* Releases TLS state; the caller owns and closes the descriptor. */
void yd_connection_close(YDConnection *connection);
#endif
