#define _POSIX_C_SOURCE 200809L
#include "tls.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "Yamora TLS requires system OpenSSL 3 or newer"
#endif
#define PEM_LIMIT (1024U * 1024U)
typedef enum { PROFILE_HTTP, PROFILE_PEER, PROFILE_BINARY, PROFILE_SHARD } Profile;
static const Profile peer_alpn = PROFILE_PEER, binary_alpn = PROFILE_BINARY,
                     shard_alpn = PROFILE_SHARD;
/* Static immutable tags belong to SSL_CTX, never the reloadable YDTLS owner.
 * SSL objects retain their exact context/tag after replacement or owner free.
 * This module owns the application-data slot on every context it constructs. */
typedef struct { Profile profile; bool client_verification; } ContextProfile;
static const ContextProfile http_server = {PROFILE_HTTP, false},
                            http_mutual = {PROFILE_HTTP, true},
                            binary_server = {PROFILE_BINARY, false},
                            binary_mutual = {PROFILE_BINARY, true},
                            peer_profile = {PROFILE_PEER, true},
                            shard_profile = {PROFILE_SHARD, true};
struct YDTLS {
    pthread_mutex_t lock;
    SSL_CTX *context;
    char *certificate, *key, *client_ca, *crl_file;
    Profile profile;
};
static bool fail(char *error, size_t length, const char *message) {
    if (error && length)
        snprintf(error, length, "%s", message);
    return false;
}
static uint64_t now(void) {
    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC, &time))
        return 0;
    return (uint64_t)time.tv_sec * 1000 + (uint64_t)time.tv_nsec / 1000000;
}
static bool ready(int fd, short events, uint64_t deadline) {
    for (;;) {
        uint64_t current = now();
        if (!current || current >= deadline) {
            errno = ETIMEDOUT;
            return false;
        }
        uint64_t left = deadline - current;
        struct pollfd poller = {.fd = fd, .events = events};
        int status = poll(&poller, 1, left > INT_MAX ? INT_MAX : (int)left);
        if (status < 0 && errno == EINTR)
            continue;
        if (!status) {
            errno = ETIMEDOUT;
            return false;
        }
        if (status < 0 || (poller.revents & (POLLERR | POLLNVAL)))
            return false;
        return true; /* HUP is passed to the I/O operation to establish EOF. */
    }
}
static BIO *pem_descriptor(int fd, bool secret) {
    struct stat st;
    bool valid = fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0 &&
                 st.st_size <= PEM_LIMIT && !(st.st_mode & (S_IWGRP | S_IWOTH)) &&
                 (!secret || !(st.st_mode & (S_IXUSR | S_IRWXG | S_IRWXO)));
    unsigned char *data = valid ? malloc((size_t)st.st_size) : NULL;
    size_t used = 0;
    valid = valid && data;
    while (valid && used < (size_t)st.st_size) {
        ssize_t got = read(fd, data + used, (size_t)st.st_size - used);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            valid = false;
        else
            used += (size_t)got;
    }
    unsigned char extra;
    if (valid)
        valid = read(fd, &extra, 1) == 0;
    if (fd >= 0)
        close(fd);
    BIO *bio = valid ? BIO_new(BIO_s_mem()) : NULL;
    if (bio && BIO_write(bio, data, (int)used) != (int)used) {
        BIO_free(bio);
        bio = NULL;
    }
    if (data && secret)
        OPENSSL_cleanse(data, used);
    free(data);
    return bio;
}
static BIO *pem_file(const char *path, bool secret) {
    return pem_descriptor(open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK), secret);
}
/* Traverse CRL path components by descriptor: O_NOFOLLOW on the final file
 * alone would still accept a symlink in an ancestor directory. */
static BIO *crl_file(const char *path) {
    if (strlen(path) >= PATH_MAX)
        return NULL;
    char *copy = strdup(path), *save = NULL;
    if (!copy)
        return NULL;
    int directory = open(path[0] == '/' ? "/" : ".", O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    char *part = strtok_r(copy, "/", &save);
    int fd = -1;
    while (directory >= 0 && part) {
        char *next = strtok_r(NULL, "/", &save);
        if (!strcmp(part, ".."))
            break;
        int opened = openat(directory, part, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK |
                                              (next ? O_DIRECTORY : 0));
        close(directory);
        directory = next ? opened : -1;
        if (!next)
            fd = opened;
        part = next;
    }
    if (directory >= 0)
        close(directory);
    free(copy);
    struct stat st;
    if (fd >= 0 && (fstat(fd, &st) || (st.st_uid != 0 && st.st_uid != geteuid()) ||
                   st.st_size > YD_TLS_CRL_MAX_BYTES)) {
        close(fd);
        fd = -1;
    }
    return pem_descriptor(fd, false);
}
static int no_password(char *buffer, int size, int writing, void *argument) {
    (void)buffer;
    (void)size;
    (void)writing;
    (void)argument;
    return 0; /* Encrypted keys never trigger an unattended terminal prompt. */
}
static bool pem_end(BIO *bio) {
    unsigned long code = ERR_peek_last_error();
    return BIO_eof(bio) && ERR_GET_LIB(code) == ERR_LIB_PEM &&
           ERR_GET_REASON(code) == PEM_R_NO_START_LINE;
}
static int alpn(SSL *ssl, const unsigned char **out, unsigned char *size,
                const unsigned char *offered, unsigned int length, void *argument) {
    (void)ssl;
    static const unsigned char http[] = "\x08http/1.1";
    static const unsigned char peers[] = "\x0d"
                                         "yamora-raft/1";
    static const unsigned char binary[] = "\x0f" "yamora-binary/1";
    static const unsigned char shards[] = "\x0e" "yamora-shard/1";
    Profile profile = argument ? *(const Profile *)argument : PROFILE_HTTP;
    const unsigned char *protocols = profile == PROFILE_BINARY ? binary :
                                     profile == PROFILE_PEER ? peers :
                                     profile == PROFILE_SHARD ? shards : http;
    unsigned int protocols_size = profile == PROFILE_BINARY ? sizeof(binary) - 1 :
                                  profile == PROFILE_PEER ? sizeof(peers) - 1 :
                                  profile == PROFILE_SHARD ? sizeof(shards) - 1 : sizeof(http) - 1;
    unsigned char *selected = NULL;
    int result = SSL_select_next_proto(&selected, size, protocols, protocols_size, offered, length);
    if (result != OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    *out = selected;
    return SSL_TLSEXT_ERR_OK;
}
static bool identity(SSL_CTX *ctx, const char *certificate, const char *key) {
    BIO *certificates = pem_file(certificate, false), *keys = pem_file(key, true);
    X509 *leaf = certificates ? PEM_read_bio_X509_AUX(certificates, NULL, no_password, NULL) : NULL;
    EVP_PKEY *private = keys ? PEM_read_bio_PrivateKey(keys, NULL, no_password, NULL) : NULL;
    bool valid = leaf && private && X509_cmp_current_time(X509_get0_notBefore(leaf)) < 0 &&
                 X509_cmp_current_time(X509_get0_notAfter(leaf)) > 0 &&
                 SSL_CTX_use_certificate(ctx, leaf) == 1 &&
                 SSL_CTX_use_PrivateKey(ctx, private) == 1 && SSL_CTX_check_private_key(ctx) == 1;
    unsigned count = 0;
    while (valid) {
        X509 *chain = PEM_read_bio_X509(certificates, NULL, no_password, NULL);
        if (!chain) {
            valid = pem_end(certificates);
            break;
        }
        if (++count > 16 || SSL_CTX_add_extra_chain_cert(ctx, chain) != 1) {
            X509_free(chain);
            valid = false;
        }
    }
    X509_free(leaf);
    EVP_PKEY_free(private);
    BIO_free(certificates);
    BIO_free(keys);
    ERR_clear_error();
    return valid;
}
static bool authorities(SSL_CTX *ctx, const char *path) {
    BIO *bio = pem_file(path, false);
    if (!bio)
        return false;
    unsigned count = 0;
    bool valid = true;
    for (;;) {
        X509 *certificate = PEM_read_bio_X509(bio, NULL, no_password, NULL);
        if (!certificate) {
            valid = pem_end(bio);
            break;
        }
        valid = ++count <= 64 && X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), certificate) == 1;
        X509_free(certificate);
        if (!valid)
            break;
    }
    BIO_free(bio);
    ERR_clear_error();
    return valid && count > 0;
}
static bool crl_authority(X509_CRL *crl, X509 *issuer) {
    if (!issuer || X509_NAME_cmp(X509_CRL_get_issuer(crl), X509_get_subject_name(issuer)) ||
        X509_check_ca(issuer) <= 0 ||
        ((X509_get_extension_flags(issuer) & EXFLAG_KUSAGE) &&
         !(X509_get_key_usage(issuer) & KU_CRL_SIGN)))
        return false;
    int critical = -1;
    AUTHORITY_KEYID *akid = X509_CRL_get_ext_d2i(crl, NID_authority_key_identifier, &critical, NULL);
    bool valid = (akid || critical == -1) && (!akid || X509_check_akid(issuer, akid) == X509_V_OK);
    AUTHORITY_KEYID_free(akid);
    return valid;
}
static bool crl_issuer(X509_STORE *store, X509_CRL *crl) {
    bool valid = false;
    const STACK_OF(X509_OBJECT) *objects = X509_STORE_get0_objects(store);
    for (int i = 0; !valid && i < sk_X509_OBJECT_num(objects); i++) {
        X509 *issuer = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(objects, i));
        if (!crl_authority(crl, issuer))
            continue;
        EVP_PKEY *key = X509_get0_pubkey(issuer);
        X509_STORE_CTX *check = X509_STORE_CTX_new();
        valid = key && check && X509_STORE_CTX_init(check, store, issuer, NULL) == 1;
        if (valid) {
            X509_VERIFY_PARAM *parameters = X509_STORE_CTX_get0_param(check);
            X509_VERIFY_PARAM_set_depth(parameters, 8);
            X509_VERIFY_PARAM_set_auth_level(parameters, 2);
            valid = X509_verify_cert(check) == 1 && X509_CRL_verify(crl, key) == 1;
        }
        X509_STORE_CTX_free(check);
    }
    return valid;
}
static bool crl_supported(X509_CRL *crl) {
    /* This slice accepts complete direct CRLs only. Unsupported scope or delta
     * semantics must never silently weaken the revocation decision. */
    for (int i = 0; i < X509_CRL_get_ext_count(crl); i++) {
        X509_EXTENSION *extension = X509_CRL_get_ext(crl, i);
        int nid = OBJ_obj2nid(X509_EXTENSION_get_object(extension));
        if (X509_EXTENSION_get_critical(extension) || nid == NID_delta_crl ||
            nid == NID_issuing_distribution_point)
            return false;
    }
    const STACK_OF(X509_REVOKED) *revoked = X509_CRL_get_REVOKED(crl);
    for (int i = 0; i < sk_X509_REVOKED_num(revoked); i++) {
        X509_REVOKED *entry = sk_X509_REVOKED_value(revoked, i);
        for (int j = 0; j < X509_REVOKED_get_ext_count(entry); j++) {
            X509_EXTENSION *extension = X509_REVOKED_get_ext(entry, j);
            if (X509_EXTENSION_get_critical(extension) ||
                OBJ_obj2nid(X509_EXTENSION_get_object(extension)) == NID_certificate_issuer)
                return false;
        }
        int critical = -1;
        ASN1_ENUMERATED *reason = X509_REVOKED_get_ext_d2i(entry, NID_crl_reason, &critical, NULL);
        long code = reason ? ASN1_ENUMERATED_get(reason) : 0;
        bool decoded = reason != NULL || critical == -1;
        ASN1_ENUMERATED_free(reason);
        if (!decoded || code < 0 || code == 7 || code == 8 || code > 10)
            return false; /* removeFromCRL belongs to delta CRLs, never full snapshots. */
    }
    return true;
}
static X509_CRL *crl_read(BIO *bio) {
    char *name = NULL, *header = NULL;
    unsigned char *data = NULL;
    long size = 0;
    X509_CRL *crl = NULL;
    if (PEM_read_bio(bio, &name, &header, &data, &size) == 1 &&
        !strcmp(name, "X509 CRL") && !*header && size > 0) {
        const unsigned char *cursor = data;
        crl = d2i_X509_CRL(NULL, &cursor, size);
        if (cursor != data + size) {
            X509_CRL_free(crl);
            crl = NULL;
        }
    }
    OPENSSL_free(name);
    OPENSSL_free(header);
    OPENSSL_free(data);
    return crl;
}
static bool revocations(SSL_CTX *ctx, const char *path) {
    BIO *bio = crl_file(path);
    if (!bio)
        return false;
    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    X509_CRL *loaded[YD_TLS_CRL_MAX_COUNT] = {0};
    unsigned count = 0;
    bool valid = true;
    for (;;) {
        char *data = NULL;
        long size = BIO_get_mem_data(bio, &data);
        long whitespace = 0;
        while (whitespace < size && isspace((unsigned char)data[whitespace]))
            whitespace++;
        if (whitespace)
            BIO_read(bio, data, (int)whitespace);
        size = BIO_get_mem_data(bio, &data);
        if (!size)
            break;
        static const char begin[] = "-----BEGIN X509 CRL-----";
        size_t begin_size = sizeof(begin) - 1;
        bool opening = size > (long)begin_size && !memcmp(data, begin, begin_size) &&
                       (data[begin_size] == '\n' ||
                        (size > (long)begin_size + 1 && data[begin_size] == '\r' &&
                         data[begin_size + 1] == '\n'));
        if (count == YD_TLS_CRL_MAX_COUNT || !opening) {
            valid = false;
            break;
        }
        X509_CRL *crl = crl_read(bio);
        valid = crl && X509_CRL_get0_lastUpdate(crl) &&
                X509_cmp_current_time(X509_CRL_get0_lastUpdate(crl)) < 0 &&
                X509_CRL_get0_nextUpdate(crl) &&
                X509_cmp_current_time(X509_CRL_get0_nextUpdate(crl)) > 0 && crl_supported(crl) &&
                crl_issuer(store, crl);
        /* One authority-approved snapshot per issuer, without ambiguous CRL
         * selection by number, order, or signature under a different key. */
        for (unsigned i = 0; valid && i < count; i++)
            valid = X509_NAME_cmp(X509_CRL_get_issuer(loaded[i]), X509_CRL_get_issuer(crl)) != 0;
        if (!valid) {
            X509_CRL_free(crl);
            break;
        }
        loaded[count++] = crl;
    }
    /* Do not publish a partly protected trust bundle. Every configured CA
     * needs its own full CRL, including roots used to check intermediates. */
    const STACK_OF(X509_OBJECT) *objects = X509_STORE_get0_objects(store);
    for (int i = 0; valid && i < sk_X509_OBJECT_num(objects); i++) {
        X509 *issuer = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(objects, i));
        if (!issuer || X509_check_ca(issuer) <= 0)
            continue;
        bool covered = false;
        EVP_PKEY *key = X509_get0_pubkey(issuer);
        for (unsigned j = 0; !covered && j < count; j++)
            covered = key && crl_authority(loaded[j], issuer) &&
                      X509_CRL_verify(loaded[j], key) == 1;
        valid = covered;
    }
    for (unsigned i = 0; valid && i < count; i++)
        valid = X509_STORE_add_crl(store, loaded[i]) == 1;
    for (unsigned i = 0; i < count; i++)
        X509_CRL_free(loaded[i]);
    BIO_free(bio);
    ERR_clear_error();
    return valid && count > 0 &&
           X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(ctx),
                                       X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL) == 1;
}
static SSL_CTX *context(YDTLS *tls, char *error, size_t length) {
    ERR_clear_error();
    SSL_CTX *ctx = SSL_CTX_new((tls->profile == PROFILE_PEER || tls->profile == PROFILE_SHARD) ? TLS_method() : TLS_server_method());
    bool valid = ctx && SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) == 1 &&
                 SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) == 1;
    if (valid) {
        const ContextProfile *tag = tls->profile == PROFILE_SHARD ? &shard_profile :
            tls->profile == PROFILE_PEER ? &peer_profile :
            tls->profile == PROFILE_BINARY ? (tls->client_ca ? &binary_mutual : &binary_server) :
                                            (tls->client_ca ? &http_mutual : &http_server);
        valid = SSL_CTX_set_app_data(ctx, (void *)tag) == 1;
        SSL_CTX_set_security_level(ctx, 2);
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
        valid = valid && SSL_CTX_set_num_tickets(ctx, 0) == 1;
        SSL_CTX_set_max_early_data(ctx, 0);
        SSL_CTX_set_max_cert_list(ctx, 65536);
        SSL_CTX_set_verify_depth(ctx, 8);
        SSL_CTX_set_alpn_select_cb(ctx, alpn, tls->profile == PROFILE_PEER ? (void *)&peer_alpn :
                                            tls->profile == PROFILE_BINARY ? (void *)&binary_alpn :
                                            tls->profile == PROFILE_SHARD ? (void *)&shard_alpn : NULL);
        valid = valid && identity(ctx, tls->certificate, tls->key);
        if (tls->client_ca) {
            valid = valid && authorities(ctx, tls->client_ca);
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        }
        if (tls->crl_file)
            valid = valid && revocations(ctx, tls->crl_file);
    }
    if (!valid) {
        SSL_CTX_free(ctx);
        fail(error, length, "TLS identity/trust/revocation configuration is invalid or unavailable");
        return NULL;
    }
    return ctx;
}
static YDTLS *tls_new(const char *certificate, const char *key, const char *client_ca, Profile profile,
                      const YDTLSOptions *options, char *error, size_t length) {
    if (error && length)
        error[0] = 0;
    const char *crl = options ? options->crl_file : NULL;
    if (!certificate || !key || ((profile == PROFILE_PEER || profile == PROFILE_SHARD) && !client_ca) || (crl && (!*crl || !client_ca))) {
        fail(error, length, "TLS certificate/key and CA with a nonempty CRL path are required");
        return NULL;
    }
    YDTLS *tls = calloc(1, sizeof(*tls));
    if (!tls)
        return NULL;
    tls->certificate = strdup(certificate);
    tls->key = strdup(key);
    tls->client_ca = client_ca ? strdup(client_ca) : NULL;
    tls->crl_file = crl ? strdup(crl) : NULL;
    tls->profile = profile;
    if (pthread_mutex_init(&tls->lock, NULL)) {
        free(tls->certificate);
        free(tls->key);
        free(tls->client_ca);
        free(tls->crl_file);
        free(tls);
        return NULL;
    }
    if (tls->certificate && tls->key && (!client_ca || tls->client_ca) && (!crl || tls->crl_file))
        tls->context = context(tls, error, length);
    if (!tls->context) {
        yd_tls_free(tls);
        return NULL;
    }
    return tls;
}
YDTLS *yd_tls_new(const char *certificate, const char *key, const char *client_ca, char *error,
                  size_t length) {
    return yd_tls_new_with_options(certificate, key, client_ca, NULL, error, length);
}
YDTLS *yd_tls_peer_new(const char *certificate, const char *key, const char *ca, char *error,
                       size_t length) {
    return yd_tls_peer_new_with_options(certificate, key, ca, NULL, error, length);
}
YDTLS *yd_tls_new_with_options(const char *certificate, const char *key, const char *client_ca,
                               const YDTLSOptions *options, char *error, size_t length) {
    return tls_new(certificate, key, client_ca, PROFILE_HTTP, options, error, length);
}
YDTLS *yd_tls_peer_new_with_options(const char *certificate, const char *key, const char *ca,
                                    const YDTLSOptions *options, char *error, size_t length) {
    return tls_new(certificate, key, ca, PROFILE_PEER, options, error, length);
}
YDTLS *yd_tls_binary_new(const char *certificate, const char *key, const char *client_ca,
                         char *error, size_t length) {
    return yd_tls_binary_new_with_options(certificate, key, client_ca, NULL, error, length);
}
YDTLS *yd_tls_binary_new_with_options(const char *certificate, const char *key,
                                      const char *client_ca, const YDTLSOptions *options,
                                      char *error, size_t length) {
    return tls_new(certificate, key, client_ca, PROFILE_BINARY, options, error, length);
}
YDTLS *yd_tls_shard_new(const char *certificate, const char *key, const char *ca,
    char *error, size_t length) {
    return yd_tls_shard_new_with_options(certificate, key, ca, NULL, error, length);
}
YDTLS *yd_tls_shard_new_with_options(const char *certificate, const char *key, const char *ca,
    const YDTLSOptions *options, char *error, size_t length) {
    return tls_new(certificate, key, ca, PROFILE_SHARD, options, error, length);
}
bool yd_tls_is_shard(const YDTLS *tls) { return tls && tls->profile == PROFILE_SHARD; }
bool yd_tls_is_peer(const YDTLS *tls) { return tls && tls->profile == PROFILE_PEER; }
bool yd_tls_is_binary(const YDTLS *tls) { return tls && tls->profile == PROFILE_BINARY; }
bool yd_tls_reload(YDTLS *tls, char *error, size_t length) {
    if (!tls)
        return fail(error, length, "TLS profile is required");
    if (error && length)
        error[0] = 0;
    SSL_CTX *replacement = context(tls, error, length);
    if (!replacement)
        return false;
    pthread_mutex_lock(&tls->lock);
    SSL_CTX *previous = tls->context;
    tls->context = replacement;
    pthread_mutex_unlock(&tls->lock);
    SSL_CTX_free(previous); /* Existing SSL sessions retain their own context reference. */
    return true;
}
void yd_tls_free(YDTLS *tls) {
    if (tls) {
        SSL_CTX_free(tls->context);
        pthread_mutex_destroy(&tls->lock);
        free(tls->certificate);
        free(tls->key);
        free(tls->client_ca);
        free(tls->crl_file);
        free(tls);
    }
}
static bool retry(YDConnection *connection, int status, uint64_t deadline) {
    if (status == SSL_ERROR_WANT_READ)
        return ready(connection->fd, POLLIN, deadline);
    if (status == SSL_ERROR_WANT_WRITE)
        return ready(connection->fd, POLLOUT, deadline);
    connection->failed = true;
    errno = EIO;
    return false;
}
static bool initialize(YDConnection *connection, int descriptor, YDTLS *tls, int timeout_ms,
                       const char *expected_name) {
    *connection = (YDConnection){.fd = descriptor, .timeout_ms = timeout_ms};
    int flags = fcntl(descriptor, F_GETFL);
    if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK))
        return false;
    if (!tls)
        return true;
    pthread_mutex_lock(&tls->lock);
    SSL *ssl = SSL_new(tls->context);
    pthread_mutex_unlock(&tls->lock);
    connection->tls = ssl;
    if (!ssl || SSL_set_fd(ssl, descriptor) != 1) {
        yd_connection_close(connection);
        return false;
    }
    if (expected_name) {
        static const unsigned char raft_protocol[] = "\x0d" "yamora-raft/1";
        static const unsigned char shard_protocol[] = "\x0e" "yamora-shard/1";
        const unsigned char *protocols = tls->profile == PROFILE_SHARD ? shard_protocol : raft_protocol;
        unsigned protocol_size = tls->profile == PROFILE_SHARD ? sizeof(shard_protocol) - 1 : sizeof(raft_protocol) - 1;
        SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_WILDCARDS | X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
        if (SSL_set1_host(ssl, expected_name) != 1 ||
            SSL_set_tlsext_host_name(ssl, expected_name) != 1 ||
            SSL_set_alpn_protos(ssl, protocols, protocol_size) != 0) {
            yd_connection_close(connection);
            return false;
        }
    }
    uint64_t deadline = now() + (uint64_t)timeout_ms;
    for (;;) {
        ERR_clear_error();
        int result = expected_name ? SSL_connect(ssl) : SSL_accept(ssl);
        if (result == 1) {
            if (tls->profile == PROFILE_HTTP)
                return true;
            const unsigned char *protocol = NULL;
            unsigned int size = 0;
            SSL_get0_alpn_selected(ssl, &protocol, &size);
            if (((tls->profile == PROFILE_PEER && size == 13 &&
                   !memcmp(protocol, "yamora-raft/1", 13)) ||
                  (tls->profile == PROFILE_BINARY && size == 15 &&
                   !memcmp(protocol, "yamora-binary/1", 15)) ||
                  (tls->profile == PROFILE_SHARD && size == 14 &&
                   !memcmp(protocol, "yamora-shard/1", 14))) &&
                (!expected_name || yd_connection_peer_name(connection, expected_name)))
                return true;
            connection->failed = true;
            yd_connection_close(connection);
            return false;
        }
        int status = SSL_get_error(ssl, result);
        if (!retry(connection, status, deadline)) {
            yd_connection_close(connection);
            return false;
        }
    }
}
bool yd_connection_init(YDConnection *connection, int descriptor, YDTLS *tls, int timeout_ms) {
    return initialize(connection, descriptor, tls, timeout_ms, NULL);
}
bool yd_connection_peer_connect(YDConnection *connection, int descriptor, YDTLS *tls,
                                const char *expected_name, int timeout_ms) {
    *connection = (YDConnection){.fd = descriptor, .timeout_ms = timeout_ms};
    return yd_tls_is_peer(tls) && expected_name && *expected_name &&
           initialize(connection, descriptor, tls, timeout_ms, expected_name);
}
bool yd_connection_shard_connect(YDConnection *connection, int descriptor, YDTLS *tls,
    const char *expected_name, int timeout_ms) {
    *connection = (YDConnection){.fd = descriptor, .timeout_ms = timeout_ms};
    return yd_tls_is_shard(tls) && expected_name && *expected_name &&
        initialize(connection, descriptor, tls, timeout_ms, expected_name);
}
bool yd_connection_peer_name(const YDConnection *connection, const char *expected_name) {
    if (!connection->tls || !expected_name || SSL_get_verify_result(connection->tls) != X509_V_OK)
        return false;
    X509 *certificate = SSL_get0_peer_certificate(connection->tls);
    return certificate &&
           X509_check_host(certificate, expected_name, 0,
                           X509_CHECK_FLAG_NO_WILDCARDS | X509_CHECK_FLAG_NEVER_CHECK_SUBJECT,
                           NULL) == 1;
}
ssize_t yd_connection_read(YDConnection *connection, void *buffer, size_t size, uint64_t deadline) {
    for (;;) {
        if (now() >= deadline) {
            errno = ETIMEDOUT;
            return -1;
        }
        if (connection->tls) {
            size_t got = 0;
            ERR_clear_error();
            int result = SSL_read_ex(connection->tls, buffer, size, &got);
            if (result == 1)
                return (ssize_t)got;
            int status = SSL_get_error(connection->tls, result);
            if (status == SSL_ERROR_ZERO_RETURN)
                return 0;
            if (!retry(connection, status, deadline))
                return -1;
        } else {
            ssize_t got = recv(connection->fd, buffer, size, 0);
            if (got >= 0)
                return got;
            if (errno == EINTR)
                continue;
            if ((errno != EAGAIN && errno != EWOULDBLOCK) ||
                !ready(connection->fd, POLLIN, deadline))
                return -1;
        }
    }
}
bool yd_connection_send(YDConnection *connection, const void *buffer, size_t size) {
    if (connection->failed)
        return false;
    if (!connection->write_deadline)
        connection->write_deadline = now() + (uint64_t)connection->timeout_ms;
    size_t used = 0;
    while (used < size) {
        if (now() >= connection->write_deadline) {
            errno = ETIMEDOUT;
            return false;
        }
        if (connection->tls) {
            size_t sent = 0;
            ERR_clear_error();
            int result =
                SSL_write_ex(connection->tls, (const char *)buffer + used, size - used, &sent);
            if (result == 1) {
                used += sent;
                continue;
            }
            int status = SSL_get_error(connection->tls, result);
            if (!retry(connection, status, connection->write_deadline))
                return false;
        } else {
            ssize_t sent = send(connection->fd, (const char *)buffer + used, size - used,
#ifdef MSG_NOSIGNAL
                                MSG_NOSIGNAL
#else
                                0
#endif
            );
            if (sent > 0) {
                used += (size_t)sent;
                continue;
            }
            if (sent < 0 && errno == EINTR)
                continue;
            if (sent == 0 || (errno != EAGAIN && errno != EWOULDBLOCK) ||
                !ready(connection->fd, POLLOUT, connection->write_deadline))
                return false;
        }
    }
    return true;
}
typedef struct {
    bool handshaken, eof;
    const void *pending_buffer;
    unsigned char *pending_copy;
    size_t pending_size;
} BinaryState;
static void clear_write(BinaryState *state) {
    if (state->pending_copy) {
        OPENSSL_cleanse(state->pending_copy, state->pending_size);
        free(state->pending_copy);
    }
    state->pending_copy = NULL;
    state->pending_buffer = NULL;
    state->pending_size = 0;
}
static YDTLSStep step_fail(YDConnection *connection, int code) {
    if (connection) {
        connection->failed = true;
        if (connection->binary_state)
            clear_write(connection->binary_state);
    }
    errno = code;
    return YD_TLS_ERROR;
}
bool yd_connection_binary_begin(YDConnection *connection, int descriptor, YDTLS *tls) {
    if (!connection) {
        errno = EINVAL;
        return false;
    }
    *connection = (YDConnection){.fd = descriptor, .failed = true};
    if (!yd_tls_is_binary(tls)) {
        errno = EINVAL;
        return false;
    }
    int flags = fcntl(descriptor, F_GETFL);
    if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK))
        return false;
    BinaryState *state = calloc(1, sizeof(*state));
    if (!state) {
        errno = ENOMEM;
        return false;
    }
    ERR_clear_error();
    pthread_mutex_lock(&tls->lock);
    SSL *ssl = SSL_new(tls->context);
    pthread_mutex_unlock(&tls->lock);
    if (!ssl || SSL_set_fd(ssl, descriptor) != 1) {
        SSL_free(ssl);
        free(state);
        errno = EIO;
        return false;
    }
    SSL_set_accept_state(ssl);
    /* A successful call may consume a prefix; WANT must retry identical bytes. */
    SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_clear_mode(ssl, SSL_MODE_AUTO_RETRY | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    connection->tls = ssl;
    connection->binary_state = state;
    connection->failed = false;
    return true;
}
static YDTLSStep step_check(YDConnection *connection, uint64_t deadline) {
    if (!connection || connection->failed || !connection->tls || !connection->binary_state)
        return step_fail(connection, EINVAL);
    BinaryState *state = connection->binary_state;
    if (state->eof)
        return YD_TLS_EOF;
    uint64_t current = now();
    if (!current)
        return step_fail(connection, EIO);
    if (!deadline || current >= deadline)
        return step_fail(connection, ETIMEDOUT);
    return YD_TLS_READY;
}
static YDTLSStep step_result(YDConnection *connection, int result) {
    int status = SSL_get_error(connection->tls, result);
    if (status == SSL_ERROR_WANT_READ)
        return YD_TLS_WANT_READ;
    if (status == SSL_ERROR_WANT_WRITE)
        return YD_TLS_WANT_WRITE;
    if (status == SSL_ERROR_ZERO_RETURN) {
        BinaryState *state = connection->binary_state;
        state->eof = true;
        clear_write(state);
        return YD_TLS_EOF;
    }
    return step_fail(connection, EIO);
}
YDTLSStep yd_connection_handshake_step(YDConnection *connection, uint64_t deadline) {
    YDTLSStep check = step_check(connection, deadline);
    if (check != YD_TLS_READY)
        return check;
    BinaryState *state = connection->binary_state;
    if (state->handshaken)
        return YD_TLS_READY;
    ERR_clear_error();
    errno = 0;
    int result = SSL_accept(connection->tls);
    if (result != 1)
        return step_result(connection, result);
    const unsigned char *protocol = NULL;
    unsigned int size = 0;
    SSL_get0_alpn_selected(connection->tls, &protocol, &size);
    if (size != 15 || memcmp(protocol, "yamora-binary/1", 15))
        return step_fail(connection, EPROTO);
    state->handshaken = true;
    return YD_TLS_READY;
}
YDTLSStep yd_connection_read_step(YDConnection *connection, void *buffer, size_t size,
                                  uint64_t deadline, size_t *transferred) {
    if (transferred)
        *transferred = 0;
    YDTLSStep check = step_check(connection, deadline);
    if (check != YD_TLS_READY)
        return check;
    BinaryState *state = connection->binary_state;
    if (!buffer || !size || !transferred || !state->handshaken || state->pending_copy)
        return step_fail(connection, EINVAL);
    size_t got = 0;
    ERR_clear_error();
    errno = 0;
    int result = SSL_read_ex(connection->tls, buffer, size, &got);
    if (result != 1)
        return step_result(connection, result);
    if (!got || got > size)
        return step_fail(connection, EIO);
    *transferred = got;
    return YD_TLS_READY;
}
YDTLSStep yd_connection_write_step(YDConnection *connection, const void *buffer, size_t size,
                                   uint64_t deadline, size_t *transferred) {
    if (transferred)
        *transferred = 0;
    YDTLSStep check = step_check(connection, deadline);
    if (check != YD_TLS_READY)
        return check;
    BinaryState *state = connection->binary_state;
    if (!buffer || !size || !transferred || !state->handshaken)
        return step_fail(connection, EINVAL);
    if (state->pending_copy) {
        if (buffer != state->pending_buffer || size != state->pending_size ||
            memcmp(buffer, state->pending_copy, size))
            return step_fail(connection, EINVAL);
    } else {
        state->pending_copy = malloc(size);
        if (!state->pending_copy)
            return step_fail(connection, ENOMEM);
        memcpy(state->pending_copy, buffer, size);
        state->pending_buffer = buffer;
        state->pending_size = size;
    }
    size_t sent = 0;
    ERR_clear_error();
    errno = 0;
    int result = SSL_write_ex(connection->tls, state->pending_copy, size, &sent);
    if (result != 1)
        return step_result(connection, result);
    if (!sent || sent > size)
        return step_fail(connection, EIO);
    clear_write(state);
    *transferred = sent;
    return YD_TLS_READY;
}
YDTLSClientIdentityResult yd_connection_client_identity(const YDConnection *connection,
                                                        YDTLSClientIdentity *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!connection || !out || connection->failed) return YD_TLS_CLIENT_ERROR;
    SSL *ssl = connection->tls;
    if (!ssl) return YD_TLS_CLIENT_NONE;
    const ContextProfile *tag = SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl));
    if ((tag != &http_server && tag != &http_mutual && tag != &binary_server &&
         tag != &binary_mutual) || !SSL_is_server(ssl) || !SSL_is_init_finished(ssl) ||
        SSL_get_shutdown(ssl) || SSL_version(ssl) != TLS1_3_VERSION)
        return YD_TLS_CLIENT_ERROR;
    if (connection->binary_state) {
        const BinaryState *state = connection->binary_state;
        if (!state->handshaken || state->eof) return YD_TLS_CLIENT_ERROR;
    }
    if (tag->profile == PROFILE_BINARY) {
        static const char expected[] = "yamora-binary/1";
        const unsigned char *protocol = NULL;
        unsigned int size = 0;
        SSL_get0_alpn_selected(ssl, &protocol, &size);
        if (size != sizeof(expected) - 1 || memcmp(protocol, expected, sizeof(expected) - 1))
            return YD_TLS_CLIENT_ERROR;
    }
    if (!tag->client_verification) return YD_TLS_CLIENT_NONE;
    int required = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    X509 *leaf = SSL_get0_peer_certificate(ssl);
    if ((SSL_get_verify_mode(ssl) & required) != required || !leaf ||
        SSL_get_verify_result(ssl) != X509_V_OK)
        return YD_TLS_CLIENT_ERROR;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int size = 0;
    if (X509_digest(leaf, EVP_sha256(), digest, &size) != 1 || size != YD_TLS_CLIENT_SHA256_SIZE)
        return YD_TLS_CLIENT_ERROR;
    memcpy(out->leaf_sha256, digest, size);
    out->verified = true;
    return YD_TLS_CLIENT_VERIFIED;
}
bool yd_connection_channel_binding(const YDConnection *connection, unsigned char out[32]) {
    if (out) memset(out, 0, 32);
    if (!connection || !out || connection->failed || connection->fd < 0 ||
        connection->binary_state || !connection->tls) return false;
    SSL *ssl = connection->tls;
    const ContextProfile *tag = SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl));
    if ((tag != &http_server && tag != &http_mutual) || !SSL_is_server(ssl) ||
        !SSL_is_init_finished(ssl) || SSL_get_shutdown(ssl) ||
        SSL_version(ssl) != TLS1_3_VERSION || SSL_get_fd(ssl) != connection->fd) return false;
    static const char label[] = "EXPORTER-Channel-Binding";
    ERR_clear_error();
    if (SSL_export_keying_material(ssl, out, 32, label, sizeof(label)-1, NULL, 0, 1) != 1) {
        memset(out, 0, 32); return false;
    }
    return true;
}
void yd_connection_close(YDConnection *connection) {
    if (!connection)
        return;
    if (connection->binary_state) {
        clear_write(connection->binary_state);
        free(connection->binary_state);
        connection->binary_state = NULL;
        SSL_free(connection->tls);
        connection->tls = NULL;
        return;
    }
    if (connection->tls) {
        if (!connection->failed && SSL_is_init_finished(connection->tls))
            (void)SSL_shutdown(connection->tls);
        SSL_free(connection->tls);
        connection->tls = NULL;
    }
}
