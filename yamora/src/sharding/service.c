#define _POSIX_C_SOURCE 200809L
#include "service.h"
#include "../security/access.h"
#include "service_wire.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
enum { STATE = 1, CONTROL, NATIVE };
typedef struct {
  YDRaftView *view;
  YDShardNative *native;
  YDShardControl *control;
  char token[65], shard[64];
  char *credential;
} Capture;
struct YDShardService {
  YDShardTransport *rpc;
  YDShardServiceCallbacks cb;
  char group[64], control[64];
  unsigned timeout;
  YDTLS *tls;
  YDValue *model;
  int listener;
  pthread_t worker;
  bool running;
  atomic_bool stop;
  pthread_mutex_t snapshots;
  Capture captures[64];
  size_t next_capture;
};
static void capture_free(Capture *c) {
  yd_shard_native_close(c->native);
  yd_shard_control_close(c->control);
  yd_raft_view_close(c->view);
  if (c->credential) {
    volatile char *p = c->credential;
    size_t size = strlen(c->credential);
    for (size_t i = 0; i < size; i++)
      p[i] = 0;
  }
  free(c->credential);
  memset(c, 0, sizeof(*c));
}
static int http_status(YDShardStatus s) {
  return s == YD_SHARD_OK                 ? 200
         : s == YD_SHARD_FORBIDDEN        ? 403
         : s == YD_SHARD_UNAVAILABLE      ? 503
         : s == YD_SHARD_RESOURCE_FAILURE ? 503
         : s == YD_SHARD_CONFLICT || s == YD_SHARD_MIGRATING ||
                 s == YD_SHARD_STALE_PLACEMENT
             ? 409
         : s == YD_SHARD_BUDGET_EXCEEDED   ? 413
         : s == YD_SHARD_DEADLINE_EXCEEDED ? 504
         : s == YD_SHARD_EXPIRED           ? 410
                                           : 400;
}
static YDDiskReply failure(YDShardStatus s) {
  return yd_disk_error_reply(http_status(s), yd_shard_status_name(s));
}
static bool allowed(YDShardService *s, const char *credential,
                    const char *collection, bool write, bool admin) {
  return s && credential && credential[0] &&
         strnlen(credential, YD_SHARD_CREDENTIAL_BYTES + 1) <=
             YD_SHARD_CREDENTIAL_BYTES &&
         collection && collection[0] &&
         s->cb.authorize(s->cb.auth_context, credential, collection, write,
                         admin);
}
static YDShardStatus dispatch(void *, unsigned, const char *,
                              const unsigned char *, size_t, unsigned char **,
                              size_t *);
static YDShardStatus call(YDShardService *s, const char *group, unsigned kind,
                          const char *credential, const unsigned char *p,
                          size_t n, unsigned char **out, size_t *size) {
  *out = NULL;
  *size = 0;
  if (!strcmp(group, s->group)) {
    YDShardStatus status = dispatch(s, kind, credential, p, n, out, size);
    if (status != YD_SHARD_UNAVAILABLE)
      return status;
    free(*out);
    *out = NULL;
    *size = 0;
  }
  return yd_shard_rpc_call(s->rpc, group, kind, credential, p, n, out, size);
}
static YDShardStatus state(YDShardService *s, const char *credential,
                           const char *collection, YDShardControl **out) {
  *out = NULL;
  if (!allowed(s, credential, collection, false, false))
    return YD_SHARD_FORBIDDEN;
  unsigned char *p = NULL;
  size_t n = 0;
  YDShardStatus status =
      call(s, s->control, STATE, credential, (const unsigned char *)collection,
           strlen(collection), &p, &n);
  if (status == YD_SHARD_OK) {
    *out = yd_shard_control_import(p, n);
    if (!*out)
      status = YD_SHARD_CORRUPT;
  }
  free(p);
  return status;
}
static bool same_state(YDShardControl *a, YDShardControl *b) {
  size_t an, bn;
  unsigned char *ap = yd_shard_control_export(a, &an),
                *bp = yd_shard_control_export(b, &bn);
  bool same = ap && bp && an == bn && !memcmp(ap, bp, an);
  free(ap);
  free(bp);
  return same;
}
static bool registered(YDShardService *s, const YDShardPlacement *p) {
  if (!p)
    return false;
  for (size_t i = 0; i < yd_shard_placement_ranges(p); i++) {
    YDShardRange r;
    if (!yd_shard_placement_range(p, i, &r) ||
        !yd_shard_rpc_group(s->rpc, r.group))
      return false;
  }
  return true;
}
static YDShardStatus execute(YDShardService *s, const char *target,
                             const unsigned char *p, size_t n,
                             unsigned char **out, size_t *size) {
  YDRaftWrite w = {.method = "YSHARD", .target = target, .body = p, .size = n};
  unsigned char hash[32];
  unsigned hn = 0;
  EVP_MD_CTX *md = EVP_MD_CTX_new();
  bool ok = md && EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1 &&
            EVP_DigestUpdate(md, target, strlen(target) + 1) == 1 &&
            EVP_DigestUpdate(md, p, n) == 1 &&
            EVP_DigestFinal_ex(md, hash, &hn) == 1 && hn == 32;
  EVP_MD_CTX_free(md);
  if (!ok)
    return YD_SHARD_RESOURCE_FAILURE;
  memcpy(w.id, hash, 16);
  w.id[0] |= 1;
  YDDiskReply reply = s->cb.execute(s->cb.context, &w, s->timeout);
  YDShardStatus status = YD_SHARD_UNAVAILABLE;
  if (reply.status == 200) {
    *out = (unsigned char *)reply.body;
    *size = reply.length;
    reply.body = NULL;
    status = YD_SHARD_OK;
  } else if (reply.status == 403)
    status = YD_SHARD_FORBIDDEN;
  else if (reply.status == 409)
    status = YD_SHARD_CONFLICT;
  else if (reply.status == 413)
    status = YD_SHARD_BUDGET_EXCEEDED;
  else if (reply.status >= 400 && reply.status < 500)
    status = YD_SHARD_INVALID_ARGUMENT;
  yd_disk_reply_free(&reply);
  return status;
}
static YDShardStatus dispatch(void *context, unsigned kind,
                              const char *credential, const unsigned char *p,
                              size_t n, unsigned char **out, size_t *size) {
  YDShardService *s = context;
  *out = NULL;
  *size = 0;
  if (kind == STATE) {
    if (strcmp(s->group, s->control) || !p || !n || n > 63 || memchr(p, 0, n))
      return YD_SHARD_INVALID_ARGUMENT;
    char collection[64];
    memcpy(collection, p, n);
    collection[n] = 0;
    if (!allowed(s, credential, collection, false, false))
      return YD_SHARD_FORBIDDEN;
    YDRaftView *v = s->cb.view(s->cb.context, s->timeout);
    if (!v)
      return YD_SHARD_UNAVAILABLE;
    YDDiskView at = yd_raft_view_value(v);
    /* Each collection has its own record; an uninstalled one reads empty. */
    YDShardControl *c =
        yd_shard_control_open_collection_at(yd_raft_view_disk(v), &at, collection);
    const YDShardPlacement *place = yd_shard_control_placement(c);
    YDShardStatus status =
        !c ? YD_SHARD_CORRUPT
        : place && strcmp(collection, yd_shard_placement_collection(place))
            ? YD_SHARD_CORRUPT
            : YD_SHARD_OK;
    if (status == YD_SHARD_OK) {
      *out = yd_shard_control_export(c, size);
      if (!*out)
        status = YD_SHARD_RESOURCE_FAILURE;
    }
    yd_shard_control_close(c);
    yd_raft_view_close(v);
    return status;
  }
  if (kind == CONTROL) {
    if (strcmp(s->group, s->control) || !p || n < 36 || memcmp(p, "YCC1", 4))
      return YD_SHARD_INVALID_ARGUMENT;
    YDShardControl *next = yd_shard_control_import(p + 36, n - 36);
    const YDShardPlacement *place = yd_shard_control_placement(next);
    if (!place) {
      yd_shard_control_close(next);
      return YD_SHARD_INVALID_ARGUMENT;
    }
    bool auth = allowed(s, credential, yd_shard_placement_collection(place),
                        true, true) &&
                registered(s, place);
    yd_shard_control_close(next);
    if (!auth)
      return YD_SHARD_FORBIDDEN;
    /* Authorization precedes execute(), which may replay a durable receipt. */
    return execute(s, "/internal/shard/control", p, n, out, size);
  }
  if (kind != NATIVE)
    return YD_SHARD_INVALID_ARGUMENT;
  Decoded d;
  if (!request_get(p, n, &d))
    return YD_SHARD_INVALID_ARGUMENT;
  bool write = d.q.operation != YD_SHARD_RPC_READ &&
               d.q.operation != YD_SHARD_RPC_SCAN &&
               d.q.operation != YD_SHARD_RPC_LOG;
  /* Migration operations and both change-log operations need admin. */
  bool admin = d.q.operation >= YD_SHARD_RPC_FREEZE;
  const char *collection = yd_shard_placement_collection(d.q.placement);
  YDShardStatus status = YD_SHARD_FORBIDDEN;
  if (strcmp(d.group, s->group) ||
      !allowed(s, credential, collection, write, admin))
    goto end;
  YDShardControl *trusted = NULL;
  status = state(s, credential, collection, &trusted);
  if (status == YD_SHARD_OK && !same_state(trusted, d.control))
    status = YD_SHARD_STALE_PLACEMENT;
  yd_shard_control_close(trusted);
  if (status != YD_SHARD_OK)
    goto end;
  if (write) {
    status = execute(s, "/internal/shard/native", p, n, out, size);
    goto end;
  }
  bool scan = d.q.operation == YD_SHARD_RPC_SCAN &&
              !(d.q.migration.phase == YD_SHARD_COPYING &&
                !strcmp(d.q.migration.shard, d.q.range.shard));
  if (scan && d.snapshot[0]) {
    /* A pinned data view does not prove current leadership or a majority.
     * Close the fresh proof before taking the capture mutex; retain the
     * original capture generation for stable pagination. */
    YDRaftView *proof = s->cb.view(s->cb.context, s->timeout);
    if (!proof) {
      status = YD_SHARD_UNAVAILABLE;
      goto end;
    }
    yd_raft_view_close(proof);
    pthread_mutex_lock(&s->snapshots);
    Capture *capture = NULL;
    for (size_t i = 0; i < 64; i++)
      if (s->captures[i].view && !strcmp(s->captures[i].token, d.snapshot) &&
          !strcmp(s->captures[i].shard, d.q.range.shard) &&
          !strcmp(s->captures[i].credential, credential) &&
          same_state(s->captures[i].control, d.control)) {
        capture = s->captures + i;
        break;
      }
    YDShardResponse response = {0};
    status = YD_SHARD_STALE_PLACEMENT;
    if (capture) {
      YDDiskView at = yd_raft_view_value(capture->view);
      status = yd_shard_native_call_at(capture->native, &at, &d.q, &response);
      if (status == YD_SHARD_OK && !response_put(&response, out, size))
        status = YD_SHARD_RESOURCE_FAILURE;
      if (status != YD_SHARD_OK || response.page.end)
        capture_free(capture);
    }
    yd_shard_page_free(&response.page);
    pthread_mutex_unlock(&s->snapshots);
    goto end;
  }
  YDRaftView *v = s->cb.view(s->cb.context, s->timeout);
  if (!v) {
    status = YD_SHARD_UNAVAILABLE;
    goto end;
  }
  YDDiskView at = yd_raft_view_value(v);
  YDShardNative *native =
      yd_shard_native_open(yd_raft_view_disk(v), s->group, d.control);
  YDShardResponse response = {0};
  status = native ? yd_shard_native_call_at(native, &at, &d.q, &response)
                  : YD_SHARD_RESOURCE_FAILURE;
  if (status == YD_SHARD_OK && !response_put(&response, out, size))
    status = YD_SHARD_RESOURCE_FAILURE;
  if (scan && status == YD_SHARD_OK && !response.page.end) {
    char *copy = strdup(credential);
    if (!copy) {
      free(*out);
      *out = NULL;
      *size = 0;
      status = YD_SHARD_RESOURCE_FAILURE;
    } else {
      pthread_mutex_lock(&s->snapshots);
      Capture *capture = s->captures + s->next_capture;
      capture_free(capture);
      *capture = (Capture){.view = v,
                           .native = native,
                           .control = d.control,
                           .credential = copy};
      strcpy(capture->token, response.snapshot);
      strcpy(capture->shard, d.q.range.shard);
      s->next_capture = (s->next_capture + 1) % 64;
      pthread_mutex_unlock(&s->snapshots);
      v = NULL;
      native = NULL;
      d.control = NULL;
    }
  }
  yd_shard_page_free(&response.page);
  yd_shard_native_close(native);
  if (v)
    yd_raft_view_close(v);
end:
  decoded_free(&d);
  return status;
}
YDShardService *yd_shard_service_new(const YDShardServiceConfig *c) {
  if (!c || !c->local_group || strnlen(c->local_group, 64) > 63 ||
      !c->control_group || strnlen(c->control_group, 64) > 63 ||
      !c->callbacks.execute || !c->callbacks.view || !c->callbacks.authorize)
    return NULL;
  YDShardTransport *rpc = yd_shard_rpc_new(c->tls, c->local_name, c->peers,
                                           c->peer_count, c->timeout_ms);
  if (!rpc)
    return NULL;
  if (!yd_shard_rpc_group(rpc, c->local_group) ||
      !yd_shard_rpc_group(rpc, c->control_group)) {
    yd_shard_rpc_free(rpc);
    return NULL;
  }
  bool local = false;
  for (size_t i = 0; i < c->peer_count; i++)
    if (!strcmp(c->peers[i].name, c->local_name) &&
        !strcmp(c->peers[i].group, c->local_group))
      local = true;
  if (!local) {
    yd_shard_rpc_free(rpc);
    return NULL;
  }
  YDShardService *s = calloc(1, sizeof(*s));
  if (!s) {
    yd_shard_rpc_free(rpc);
    return NULL;
  }
  s->rpc = rpc;
  s->cb = c->callbacks;
  s->timeout = c->timeout_ms;
  s->listener = -1;
  if (pthread_mutex_init(&s->snapshots, NULL)) {
    yd_shard_rpc_free(rpc);
    free(s);
    return NULL;
  }
  strcpy(s->group, c->local_group);
  strcpy(s->control, c->control_group);
  atomic_init(&s->stop, false);
  return s;
}
bool yd_shard_service_serve(YDShardService *s, int fd) {
  return s && yd_shard_rpc_serve(s->rpc, fd, dispatch, s);
}
static void *worker(void *p) {
  YDShardService *s = p;
  while (!atomic_load(&s->stop)) {
    struct pollfd f = {.fd = s->listener, .events = POLLIN};
    int rc = poll(&f, 1, 100);
    if (rc < 0 && errno == EINTR)
      continue;
    if (rc <= 0)
      continue;
    int fd = accept(s->listener, NULL, NULL);
    if (fd < 0)
      continue;
    int flags = fcntl(fd, F_GETFD);
    if (flags >= 0)
      fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    yd_shard_service_serve(s, fd);
    close(fd);
  }
  return NULL;
}
bool yd_shard_service_start(YDShardService *s) {
  if (!s || s->listener < 0 || s->running)
    return false;
  s->running = pthread_create(&s->worker, NULL, worker, s) == 0;
  return s->running;
}
void yd_shard_service_free(YDShardService *s) {
  if (!s)
    return;
  atomic_store(&s->stop, true);
  if (s->running)
    pthread_join(s->worker, NULL);
  if (s->listener >= 0)
    close(s->listener);
  for (size_t i = 0; i < 64; i++)
    capture_free(s->captures + i);
  pthread_mutex_destroy(&s->snapshots);
  yd_shard_rpc_free(s->rpc);
  yd_tls_free(s->tls);
  yd_free(s->model);
  free(s);
}
static bool fields(const YDValue *v, const char *const names[], size_t n) {
  if (!v || v->type != YD_MAP)
    return false;
  for (size_t i = 0; i < v->count; i++) {
    size_t j = 0;
    while (j < n && strcmp(v->keys[i], names[j]))
      j++;
    if (j == n)
      return false;
  }
  return true;
}
static const char *string(const YDValue *v) {
  return v && v->type == YD_STRING ? v->scalar : NULL;
}
static bool integer(const YDValue *v, uint64_t low, uint64_t high,
                    uint64_t *out) {
  uint64_t n;
  if (!v || v->type != YD_INT || !yd_integer_bits(v->scalar, &n) ||
      n > INT64_MAX || n < low || n > high)
    return false;
  *out = n;
  return true;
}
static const char *path(const YDValue *v) {
  const char *s = string(v);
  if (!s || s[0] != '/' || strlen(s) > 4096)
    return NULL;
  for (size_t i = 0; s[i]; i++)
    if ((unsigned char)s[i] < 32 || s[i] == 127)
      return NULL;
  return s;
}
static int listen_private(const char *address, unsigned port) {
  struct sockaddr_storage ss = {0};
  socklen_t length;
  int family;
  struct sockaddr_in *a = (struct sockaddr_in *)&ss;
  struct sockaddr_in6 *b = (struct sockaddr_in6 *)&ss;
  a->sin_family = AF_INET;
  a->sin_port = htons((uint16_t)port);
  if (address && inet_pton(AF_INET, address, &a->sin_addr) == 1) {
    uint32_t n = ntohl(a->sin_addr.s_addr);
    if (!((n >> 24) == 10 || (n >> 24) == 127 || (n >> 20) == 0xac1 ||
          (n >> 16) == 0xc0a8))
      return -1;
    family = AF_INET;
    length = sizeof(*a);
  } else {
    memset(&ss, 0, sizeof(ss));
    b->sin6_family = AF_INET6;
    b->sin6_port = htons((uint16_t)port);
    if (!address || inet_pton(AF_INET6, address, &b->sin6_addr) != 1 ||
        !((b->sin6_addr.s6_addr[0] & 0xfe) == 0xfc ||
          IN6_IS_ADDR_LOOPBACK(&b->sin6_addr)))
      return -1;
    family = AF_INET6;
    length = sizeof(*b);
  }
  int fd = socket(family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (fd < 0)
    return -1;
  int one = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) ||
      bind(fd, (struct sockaddr *)&ss, length) || listen(fd, 32)) {
    close(fd);
    return -1;
  }
  return fd;
}
YDShardService *yd_shard_service_load(const char *file,
                                      const YDShardServiceCallbacks *cb,
                                      char *error, size_t length) {
  size_t n = 0;
  char *source = yd_access_read_private(file, YD_SHARD_METADATA_LIMIT, &n);
  YDValue *m = source ? yd_parse_sized((unsigned char *)source, n,
                                       YD_SHARD_METADATA_LIMIT, NULL, 0)
                      : NULL;
  free(source);
  static const char *const root[] = {
      "version", "local_name", "local_group", "control_group",
      "listen",  "peer_tls",   "peers",       "request_timeout_ms"};
  static const char *const tlsfields[] = {"cert_file", "key_file", "ca_file",
                                          "crl_file"},
                           *const listenfields[] = {"address", "port"},
                           *const peerfields[] = {"group", "name", "address",
                                                  "port"};
  YDShardService *s = NULL;
  YDTLS *tls = NULL;
  YDShardEndpoint peers[YD_SHARD_RPC_PEERS];
  YDShardServiceConfig c = {.timeout_ms = 5000};
  uint64_t version, port, timeout = 5000;
  const YDValue *t = yd_get(m, "peer_tls"), *l = yd_get(m, "listen"),
                *ps = yd_get(m, "peers");
  const char *cert = path(yd_get(t, "cert_file")),
             *key = path(yd_get(t, "key_file")),
             *ca = path(yd_get(t, "ca_file")),
             *crl = path(yd_get(t, "crl_file"));
  if (!cb || !fields(m, root, 8) ||
      !integer(yd_get(m, "version"), 1, 1, &version) ||
      !fields(t, tlsfields, 4) || !cert || !key || !ca ||
      (yd_get(t, "crl_file") && !crl) || !fields(l, listenfields, 2) ||
      !integer(yd_get(l, "port"), 1, 65535, &port) || !ps ||
      ps->type != YD_ARRAY || !ps->count || ps->count > YD_SHARD_RPC_PEERS ||
      (yd_get(m, "request_timeout_ms") &&
       !integer(yd_get(m, "request_timeout_ms"), 100, 30000, &timeout)))
    goto bad;
  for (size_t i = 0; i < ps->count; i++) {
    const YDValue *p = ps->items[i];
    uint64_t pp;
    if (!fields(p, peerfields, 4) || !integer(yd_get(p, "port"), 1, 65535, &pp))
      goto bad;
    peers[i] =
        (YDShardEndpoint){string(yd_get(p, "group")), string(yd_get(p, "name")),
                          string(yd_get(p, "address")), (unsigned)pp};
  }
  YDTLSOptions options = {.crl_file = crl};
  tls = yd_tls_shard_new_with_options(cert, key, ca, &options, error, length);
  if (!tls)
    goto bad;
  c.tls = tls;
  c.local_name = string(yd_get(m, "local_name"));
  c.local_group = string(yd_get(m, "local_group"));
  c.control_group = string(yd_get(m, "control_group"));
  c.peers = peers;
  c.peer_count = ps->count;
  c.timeout_ms = (unsigned)timeout;
  c.callbacks = *cb;
  s = yd_shard_service_new(&c);
  if (!s)
    goto bad;
  /* The advertised local endpoint and listener must be identical. */
  bool found = false;
  const char *address = string(yd_get(l, "address"));
  for (size_t i = 0; i < ps->count; i++)
    if (!strcmp(peers[i].name, c.local_name))
      found = address && !strcmp(address, peers[i].address) &&
              port == peers[i].port;
  if (!found || (s->listener = listen_private(address, (unsigned)port)) < 0)
    goto bad;
  s->model = m;
  s->tls = tls;
  return s;
bad:
  yd_shard_service_free(s);
  yd_tls_free(tls);
  yd_free(m);
  if (error && length)
    snprintf(error, length,
             "invalid or unavailable private shard configuration");
  return NULL;
}
typedef struct {
  YDShardService *s;
  const char *credential, *collection;
  YDShardControl *control;
  const char *group;
} RouteCall;
static bool router_auth(void *ctx, const char *collection, bool write) {
  RouteCall *c = ctx;
  return allowed(c->s, c->credential, collection, write, false);
}
static YDShardStatus router_call(void *ctx, const YDShardRequest *q,
                                 YDShardResponse *response) {
  RouteCall *c = ctx;
  unsigned char *body = NULL, *reply = NULL;
  size_t n = 0, rn = 0;
  if (!request_put(c->control, c->group, q, &body, &n))
    return YD_SHARD_RESOURCE_FAILURE;
  YDShardStatus status =
      call(c->s, c->group, NATIVE, c->credential, body, n, &reply, &rn);
  free(body);
  if (status == YD_SHARD_OK && !response_get(reply, rn, response))
    status = YD_SHARD_CORRUPT;
  free(reply);
  return status;
}
static YDShardStatus router_commit(void *ctx, const unsigned char *p,
                                   size_t n) {
  RouteCall *c = ctx;
  unsigned char *reply = NULL;
  size_t rn = 0;
  YDShardStatus status =
      call(c->s, c->s->control, CONTROL, c->credential, p, n, &reply, &rn);
  free(reply);
  return status;
}
/* Bind every group of a placement plus both migration peers. Names are owned
 * (strdup) because range/migration storage is local; the caller frees
 * bindings[i].group for i < *count on every outcome. */
static YDShardStatus bind_groups(YDShardService *s, YDShardControl *c,
                                 const RouteCall *base,
                                 YDShardBinding *bindings, RouteCall *contexts,
                                 size_t *count) {
  const YDShardPlacement *place = yd_shard_control_placement(c);
  *count = 0;
  /* Keep both migration peers registered after ownership publication removes
   * the source's last range. Resumption must still validate both bindings. */
  for (size_t i = 0; i < yd_shard_placement_ranges(place) + 2; i++) {
    YDShardRange range;
    char group[64];
    if (i < yd_shard_placement_ranges(place)) {
      yd_shard_placement_range(place, i, &range);
      strcpy(group, range.group);
    } else {
      YDShardMigration migration = yd_shard_control_migration(c);
      if (migration.phase == YD_SHARD_IDLE)
        continue;
      strcpy(group, i == yd_shard_placement_ranges(place) ? migration.target
                                                          : migration.source);
    }
    bool seen = false;
    for (size_t j = 0; j < *count; j++)
      seen |= !strcmp(bindings[j].group, group);
    if (seen)
      continue;
    if (*count == YD_SHARD_RPC_PEERS || !yd_shard_rpc_group(s->rpc, group))
      return YD_SHARD_UNAVAILABLE;
    char *owned = strdup(group);
    if (!owned)
      return YD_SHARD_RESOURCE_FAILURE;
    contexts[*count] = *base;
    contexts[*count].group = owned;
    bindings[*count] = (YDShardBinding){owned, router_call, contexts + *count};
    (*count)++;
  }
  return YD_SHARD_OK;
}
/* A foreign $lookup relation: the same credential, a fresh trusted control
 * read for that collection, and bindings for its own groups. */
typedef struct {
  YDShardRouter router; /* first: release receives this pointer */
  RouteCall base;
  YDShardBinding bindings[YD_SHARD_RPC_PEERS];
  RouteCall contexts[YD_SHARD_RPC_PEERS];
  size_t count;
  YDShardControl *control;
  char collection[64];
} Foreign;
static void router_release(void *ctx, YDShardRouter *router) {
  (void)ctx;
  Foreign *f = (Foreign *)router;
  if (!f)
    return;
  for (size_t i = 0; i < f->count; i++)
    free((void *)f->bindings[i].group);
  yd_shard_control_close(f->control);
  free(f);
}
static YDShardStatus router_resolve(void *ctx, const char *collection,
                                    YDShardRouter **out) {
  RouteCall *c = ctx;
  *out = NULL;
  if (!collection || !collection[0] || strnlen(collection, 64) > 63)
    return YD_SHARD_INVALID_ARGUMENT;
  Foreign *f = calloc(1, sizeof(*f));
  if (!f)
    return YD_SHARD_RESOURCE_FAILURE;
  strcpy(f->collection, collection);
  YDShardStatus status = state(c->s, c->credential, f->collection, &f->control);
  if (status == YD_SHARD_OK && !yd_shard_control_placement(f->control))
    status = YD_SHARD_CROSS_SHARD_UNSUPPORTED; /* not a sharded collection */
  if (status == YD_SHARD_OK) {
    f->base = (RouteCall){c->s, c->credential, f->collection, f->control, NULL};
    status = bind_groups(c->s, f->control, &f->base, f->bindings, f->contexts,
                         &f->count);
  }
  if (status != YD_SHARD_OK) {
    router_release(NULL, &f->router);
    return status;
  }
  f->router = (YDShardRouter){.control = f->control,
                              .bindings = f->bindings,
                              .binding_count = f->count,
                              .authorize = router_auth,
                              .auth_context = &f->base};
  *out = &f->router;
  return YD_SHARD_OK;
}
static bool json_string(Buffer *b, const char *p, size_t n) {
  char *copy = malloc(n + 1);
  if (!copy) {
    b->bad = true;
    return false;
  }
  memcpy(copy, p, n);
  copy[n] = 0;
  YDValue value = {.type = YD_STRING, .scalar = copy};
  size_t size;
  char *json = yd_json(&value, &size);
  free(copy);
  if (!json) {
    b->bad = true;
    return false;
  }
  put(b, json, size);
  free(json);
  return !b->bad;
}
static YDDiskReply json_rows(const YDShardPage *page, uint64_t matched,
                             uint64_t visited, size_t shards) {
  Buffer b = {0};
  char header[192];
  int hn = snprintf(
      header, sizeof(header),
      "{\"matched\":%llu,\"visited\":%llu,\"shards\":%zu,\"rows\":[",
      (unsigned long long)matched, (unsigned long long)visited, shards);
  put(&b, header, (size_t)hn);
  for (size_t i = 0; i < page->count; i++) {
    const YDShardRow *row = page->rows + i;
    if (i)
      put(&b, ",", 1);
    put(&b, "{\"id\":", 6);
    json_string(&b, row->id, strlen(row->id));
    put(&b, ",\"source\":", 10);
    json_string(&b, (const char *)row->source, row->length);
    put(&b, "}", 1);
  }
  put(&b, "]}", 2);
  unsigned char *out = NULL;
  size_t n = 0;
  if (!finish(&b, &out, &n))
    return failure(YD_SHARD_BUDGET_EXCEEDED);
  return (YDDiskReply){.status = 200,
                       .body = (char *)out,
                       .length = n,
                       .content_type = "application/json"};
}
/* {"results": <array>, "input": {...}, "lookups": [{from, mode, ...}]}.
 * Collection names are grammar-checked identifiers. */
static YDDiskReply explain_json(const char *results, size_t n,
                                const YDShardJoinStats *stats) {
  Buffer b = {0};
  char text[320];
  put(&b, "{\"results\":", 11);
  put(&b, results, n);
  int z = snprintf(text, sizeof(text),
                   ",\"input\":{\"rows\":%llu,\"bytes\":%llu,\"shards\":%zu},"
                   "\"global_snapshot\":false,\"lookups\":[",
                   (unsigned long long)stats->input_rows,
                   (unsigned long long)stats->input_bytes, stats->input_shards);
  put(&b, text, (size_t)z);
  for (size_t i = 0; i < stats->relations; i++) {
    const YDShardJoinRelation *r = stats->relation + i;
    z = snprintf(text, sizeof(text),
                 "%s{\"from\":\"%s\",\"mode\":\"%s\",\"shards\":%zu,"
                 "\"ranges\":%zu,\"rows\":%llu,\"bytes\":%llu}",
                 i ? "," : "", r->collection,
                 r->local ? "input" : r->targeted ? "targeted" : "scatter",
                 r->shards, r->ranges, (unsigned long long)r->rows,
                 (unsigned long long)r->bytes);
    put(&b, text, (size_t)z);
  }
  put(&b, "]}", 2);
  unsigned char *out = NULL;
  size_t size = 0;
  if (!finish(&b, &out, &size))
    return failure(YD_SHARD_BUDGET_EXCEEDED);
  return (YDDiskReply){.status = 200,
                       .body = (char *)out,
                       .length = size,
                       .content_type = "application/json"};
}
/* {"changes":[{shard, sequence, epoch, operation, id, key, source?}],
 *  "next_after", "has_more", "epoch", "shards"}. Shard names are
 * grammar-checked; IDs, sources and the token go through the JSON encoder. */
static YDDiskReply changes_json(const YDShardChanges *c) {
  Buffer b = {0};
  put(&b, "{\"changes\":[", 12);
  for (size_t i = 0; i < c->count; i++) {
    const YDShardChange *e = c->changes + i;
    char head[192], key[2 * YD_SHARD_KEY_BYTES + 1];
    for (size_t k = 0; k < e->key.length; k++)
      snprintf(key + 2 * k, 3, "%02x", e->key.bytes[k]);
    key[2 * e->key.length] = 0;
    int z = snprintf(head, sizeof(head),
                     "%s{\"shard\":\"%s\",\"sequence\":%llu,\"epoch\":%llu,"
                     "\"operation\":\"%s\",\"id\":",
                     i ? "," : "", e->shard, (unsigned long long)e->sequence,
                     (unsigned long long)e->epoch,
                     e->deleted ? "delete" : "write");
    put(&b, head, (size_t)z);
    json_string(&b, e->id, strlen(e->id));
    put(&b, ",\"key\":\"", 8);
    put(&b, key, strlen(key));
    put(&b, "\"", 1);
    if (!e->deleted) {
      put(&b, ",\"source\":", 10);
      json_string(&b, (const char *)e->source, e->length);
    }
    put(&b, "}", 1);
  }
  put(&b, "],\"next_after\":", 15);
  json_string(&b, c->next, strlen(c->next));
  char tail[128];
  int z = snprintf(tail, sizeof(tail),
                   ",\"has_more\":%s,\"epoch\":%llu,\"shards\":%zu}",
                   c->more ? "true" : "false", (unsigned long long)c->epoch,
                   c->shards);
  put(&b, tail, (size_t)z);
  unsigned char *out = NULL;
  size_t size = 0;
  if (!finish(&b, &out, &size))
    return failure(YD_SHARD_BUDGET_EXCEEDED);
  return (YDDiskReply){.status = 200,
                       .body = (char *)out,
                       .length = size,
                       .content_type = "application/json"};
}
static YDDiskReply state_json(YDShardControl *c) {
  const YDShardPlacement *p = yd_shard_control_placement(c);
  if (!p)
    return yd_disk_error_reply(404, "shard_placement_missing");
  size_t n;
  unsigned char *metadata = yd_shard_placement_encode(p, &n);
  if (!metadata)
    return failure(YD_SHARD_RESOURCE_FAILURE);
  YDShardMigration m = yd_shard_control_migration(c);
  Buffer b = {0};
  put(&b, "{\"placement\":", 13);
  put(&b, metadata, n);
  free(metadata);
  char tail[320];
  int z = snprintf(tail, sizeof(tail),
                   ",\"migration\":{\"phase\":%u,\"sequence\":%llu,\"id\":\"%"
                   "s\",\"rows\":%llu,\"bytes\":%llu,\"copied\":%s}}",
                   (unsigned)m.phase, (unsigned long long)m.sequence,
                   m.migration, (unsigned long long)m.rows,
                   (unsigned long long)m.bytes, m.copied ? "true" : "false");
  put(&b, tail, (size_t)z);
  unsigned char *out;
  size_t size;
  if (!finish(&b, &out, &size))
    return failure(YD_SHARD_RESOURCE_FAILURE);
  return (YDDiskReply){.status = 200,
                       .body = (char *)out,
                       .length = size,
                       .content_type = "application/json"};
}
YDDiskReply yd_shard_service_request(YDShardService *s, const char *credential,
                                     const char *method, const char *target,
                                     const unsigned char *body, size_t n) {
  if (!s)
    return yd_disk_error_reply(503, "sharding_disabled");
  if (!method || !target || n > YD_SHARD_RPC_BYTES)
    return failure(YD_SHARD_INVALID_ARGUMENT);
  bool get = !strcmp(method, "GET") &&
             !strncmp(target, "/v1/sharding?collection=", 24);
  char get_collection[64] = {0};
  YDValue *m = NULL;
  const char *collection = NULL;
  if (get) {
    const char *v = target + 24;
    if (!v[0] || strnlen(v, 64) > 63)
      return failure(YD_SHARD_INVALID_ARGUMENT);
    strcpy(get_collection, v);
    collection = get_collection;
  } else {
    if (strcmp(method, "POST"))
      return failure(YD_SHARD_INVALID_ARGUMENT);
    m = yd_parse_request(body, n, NULL, 0);
    collection = string(yd_get(m, "collection"));
  }
  YDDiskReply reply = {0};
  YDShardControl *c = NULL;
  YDShardStatus status = YD_SHARD_INVALID_ARGUMENT;
  if (!get && !strcmp(target, "/v1/sharding/install")) {
    /* Installation accepts the placement document itself. */
    YDShardPlacement *place = NULL;
    status = yd_shard_placement_parse(body, n, &place);
    if (status != YD_SHARD_OK)
      goto end;
    collection = yd_shard_placement_collection(place);
    if (!allowed(s, credential, collection, true, true) ||
        !registered(s, place)) {
      status = YD_SHARD_FORBIDDEN;
      yd_shard_placement_free(place);
      goto end;
    }
    status = state(s, credential, collection, &c);
    yd_shard_placement_free(place);
    if (status != YD_SHARD_OK)
      goto end;
    unsigned char *command = NULL, *out = NULL;
    size_t cn = 0, on = 0;
    status = yd_shard_control_install(c, body, n, &command, &cn);
    if (status == YD_SHARD_OK)
      status = call(s, s->control, CONTROL, credential, command, cn, &out, &on);
    free(command);
    free(out);
    goto end;
  }
  if (!collection) {
    status = YD_SHARD_INVALID_ARGUMENT;
    goto end;
  }
  /* The change feed exposes every document of every shard: admin only. */
  bool admin = !get && (!strcmp(target, "/v1/sharding/migrate") ||
                        !strcmp(target, "/v1/sharding/step") ||
                        !strcmp(target, "/v1/sharding/changes"));
  bool write = admin || (!get && !strcmp(target, "/v1/sharding/route") &&
                         strcmp(string(yd_get(m, "operation"))
                                    ? string(yd_get(m, "operation"))
                                    : "",
                                "read"));
  if (!allowed(s, credential, collection, write, admin)) {
    status = YD_SHARD_FORBIDDEN;
    goto end;
  }
  status = state(s, credential, collection, &c);
  if (status != YD_SHARD_OK)
    goto end;
  const YDShardPlacement *place = yd_shard_control_placement(c);
  if (get) {
    reply = state_json(c);
    goto end;
  }
  if (!place) {
    status = YD_SHARD_STALE_PLACEMENT;
    goto end;
  }
  RouteCall base = {s, credential, collection, c, NULL};
  YDShardBinding bindings[YD_SHARD_RPC_PEERS];
  RouteCall contexts[YD_SHARD_RPC_PEERS];
  size_t count = 0;
  status = bind_groups(s, c, &base, bindings, contexts, &count);
  if (status != YD_SHARD_OK)
    goto bindings_end;
  YDShardRouter router = {.control = c,
                          .bindings = bindings,
                          .binding_count = count,
                          .authorize = router_auth,
                          .auth_context = &base,
                          .commit = router_commit,
                          .commit_context = &base,
                          .resolve = router_resolve,
                          .release = router_release,
                          .resolve_context = &base};
  if (!strcmp(target, "/v1/sharding/migrate")) {
    static const char *const names[] = {"collection", "shard", "target",
                                        "mutation_id"};
    if (!fields(m, names, 4))
      goto invalid;
    const char *shard = string(yd_get(m, "shard")),
               *to = string(yd_get(m, "target")),
               *id = string(yd_get(m, "mutation_id"));
    if (!yd_shard_rpc_group(s->rpc, to)) {
      status = YD_SHARD_UNAVAILABLE;
      goto bindings_end;
    }
    unsigned char *command = NULL;
    size_t cn = 0;
    status = yd_shard_control_begin(c, shard, to, id, &command, &cn);
    if (status == YD_SHARD_OK)
      status = router_commit(&base, command, cn);
    free(command);
  } else if (!strcmp(target, "/v1/sharding/step")) {
    static const char *const names[] = {"collection"};
    if (!fields(m, names, 1))
      goto invalid;
    status = yd_shard_migrate_step(&router);
  } else {
    const char *placement = string(yd_get(m, "placement_id"));
    uint64_t epoch;
    if (!placement || !integer(yd_get(m, "epoch"), 1, INT64_MAX, &epoch))
      goto invalid;
    if (!strcmp(target, "/v1/sharding/route")) {
      static const char *const names[] = {"collection", "placement_id", "epoch",
                                          "operation",  "key",          "id",
                                          "source",     "mutation_id"};
      if (!fields(m, names, 8))
        goto invalid;
      const char *op = string(yd_get(m, "operation")),
                 *id = string(yd_get(m, "id")),
                 *source = string(yd_get(m, "source")),
                 *mutation = string(yd_get(m, "mutation_id"));
      YDShardRPC operation;
      if (op && !strcmp(op, "read"))
        operation = YD_SHARD_RPC_READ;
      else if (op && !strcmp(op, "write"))
        operation = YD_SHARD_RPC_WRITE;
      else if (op && !strcmp(op, "delete"))
        operation = YD_SHARD_RPC_DELETE;
      else
        goto invalid;
      YDShardKey key;
      status = yd_shard_placement_key(place, yd_get(m, "key"), &key);
      if (status != YD_SHARD_OK)
        goto bindings_end;
      YDShardResponse response = {0};
      status = yd_shard_route(&router, placement, collection, epoch, operation,
                              &key, id, (const unsigned char *)source,
                              source ? strlen(source) : 0, mutation, &response);
      if (status == YD_SHARD_OK)
        reply = json_rows(&response.page, response.page.count,
                          response.page.count, 1);
      yd_shard_page_free(&response.page);
    } else if (!strcmp(target, "/v1/sharding/gather")) {
      static const char *const names[] = {
          "collection", "placement_id", "epoch",    "sort",     "descending",
          "offset",     "limit",        "max_rows", "max_bytes"};
      if (!fields(m, names, 9))
        goto invalid;
      uint64_t offset = 0, limit = 128, rows = YD_SHARD_GATHER_ROWS,
               limitbytes = YD_SHARD_RPC_BYTES / 2;
      if ((yd_get(m, "offset") &&
           !integer(yd_get(m, "offset"), 0, YD_SHARD_GATHER_ROWS, &offset)) ||
          (yd_get(m, "limit") &&
           !integer(yd_get(m, "limit"), 1, YD_SHARD_GATHER_ROWS, &limit)) ||
          (yd_get(m, "max_rows") &&
           !integer(yd_get(m, "max_rows"), 1, YD_SHARD_GATHER_ROWS, &rows)) ||
          (yd_get(m, "max_bytes") &&
           !integer(yd_get(m, "max_bytes"), 1, YD_SHARD_GATHER_BYTES,
                    &limitbytes)))
        goto invalid;
      const YDValue *desc = yd_get(m, "descending");
      if (desc && desc->type != YD_BOOL)
        goto invalid;
      const char *sort = string(yd_get(m, "sort"));
      if (yd_get(m, "sort") && !sort)
        goto invalid;
      YDShardQuery q = {.sort_field = sort,
                        .descending = desc && desc->boolean,
                        .offset = (size_t)offset,
                        .limit = (size_t)limit,
                        .max_rows = (size_t)rows,
                        .max_bytes = (size_t)limitbytes};
      YDShardResult result = {0};
      status =
          yd_shard_gather(&router, placement, collection, epoch, &q, &result);
      if (status == YD_SHARD_OK)
        reply = json_rows(&result.page, result.matched, result.visited,
                          result.shards);
      yd_shard_page_free(&result.page);
    } else if (!strcmp(target, "/v1/sharding/aggregate")) {
      static const char *const names[] = {
          "collection",       "placement_id",      "epoch",
          "pipeline",         "max_rows",          "max_bytes",
          "max_foreign_rows", "max_foreign_bytes", "max_matches",
          "max_time_ms",      "explain"};
      if (!fields(m, names, 11))
        goto invalid;
      uint64_t rows = YD_SHARD_GATHER_ROWS, limitbytes = YD_SHARD_RPC_BYTES / 2,
               foreign_rows = YD_SHARD_GATHER_ROWS,
               foreign_bytes = YD_SHARD_RPC_BYTES / 2, matches = 1024,
               milliseconds = 10000;
      const YDValue *explain = yd_get(m, "explain");
      if ((yd_get(m, "max_rows") &&
           !integer(yd_get(m, "max_rows"), 1, YD_SHARD_GATHER_ROWS, &rows)) ||
          (yd_get(m, "max_bytes") &&
           !integer(yd_get(m, "max_bytes"), 1, YD_SHARD_GATHER_BYTES,
                    &limitbytes)) ||
          (yd_get(m, "max_foreign_rows") &&
           !integer(yd_get(m, "max_foreign_rows"), 1, YD_SHARD_GATHER_ROWS,
                    &foreign_rows)) ||
          (yd_get(m, "max_foreign_bytes") &&
           !integer(yd_get(m, "max_foreign_bytes"), 1, YD_SHARD_GATHER_BYTES,
                    &foreign_bytes)) ||
          (yd_get(m, "max_matches") &&
           !integer(yd_get(m, "max_matches"), 1, 1024, &matches)) ||
          (yd_get(m, "max_time_ms") &&
           !integer(yd_get(m, "max_time_ms"), 1, 30000, &milliseconds)) ||
          (explain && explain->type != YD_BOOL))
        goto invalid;
      YDShardJoinLimits limits = {.max_rows = (size_t)rows,
                                  .max_bytes = (size_t)limitbytes,
                                  .max_foreign_rows = (size_t)foreign_rows,
                                  .max_foreign_bytes = (size_t)foreign_bytes,
                                  .max_matches = (size_t)matches,
                                  .max_time_ms = milliseconds};
      YDShardJoinStats stats;
      char *json = NULL, error[128];
      size_t jn = 0;
      status = yd_shard_aggregate_join(&router, placement, collection, epoch,
                                       yd_get(m, "pipeline"), &limits, &json,
                                       &jn, &stats, error, sizeof(error));
      if (status == YD_SHARD_OK && explain && explain->boolean) {
        reply = explain_json(json, jn, &stats);
        free(json);
      } else if (status == YD_SHARD_OK)
        reply = (YDDiskReply){.status = 200,
                              .body = json,
                              .length = jn,
                              .content_type = "application/json"};
      else
        free(json);
    } else if (!strcmp(target, "/v1/sharding/changes")) {
      static const char *const names[] = {"collection", "placement_id", "epoch",
                                          "after",      "limit",        "max_bytes"};
      if (!fields(m, names, 6))
        goto invalid;
      /* The default byte budget holds the largest record and leaves room for
       * JSON escaping within the reply bound. */
      uint64_t limit = 128, limitbytes = YD_SHARD_RPC_BYTES / 4;
      const YDValue *after = yd_get(m, "after");
      if ((after && after->type != YD_STRING) ||
          (yd_get(m, "limit") &&
           !integer(yd_get(m, "limit"), 1, YD_SHARD_CHANGES_LIMIT, &limit)) ||
          (yd_get(m, "max_bytes") &&
           !integer(yd_get(m, "max_bytes"), 1, YD_SHARD_CHANGES_BYTES,
                    &limitbytes)))
        goto invalid;
      YDShardChanges changes;
      status = yd_shard_changes(&router, placement, collection, epoch,
                                string(after), (size_t)limit,
                                (size_t)limitbytes, &changes);
      if (status == YD_SHARD_OK)
        reply = changes_json(&changes);
      yd_shard_changes_free(&changes);
    } else
      goto invalid;
  }
  goto bindings_end;
invalid:
  status = YD_SHARD_INVALID_ARGUMENT;
bindings_end:
  for (size_t i = 0; i < count; i++)
    free((void *)bindings[i].group);
end:
  yd_shard_control_close(c);
  yd_free(m);
  if (reply.status)
    return reply;
  if (status == YD_SHARD_OK)
    return (YDDiskReply){.status = 200,
                         .body = strdup("{\"ok\":true}"),
                         .length = 11,
                         .content_type = "application/json"};
  return failure(status);
}
