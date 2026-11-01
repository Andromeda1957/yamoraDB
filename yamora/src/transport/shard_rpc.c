#define _POSIX_C_SOURCE 200809L
#include "shard_rpc.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
typedef struct {
  char group[64], name[254];
  struct sockaddr_storage address;
  socklen_t length;
} Peer;
struct YDShardTransport {
  YDTLS *tls;
  char name[254];
  Peer peers[YD_SHARD_RPC_PEERS];
  size_t count;
  unsigned timeout;
  atomic_size_t memory;
};
static uint64_t now(void) {
  struct timespec t;
  return clock_gettime(CLOCK_MONOTONIC, &t)
             ? 0
             : (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static void put32(unsigned char *p, uint32_t n) {
  for (unsigned i = 0; i < 4; i++)
    p[i] = (unsigned char)(n >> (24 - 8 * i));
}
static uint32_t get32(const unsigned char *p) {
  return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 |
         p[3];
}
static bool name(const char *s, size_t max, bool dns) {
  size_t n = s ? strnlen(s, max + 1) : 0;
  if (!n || n > max || s[0] == '-' || s[n - 1] == '-')
    return false;
  for (size_t i = 0; i < n; i++)
    if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '0' && s[i] <= '9') ||
          s[i] == '-' || (dns && s[i] == '.')))
      return false;
  return true;
}
static bool endpoint(const YDShardEndpoint *p, Peer *out) {
  if (!p || !name(p->group, 63, false) || !name(p->name, 253, true) ||
      !p->address || !p->port || p->port > 65535)
    return false;
  struct sockaddr_in a = {.sin_family = AF_INET,
                          .sin_port = htons((uint16_t)p->port)};
  if (inet_pton(AF_INET, p->address, &a.sin_addr) == 1) {
    uint32_t n = ntohl(a.sin_addr.s_addr);
    if (!((n >> 24) == 10 || (n >> 24) == 127 || (n >> 20) == 0xac1 ||
          (n >> 16) == 0xc0a8))
      return false;
    memcpy(&out->address, &a, sizeof(a));
    out->length = sizeof(a);
  } else {
    struct sockaddr_in6 b = {.sin6_family = AF_INET6,
                             .sin6_port = htons((uint16_t)p->port)};
    if (inet_pton(AF_INET6, p->address, &b.sin6_addr) != 1 ||
        !((b.sin6_addr.s6_addr[0] & 0xfe) == 0xfc ||
          IN6_IS_ADDR_LOOPBACK(&b.sin6_addr)))
      return false;
    memcpy(&out->address, &b, sizeof(b));
    out->length = sizeof(b);
  }
  strcpy(out->group, p->group);
  strcpy(out->name, p->name);
  return true;
}
YDShardTransport *yd_shard_rpc_new(YDTLS *tls, const char *local,
                                   const YDShardEndpoint *p, size_t count,
                                   unsigned timeout) {
  if (!yd_tls_is_shard(tls) || !name(local, 253, true) || !p || !count ||
      count > YD_SHARD_RPC_PEERS || timeout < 1 || timeout > 30000)
    return NULL;
  YDShardTransport *r = calloc(1, sizeof(*r));
  if (!r)
    return NULL;
  r->tls = tls;
  r->timeout = timeout;
  r->count = count;
  strcpy(r->name, local);
  bool found = false;
  for (size_t i = 0; i < count; i++) {
    if (!endpoint(p + i, r->peers + i)) {
      free(r);
      return NULL;
    }
    found |= !strcmp(local, p[i].name);
    for (size_t j = 0; j < i; j++)
      if (!strcmp(p[i].name, p[j].name)) {
        free(r);
        return NULL;
      }
  }
  if (!found) {
    free(r);
    return NULL;
  }
  atomic_init(&r->memory, 0);
  return r;
}
void yd_shard_rpc_free(YDShardTransport *r) { free(r); }
bool yd_shard_rpc_group(const YDShardTransport *r, const char *group) {
  if (!r || !group)
    return false;
  for (size_t i = 0; i < r->count; i++)
    if (!strcmp(r->peers[i].group, group))
      return true;
  return false;
}
static bool reserve(YDShardTransport *r, size_t n) {
  size_t old = atomic_load(&r->memory);
  do {
    if (n > 8U * YD_SHARD_RPC_BYTES - old)
      return false;
  } while (!atomic_compare_exchange_weak(&r->memory, &old, old + n));
  return true;
}
static bool receive(YDConnection *c, void *p, size_t n, uint64_t end) {
  size_t k = 0;
  while (k < n) {
    ssize_t got = yd_connection_read(c, (unsigned char *)p + k, n - k, end);
    if (got <= 0)
      return false;
    k += (size_t)got;
  }
  return true;
}
static void header(unsigned char h[48], unsigned kind, bool response,
                   YDShardStatus status, size_t nlen, size_t clen, size_t size,
                   const unsigned char nonce[16]) {
  memset(h, 0, 48);
  memcpy(h, "YSR1", 4);
  h[4] = response ? 2 : 1;
  h[5] = (unsigned char)kind;
  put32(h + 8, (uint32_t)status);
  put32(h + 12, (uint32_t)nlen);
  put32(h + 16, (uint32_t)clen);
  put32(h + 20, (uint32_t)size);
  memcpy(h + 24, nonce, 16);
}
static bool valid_header(const unsigned char h[48], bool response) {
  if (memcmp(h, "YSR1", 4) || h[4] != (response ? 2 : 1) || !h[5] || h[6] ||
      h[7] || get32(h + 20) > YD_SHARD_RPC_BYTES)
    return false;
  for (size_t i = 40; i < 48; i++)
    if (h[i])
      return false;
  return response ? (get32(h + 8) <= YD_SHARD_CORRUPT && !get32(h + 12) &&
                     !get32(h + 16))
                  : (!get32(h + 8) && get32(h + 12) > 0 &&
                     get32(h + 12) <= 253 && get32(h + 16) > 0 &&
                     get32(h + 16) <= YD_SHARD_CREDENTIAL_BYTES);
}
static bool known(YDShardTransport *r, YDConnection *c, const char *peer) {
  for (size_t i = 0; i < r->count; i++)
    if (!strcmp(r->peers[i].name, peer))
      return yd_connection_peer_name(c, peer);
  return false;
}
bool yd_shard_rpc_serve(YDShardTransport *r, int fd, YDShardDispatch dispatch,
                        void *ctx) {
  if (!r || !dispatch)
    return false;
  uint64_t end = now() + r->timeout;
  YDConnection c = {0};
  bool ok = yd_connection_init(&c, fd, r->tls, (int)r->timeout);
  c.write_deadline = end;
  unsigned char h[48], nonce[16];
  char peer[254] = {0};
  size_t n = 0, clen = 0;
  unsigned char *body = NULL, *reply = NULL;
  char *credential = NULL;
  size_t rn = 0;
  bool held = false;
  ok = ok && receive(&c, h, 48, end) && valid_header(h, false);
  unsigned kind = ok ? h[5] : 0;
  if (ok) {
    n = get32(h + 20);
    clen = get32(h + 16);
    memcpy(nonce, h + 24, 16);
    ok = receive(&c, peer, get32(h + 12), end) &&
         !memchr(peer, 0, get32(h + 12)) && known(r, &c, peer);
  }
  if (ok) {
    held = reserve(r, n + clen + 1);
    ok = held;
  }
  if (ok) {
    credential = calloc(clen + 1, 1);
    body = n ? malloc(n) : NULL;
    ok = credential && (!n || body) && receive(&c, credential, clen, end) &&
         !memchr(credential, 0, clen) && (!n || receive(&c, body, n, end));
  }
  if (ok) {
    YDShardStatus status =
        now() < end ? dispatch(ctx, kind, credential, body, n, &reply, &rn)
                    : YD_SHARD_UNAVAILABLE;
    if (rn > YD_SHARD_RPC_BYTES || (!reply && rn)) {
      free(reply);
      reply = NULL;
      rn = 0;
      status = YD_SHARD_BUDGET_EXCEEDED;
    }
    header(h, kind, true, status, 0, 0, rn, nonce);
    ok = yd_connection_send(&c, h, 48) &&
         (!rn || yd_connection_send(&c, reply, rn));
  }
  if (credential) {
    volatile unsigned char *p = (volatile unsigned char *)credential;
    for (size_t i = 0; i < clen; i++)
      p[i] = 0;
  }
  free(credential);
  free(body);
  free(reply);
  if (held)
    atomic_fetch_sub(&r->memory, n + clen + 1);
  yd_connection_close(&c);
  return ok;
}
static int connect_peer(const Peer *p, uint64_t end) {
  int fd = socket(p->address.ss_family,
                  SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (fd < 0)
    return -1;
  int rc = connect(fd, (const struct sockaddr *)&p->address, p->length);
  if (rc && errno != EINPROGRESS) {
    close(fd);
    return -1;
  }
  while (rc) {
    uint64_t t = now();
    if (!t || t >= end) {
      close(fd);
      return -1;
    }
    struct pollfd f = {.fd = fd, .events = POLLOUT};
    rc = poll(&f, 1, (int)(end - t));
    if (rc < 0 && errno == EINTR) {
      rc = 1;
      continue;
    }
    if (rc <= 0) {
      close(fd);
      return -1;
    }
    int error = 0;
    socklen_t n = sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &n) || error) {
      close(fd);
      return -1;
    }
    break;
  }
  return fd;
}
YDShardStatus yd_shard_rpc_call(YDShardTransport *r, const char *group,
                                unsigned kind, const char *credential,
                                const unsigned char *body, size_t n,
                                unsigned char **out, size_t *size) {
  if (!out || !size)
    return YD_SHARD_INVALID_ARGUMENT;
  *out = NULL;
  *size = 0;
  size_t clen =
      credential ? strnlen(credential, YD_SHARD_CREDENTIAL_BYTES + 1) : 0;
  if (!r || !group || !kind || kind > 255 || !clen ||
      clen > YD_SHARD_CREDENTIAL_BYTES || n > YD_SHARD_RPC_BYTES ||
      (!body && n))
    return YD_SHARD_INVALID_ARGUMENT;
  uint64_t end = now() + r->timeout;
  unsigned char nonce[16];
  if (RAND_bytes(nonce, 16) != 1)
    return YD_SHARD_RESOURCE_FAILURE;
  for (size_t i = 0; i < r->count; i++) {
    Peer *p = r->peers + i;
    if (strcmp(p->group, group))
      continue;
    uint64_t t = now();
    if (!t || t >= end)
      break;
    /* Give each replica a bounded chance within the one operation deadline. */
    size_t remaining = 0;
    for (size_t j = i; j < r->count; j++)
      remaining += !strcmp(r->peers[j].group, group);
    uint64_t attempt = t + (end - t) / remaining;
    if (attempt <= t)
      continue;
    int fd = connect_peer(p, attempt);
    if (fd < 0)
      continue;
    YDConnection c = {0};
    t = now();
    bool ok = t && t < attempt &&
              yd_connection_shard_connect(&c, fd, r->tls, p->name,
                                          (int)(attempt - t));
    c.write_deadline = attempt;
    unsigned char h[48];
    header(h, kind, false, YD_SHARD_OK, strlen(r->name), clen, n, nonce);
    ok = ok && yd_connection_send(&c, h, 48) &&
         yd_connection_send(&c, r->name, strlen(r->name)) &&
         yd_connection_send(&c, credential, clen) &&
         (!n || yd_connection_send(&c, body, n)) &&
         receive(&c, h, 48, attempt) && valid_header(h, true) && h[5] == kind &&
         !memcmp(h + 24, nonce, 16);
    size_t rn = ok ? get32(h + 20) : 0;
    bool held = ok && reserve(r, rn);
    unsigned char *reply = held && rn ? malloc(rn) : NULL;
    ok = ok && held && (!rn || (reply && receive(&c, reply, rn, attempt)));
    YDShardStatus status =
        ok ? (YDShardStatus)get32(h + 8) : YD_SHARD_UNAVAILABLE;
    yd_connection_close(&c);
    close(fd);
    if (held)
      atomic_fetch_sub(&r->memory, rn);
    if (status == YD_SHARD_UNAVAILABLE) {
      free(reply);
      continue;
    }
    if (!ok) {
      free(reply);
      continue;
    }
    *out = reply;
    *size = rn;
    return status;
  }
  return YD_SHARD_UNAVAILABLE;
}
