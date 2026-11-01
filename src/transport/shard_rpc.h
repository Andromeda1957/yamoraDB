#ifndef YAMORA_SHARD_RPC_H
#define YAMORA_SHARD_RPC_H
#include "../sharding/routing.h"
#include "tls.h"
#define YD_SHARD_RPC_PEERS 64U
#define YD_SHARD_RPC_BYTES (2U * 1024U * 1024U)
#define YD_SHARD_CREDENTIAL_BYTES 4096U
typedef struct {
  const char *group, *name, *address;
  unsigned port;
} YDShardEndpoint;
typedef struct YDShardTransport YDShardTransport;
/* Registry is operator supplied, numeric RFC1918/loopback/ULA only. Names are
 * certificate DNS identities. No DNS resolution, redirects or client URLs. */
YDShardTransport *yd_shard_rpc_new(YDTLS *, const char *local_name,
                                   const YDShardEndpoint *, size_t count,
                                   unsigned timeout_ms);
void yd_shard_rpc_free(YDShardTransport *);
typedef YDShardStatus (*YDShardDispatch)(void *, unsigned kind,
                                         const char *credential,
                                         const unsigned char *, size_t,
                                         unsigned char **reply,
                                         size_t *reply_size);
/* One connection/request, bounded allocations and absolute transport deadline.
 * Both sides require registry certificate identity and dedicated shard ALPN.
 * The dispatcher must independently authorize the original credential. */
bool yd_shard_rpc_serve(YDShardTransport *, int fd, YDShardDispatch, void *);
YDShardStatus yd_shard_rpc_call(YDShardTransport *, const char *group,
                                unsigned kind, const char *credential,
                                const unsigned char *, size_t, unsigned char **,
                                size_t *);
bool yd_shard_rpc_group(const YDShardTransport *, const char *group);
#endif
