#ifndef YAMORA_SHARD_SERVICE_H
#define YAMORA_SHARD_SERVICE_H
#include "../consensus/cluster.h"
#include "../transport/shard_rpc.h"
#include "runtime.h"
typedef struct YDShardService YDShardService;
typedef struct {
  YDDiskReply (*execute)(void *, const YDRaftWrite *, unsigned timeout_ms);
  YDRaftView *(*view)(void *, unsigned timeout_ms);
  void *context;
  /* Credential is the original bearer authorization value, independently
   * authenticated at EVERY destination before state/receipt access. Empty,
   * unknown and certificate-only public identities must fail closed. */
  bool (*authorize)(void *, const char *credential, const char *collection,
                    bool write, bool admin);
  void *auth_context;
} YDShardServiceCallbacks;
typedef struct {
  YDTLS *tls;
  const char *local_name, *local_group, *control_group;
  const YDShardEndpoint *peers;
  size_t peer_count;
  unsigned timeout_ms;
  YDShardServiceCallbacks callbacks;
} YDShardServiceConfig;
/* Config/TLS borrowed until free; callbacks must outlive service. */
YDShardService *yd_shard_service_new(const YDShardServiceConfig *);
/* Strict private operator YAML; owns model, TLS and a private numeric listener.
 * Start only after callbacks are live. Free joins listener before releasing
 * TLS. */
YDShardService *yd_shard_service_load(const char *path,
                                      const YDShardServiceCallbacks *,
                                      char *error, size_t);
bool yd_shard_service_start(YDShardService *);
void yd_shard_service_free(YDShardService *);
bool yd_shard_service_serve(YDShardService *, int fd);
/* Native daemon public surface, original bearer value only. No credential is
 * stored in commands, responses or logs. Parent rejects certificate-only input.
 */
YDDiskReply yd_shard_service_request(YDShardService *, const char *credential,
                                     const char *method, const char *target,
                                     const unsigned char *body, size_t);
/* Application dispatch for internal method YSHARD. Unrelated => status 0.
 * Deterministic prepare only, no network/commit; result owns transaction.
 * Parent combines effects, original receipt and applied checkpoint atomically.
 */
YDDiskReply yd_shard_service_prepare(YDDisk *, const YDRaftWrite *,
                                     YDDiskTxn **);
/* Snapshot admission: 1 recognized, 0 unrelated, -1 malformed reserved key. */
int yd_shard_service_key(const void *, size_t);
bool yd_shard_service_validate(const void *, size_t, const unsigned char *,
                               size_t);
#endif
