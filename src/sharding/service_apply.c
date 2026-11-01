#define _POSIX_C_SOURCE 200809L
#include "service.h"
#include "service_wire.h"
int yd_shard_service_key(const void *key, size_t size) {
  int result = yd_shard_control_key(key, size);
  return result ? result : yd_shard_native_key(key, size);
}
bool yd_shard_service_validate(const void *key, size_t size,
                               const unsigned char *bytes, size_t length) {
  int control = yd_shard_control_key(key, size);
  if (control)
    return control == 1 &&
           yd_shard_control_validate_record(key, size, bytes, length);
  return yd_shard_native_key(key, size) == 1 &&
         yd_shard_native_validate_record(key, size, bytes, length);
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
YDDiskReply yd_shard_service_prepare(YDDisk *disk, const YDRaftWrite *w,
                                     YDDiskTxn **tx) {
  if (tx)
    *tx = NULL;
  if (!w || !w->method || strcmp(w->method, "YSHARD"))
    return (YDDiskReply){0};
  if (!disk || !tx || !w->target || w->size > YD_SHARD_RPC_BYTES)
    return failure(YD_SHARD_INVALID_ARGUMENT);
  if (!strcmp(w->target, "/internal/shard/control")) {
    /* The command's next state names its collection; stage against that
     * collection's own control record. */
    YDShardControl *next = w->size >= 36 && !memcmp(w->body, "YCC1", 4)
                               ? yd_shard_control_import(w->body + 36, w->size - 36)
                               : NULL;
    const YDShardPlacement *named = yd_shard_control_placement(next);
    YDShardControl *c =
        named ? yd_shard_control_open_collection(disk, yd_shard_placement_collection(named))
              : NULL;
    yd_shard_control_close(next);
    if (!named)
      return failure(YD_SHARD_INVALID_ARGUMENT);
    if (!c)
      return failure(YD_SHARD_CORRUPT);
    *tx = yd_disk_begin(disk, NULL, 0);
    YDShardStatus status =
        *tx ? yd_shard_control_stage(c, w->body, w->size, *tx)
            : YD_SHARD_UNAVAILABLE;
    yd_shard_control_close(c);
    if (status != YD_SHARD_OK) {
      if (*tx)
        yd_disk_abort(*tx);
      *tx = NULL;
      return failure(status);
    }
    return (YDDiskReply){.status = 200};
  }
  if (strcmp(w->target, "/internal/shard/native"))
    return failure(YD_SHARD_INVALID_ARGUMENT);
  Decoded d;
  if (!request_get(w->body, w->size, &d))
    return failure(YD_SHARD_INVALID_ARGUMENT);
  YDShardNative *native = yd_shard_native_open(disk, d.group, d.control);
  YDDiskView at = yd_disk_view(disk);
  YDShardResponse response = {0};
  YDShardStatus status =
      native ? yd_shard_native_prepare_at(native, &at, &d.q, &response, tx)
             : YD_SHARD_RESOURCE_FAILURE;
  unsigned char *out = NULL;
  size_t n = 0;
  if (status == YD_SHARD_OK && !response_put(&response, &out, &n))
    status = YD_SHARD_RESOURCE_FAILURE;
  yd_shard_page_free(&response.page);
  yd_shard_native_close(native);
  decoded_free(&d);
  if (status != YD_SHARD_OK) {
    if (*tx)
      yd_disk_abort(*tx);
    *tx = NULL;
    free(out);
    return failure(status);
  }
  return (YDDiskReply){.status = 200, .body = (char *)out, .length = n};
}
