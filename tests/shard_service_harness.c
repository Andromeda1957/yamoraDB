#define _POSIX_C_SOURCE 200809L
#include "../src/sharding/service.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* Focused service fixture. The production callback contract is exercised with
 * exact immutable native views and native prepared transactions. This fixture
 * deliberately supplies no consensus proof; multi-node Raft qualification is
 * performed separately against the actual daemon. */
struct YDRaftView {
  YDDisk *disk;
  YDDiskView value;
};
YDDisk *yd_raft_view_disk(const YDRaftView *v) { return v ? v->disk : NULL; }
YDDiskView yd_raft_view_value(const YDRaftView *v) {
  return v ? v->value : (YDDiskView){0};
}
void yd_raft_view_close(YDRaftView *v) { free(v); }
typedef struct {
  YDDisk *disk;
  YDShardService *service;
  pthread_mutex_t lock;
  atomic_uint reads, writes, auth;
  atomic_bool deny, unavailable;
} Node;
static YDRaftView *view(void *p, unsigned timeout) {
  (void)timeout;
  Node *n = p;
  atomic_fetch_add(&n->reads, 1);
  if (atomic_load(&n->unavailable))
    return NULL;
  YDRaftView *v = calloc(1, sizeof(*v));
  if (!v)
    return NULL;
  pthread_mutex_lock(&n->lock);
  v->disk = n->disk;
  v->value = yd_disk_view(n->disk);
  pthread_mutex_unlock(&n->lock);
  return v;
}
static YDDiskReply execute(void *p, const YDRaftWrite *w, unsigned timeout) {
  (void)timeout;
  Node *n = p;
  atomic_fetch_add(&n->writes, 1);
  pthread_mutex_lock(&n->lock);
  YDDiskTxn *tx = NULL;
  YDDiskReply reply = yd_shard_service_prepare(n->disk, w, &tx);
  if (reply.status == 200 && tx) {
    if (!yd_disk_commit(tx, NULL, 0)) {
      yd_disk_reply_free(&reply);
      reply = yd_disk_error_reply(503, "commit_failed");
    }
  } else if (tx)
    yd_disk_abort(tx);
  pthread_mutex_unlock(&n->lock);
  return reply;
}
static bool authorize(void *p, const char *credential, const char *collection,
                      bool write, bool admin) {
  Node *n = p;
  atomic_fetch_add(&n->auth, 1);
  /* writer: everything; reader: reads of every fixture collection;
   * orders-reader: reads of orders only (foreign lookup denial). */
  if (atomic_load(&n->deny) ||
      (strcmp(collection, "docs") && strcmp(collection, "people") &&
       strcmp(collection, "orders")))
    return false;
  if (!strcmp(credential, "Bearer writer"))
    return true;
  if (write || admin)
    return false;
  return !strcmp(credential, "Bearer reader") ||
         (!strcmp(credential, "Bearer orders-reader") &&
          !strcmp(collection, "orders"));
}
static const char *text(const YDValue *m, const char *key) {
  const YDValue *v = yd_get(m, key);
  return v && v->type == YD_STRING ? v->scalar : NULL;
}
int main(int argc, char **argv) {
  if (argc == 3 && !strcmp(argv[1], "--check-config")) {
    Node node = {0};
    YDShardServiceCallbacks cb = {execute, view, &node, authorize, &node};
    char error[256];
    YDShardService *service = yd_shard_service_load(argv[2], &cb, error, sizeof(error));
    if (!service)
      return 4;
    yd_shard_service_free(service);
    return 0;
  }
  if (argc != 5)
    return 2;
  Node nodes[3] = {0};
  char error[256], root[4096];
  for (size_t i = 0; i < 3; i++) {
    snprintf(root, sizeof(root), "%s/data%zu", argv[1], i);
    nodes[i].disk = yd_disk_open(root, true, 32768, error, sizeof(error));
    if (!nodes[i].disk || pthread_mutex_init(&nodes[i].lock, NULL))
      return 3;
    YDShardServiceCallbacks cb = {execute, view, nodes + i, authorize,
                                  nodes + i};
    nodes[i].service =
        yd_shard_service_load(argv[i + 2], &cb, error, sizeof(error));
    if (!nodes[i].service || !yd_shard_service_start(nodes[i].service)) {
      fprintf(stderr, "%s\n", error);
      return 4;
    }
  }
  puts("ready");
  fflush(stdout);
  char *line = NULL;
  size_t cap = 0;
  while (getline(&line, &cap, stdin) > 0) {
    YDValue *m = yd_parse_request((unsigned char *)line, strlen(line), NULL, 0);
    const char *action = text(m, "action");
    if (action && !strcmp(action, "stats")) {
      printf(
          "{\"reads\":[%u,%u,%u],\"writes\":[%u,%u,%u],\"auth\":[%u,%u,%u]}\n",
          atomic_load(&nodes[0].reads), atomic_load(&nodes[1].reads),
          atomic_load(&nodes[2].reads), atomic_load(&nodes[0].writes),
          atomic_load(&nodes[1].writes), atomic_load(&nodes[2].writes),
          atomic_load(&nodes[0].auth), atomic_load(&nodes[1].auth),
          atomic_load(&nodes[2].auth));
    } else if (action && (!strcmp(action, "deny") ||
                          !strcmp(action, "unavailable"))) {
      const YDValue *node = yd_get(m, "node"), *value = yd_get(m, "value");
      if (node && node->type == YD_INT && node->number >= 0 &&
          node->number < 3 && value && value->type == YD_BOOL)
        atomic_store(!strcmp(action, "deny")
                         ? &nodes[(size_t)node->number].deny
                         : &nodes[(size_t)node->number].unavailable,
                     value->boolean);
      puts("{}");
    } else {
      const char *body = text(m, "body");
      YDDiskReply reply = yd_shard_service_request(
          nodes[0].service, text(m, "credential"), text(m, "method"),
          text(m, "target"), (const unsigned char *)body,
          body ? strlen(body) : 0);
      char *copy = malloc(reply.length + 1);
      if (!copy)
        return 5;
      if (reply.length)
        memcpy(copy, reply.body, reply.length);
      copy[reply.length] = 0;
      YDValue value = {.type = YD_STRING, .scalar = copy};
      size_t size;
      char *json = yd_json_sized(&value, &size, YD_LARGE_REQUEST_LIMIT);
      if (!json)
        return 6;
      printf("{\"status\":%d,\"body\":%s}\n", reply.status, json);
      free(json);
      free(copy);
      yd_disk_reply_free(&reply);
    }
    yd_free(m);
    fflush(stdout);
  }
  free(line);
  for (size_t i = 0; i < 3; i++)
    yd_shard_service_free(nodes[i].service);
  for (size_t i = 0; i < 3; i++) {
    yd_disk_close(nodes[i].disk);
    pthread_mutex_destroy(&nodes[i].lock);
  }
  return 0;
}
