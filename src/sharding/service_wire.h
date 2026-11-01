#ifndef YAMORA_SHARD_SERVICE_WIRE_H
#define YAMORA_SHARD_SERVICE_WIRE_H
#include "../transport/shard_rpc.h"
#include "runtime.h"
#include <stdlib.h>
#include <string.h>
typedef struct {
  unsigned char *p;
  size_t n, cap;
  bool bad;
} Buffer;
typedef struct {
  const unsigned char *p;
  size_t n, k;
  bool bad;
} Reader;
static inline void put(Buffer *b, const void *p, size_t n) {
  if (b->bad)
    return;
  if (n > YD_SHARD_RPC_BYTES - b->n || (!p && n)) {
    b->bad = true;
    return;
  }
  if (b->n + n > b->cap) {
    size_t cap = b->n + n;
    unsigned char *q = realloc(b->p, cap);
    if (!q) {
      b->bad = true;
      return;
    }
    b->p = q;
    b->cap = cap;
  }
  if (n)
    memcpy(b->p + b->n, p, n);
  b->n += n;
}
static inline void num(Buffer *b, uint64_t n) {
  unsigned char p[8];
  for (unsigned i = 0; i < 8; i++)
    p[i] = (unsigned char)(n >> (56 - 8 * i));
  put(b, p, 8);
}
static inline void blob(Buffer *b, const void *p, size_t n) {
  num(b, n);
  put(b, p, n);
}
static inline void str(Buffer *b, const char *s) {
  blob(b, s, s ? strlen(s) : 0);
}
static inline uint64_t number(Reader *r) {
  if (r->bad || r->n - r->k < 8) {
    r->bad = true;
    return 0;
  }
  uint64_t n = 0;
  for (unsigned i = 0; i < 8; i++)
    n = n << 8 | r->p[r->k++];
  return n;
}
static inline const unsigned char *bytes(Reader *r, size_t *n, size_t max) {
  uint64_t z = number(r);
  *n = 0;
  if (r->bad || z > max || z > r->n - r->k) {
    r->bad = true;
    return NULL;
  }
  const unsigned char *p = r->p + r->k;
  r->k += (size_t)z;
  *n = (size_t)z;
  return p;
}
static inline bool text(Reader *r, char *out, size_t cap) {
  size_t n;
  const unsigned char *p = bytes(r, &n, cap - 1);
  if (r->bad || memchr(p, 0, n)) {
    r->bad = true;
    return false;
  }
  memcpy(out, p, n);
  out[n] = 0;
  return true;
}
static inline bool done(const Reader *r) { return !r->bad && r->k == r->n; }
static inline bool finish(Buffer *b, unsigned char **out, size_t *n) {
  if (b->bad) {
    free(b->p);
    return false;
  }
  *out = b->p;
  *n = b->n;
  return true;
}
static inline bool page_put(Buffer *b, const YDShardPage *p) {
  num(b, p ? p->count : 0);
  num(b, p && p->end);
  if (p) {
    if (p->count > YD_SHARD_PAGE_ROWS || p->bytes > YD_SHARD_PAGE_BYTES ||
        (!p->rows && p->count)) {
      b->bad = true;
      return false;
    }
    for (size_t i = 0; i < p->count; i++) {
      str(b, p->rows[i].id);
      blob(b, p->rows[i].source, p->rows[i].length);
    }
  }
  return !b->bad;
}
static inline bool page_get(Reader *r, YDShardPage *p) {
  memset(p, 0, sizeof(*p));
  uint64_t count = number(r), end = number(r);
  if (r->bad || count > YD_SHARD_PAGE_ROWS || end > 1) {
    r->bad = true;
    return false;
  }
  p->end = end != 0;
  p->rows = count ? calloc((size_t)count, sizeof(*p->rows)) : NULL;
  if (count && !p->rows) {
    r->bad = true;
    return false;
  }
  for (size_t i = 0; i < count; i++) {
    p->count = i + 1;
    size_t n;
    const unsigned char *source;
    if (!text(r, p->rows[i].id, sizeof(p->rows[i].id)) || !p->rows[i].id[0])
      goto bad;
    /* Documents are checked against YD_DOCUMENT_LIMIT where they are used;
     * a change-log row is a document plus its record header. */
    source = bytes(r, &n, YD_SHARD_ROW_LIMIT);
    if (r->bad || !n || n > YD_SHARD_PAGE_BYTES - p->bytes)
      goto bad;
    p->rows[i].source = malloc(n);
    if (!p->rows[i].source)
      goto bad;
    memcpy(p->rows[i].source, source, n);
    p->rows[i].length = n;
    p->bytes += n;
  }
  return true;
bad:
  r->bad = true;
  yd_shard_page_free(p);
  return false;
}
static inline bool response_put(const YDShardResponse *response,
                                unsigned char **out, size_t *n) {
  Buffer b = {0};
  str(&b, response->snapshot);
  page_put(&b, &response->page);
  return finish(&b, out, n);
}
static inline bool response_get(const unsigned char *p, size_t n,
                                YDShardResponse *out) {
  Reader r = {.p = p, .n = n};
  memset(out, 0, sizeof(*out));
  if (!text(&r, out->snapshot, sizeof(out->snapshot)) ||
      !page_get(&r, &out->page) || !done(&r)) {
    yd_shard_page_free(&out->page);
    memset(out, 0, sizeof(*out));
    return false;
  }
  return true;
}
typedef struct {
  YDShardControl *control;
  YDShardRequest q;
  YDShardKey key;
  YDShardPage page;
  char id[256], after[256], snapshot[65], mutation[129], group[64];
} Decoded;
static inline void decoded_free(Decoded *d) {
  yd_shard_page_free(&d->page);
  yd_shard_control_close(d->control);
  memset(d, 0, sizeof(*d));
}
static inline bool request_put(YDShardControl *c, const char *group,
                               const YDShardRequest *q, unsigned char **out,
                               size_t *n) {
  Buffer b = {0};
  size_t cn;
  unsigned char *state = yd_shard_control_export(c, &cn);
  if (!state)
    return false;
  put(&b, "YSN1", 4);
  blob(&b, state, cn);
  free(state);
  str(&b, group);
  num(&b, q->operation);
  num(&b, q->range.first);
  num(&b, q->range.last);
  str(&b, q->range.shard);
  str(&b, q->range.group);
  str(&b, q->id);
  str(&b, q->after);
  str(&b, q->snapshot);
  str(&b, q->mutation_id);
  blob(&b, q->key ? q->key->bytes : NULL, q->key ? q->key->length : 0);
  blob(&b, q->source, q->length);
  page_put(&b, q->page);
  num(&b, q->max_rows);
  num(&b, q->max_bytes);
  return finish(&b, out, n);
}
static inline bool request_get(const unsigned char *p, size_t n, Decoded *d) {
  memset(d, 0, sizeof(*d));
  if (!p || n < 4 || memcmp(p, "YSN1", 4))
    return false;
  Reader r = {.p = p, .n = n, .k = 4};
  size_t size;
  const unsigned char *state = bytes(&r, &size, YD_SHARD_COMMAND_LIMIT);
  d->control = r.bad ? NULL : yd_shard_control_import(state, size);
  if (!d->control || !yd_shard_control_placement(d->control))
    goto bad;
  if (!text(&r, d->group, sizeof(d->group)))
    goto bad;
  uint64_t op = number(&r);
  if (op > YD_SHARD_RPC_LOG_STAGE)
    goto bad;
  d->q.operation = (YDShardRPC)op;
  d->q.range.first = number(&r);
  d->q.range.last = number(&r);
  if (!text(&r, d->q.range.shard, 64) || !text(&r, d->q.range.group, 64) ||
      !text(&r, d->id, 256) || !text(&r, d->after, 256) ||
      !text(&r, d->snapshot, 65) || !text(&r, d->mutation, 129))
    goto bad;
  const unsigned char *key = bytes(&r, &size, YD_SHARD_KEY_BYTES);
  if (r.bad)
    goto bad;
  if (size) {
    if (yd_shard_key_decode(key, size, &d->key) != YD_SHARD_OK)
      goto bad;
    d->q.key = &d->key;
  }
  d->q.source = bytes(&r, &d->q.length, YD_DOCUMENT_LIMIT);
  if (!d->q.length)
    d->q.source = NULL;
  if (r.bad || !page_get(&r, &d->page))
    goto bad;
  uint64_t rows = number(&r), limit = number(&r);
  if (rows > YD_SHARD_PAGE_ROWS || limit > YD_SHARD_PAGE_BYTES || !done(&r))
    goto bad;
  d->q.max_rows = (size_t)rows;
  d->q.max_bytes = (size_t)limit;
  d->q.id = d->id;
  d->q.after = d->after;
  d->q.snapshot = d->snapshot;
  d->q.mutation_id = d->mutation;
  d->q.page = &d->page;
  d->q.placement = yd_shard_control_placement(d->control);
  d->q.migration = yd_shard_control_migration(d->control);
  return true;
bad:
  decoded_free(d);
  return false;
}
#endif
