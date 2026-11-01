import { isUtf8 } from 'node:buffer';
import { configuration, request, YamoraError } from './lib/transport.js';
import { clusterTransport } from './lib/cluster.js';
import { encode, decode } from './lib/codec.js';
import { IDENTIFIER, REVISION, CHANGE_TOKEN, MAX_DOCUMENT_BYTES, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
  requireValue, identifier, revision, optionalRevision, object, keys, integer, changeToken, text, sourceBytes } from './lib/validation.js';

export { YamoraError, MAX_DOCUMENT_BYTES, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES };
export { UncertainWriteError } from './lib/cluster.js';
const CLUSTER = Symbol('cluster transport');

function check(condition, write = false) {
  if (!condition) throw new YamoraError('invalid response metadata or result', { uncertain: write });
}
function responseRevision(headers, expected) {
  const actual = headers['x-yamldb-revision'];
  check(typeof actual === 'string' && REVISION.test(actual) && (expected === undefined || expected === actual));
  return actual;
}
function mutationReceipt(result, collection, document) {
  check(result.status === 'stored' && typeof result.etag === 'string' && REVISION.test(result.etag) &&
    typeof result.revision === 'string' && REVISION.test(result.revision) && result.collection === collection && result.document === document, true);
}
function media(headers, expected) {
  return expected.includes((headers['content-type'] ?? '').split(';')[0].trim().toLowerCase());
}
function path(collection, document) {
  return `/v1/collections/${identifier(collection)}/documents/${identifier(document)}`;
}
function conditions(options, allowed, create = false) {
  keys(options, allowed);
  const headers = {};
  if (options.etag !== undefined) headers['If-Match'] = `"${revision(options.etag)}"`;
  if (options.createOnly !== undefined) requireValue(create && typeof options.createOnly === 'boolean', 'invalid create condition');
  requireValue(!(options.createOnly && options.etag !== undefined), 'conflicting write conditions');
  if (options.createOnly) headers['If-None-Match'] = '*';
  return headers;
}
function revisionHeaders(options) {
  optionalRevision(options.revision);
  return options.revision === undefined ? {} : { 'If-Match': `"${options.revision}"` };
}
function names(values, maximum, after = '') {
  return Array.isArray(values) && values.length <= maximum && values.every((id, i) =>
    typeof id === 'string' && IDENTIFIER.test(id) && id > (i ? values[i - 1] : after));
}
function cursor(result, rows) {
  check(Object.hasOwn(result, 'next_after') && (result.next_after === null ||
    (rows.length > 0 && result.next_after === rows.at(-1).id)));
}
function nonnegative(value) {
  return (Number.isSafeInteger(value) && value >= 0) || (typeof value === 'bigint' && value >= 0n && value < (1n << 64n));
}
function validateIndexes(indexes) {
  requireValue(Array.isArray(indexes) && indexes.length <= 64, 'invalid index catalog');
  const seen = new Set();
  for (const item of indexes) {
    keys(item, ['collection', 'name', 'fields', 'unique', 'type']);
    const name = `${identifier(item.collection)}/${identifier(item.name)}`;
    requireValue(!seen.has(name), 'duplicate index');
    seen.add(name);
    requireValue(item.unique === undefined || typeof item.unique === 'boolean', 'invalid unique option');
    requireValue(item.type === undefined || item.type === 'text', 'invalid index type');
    requireValue(!(item.type === 'text' && item.unique), 'text indexes cannot be unique');
    requireValue(Array.isArray(item.fields) && item.fields.length >= 1 && item.fields.length <= 8 &&
      new Set(item.fields).size === item.fields.length, 'invalid index fields');
    for (const field of item.fields) {
      text(field);
      requireValue(field.length > 0 && (field !== '$source' || (item.type === 'text' && item.fields.length === 1)), 'invalid index field');
    }
  }
}
function querySpec(spec, search = false) {
  keys(spec, search ? ['index', 'text', 'mode', 'filter', 'limit', 'after', 'revision'] :
    ['filter', 'sort', 'projection', 'limit', 'after', 'revision', 'count_only', 'explain', 'include_count']);
  optionalRevision(spec.revision);
  if (spec.limit !== undefined) integer(spec.limit, 1, 1000);
  if (spec.after !== undefined) {
    identifier(spec.after);
    requireValue(spec.revision !== undefined && !spec.count_only, 'cursor requires revision and document results');
  }
  if (spec.filter !== undefined) requireValue(object(spec.filter), 'filter must be an object');
  if (!search) {
    for (const key of ['count_only', 'explain', 'include_count'])
      if (spec[key] !== undefined) requireValue(typeof spec[key] === 'boolean', 'invalid query flag');
    if (spec.sort !== undefined) {
      requireValue(object(spec.sort) && Object.keys(spec.sort).length <= 8, 'invalid sort');
      for (const [field, order] of Object.entries(spec.sort)) requireValue(field.length > 0 && ['asc', 'desc', 'ascending', 'descending', 1, -1].includes(order), 'invalid sort field');
    }
    if (spec.projection !== undefined) requireValue(Array.isArray(spec.projection) && spec.projection.length <= 64 &&
      new Set(spec.projection).size === spec.projection.length && spec.projection.every(field => typeof field === 'string' && field.length > 0), 'invalid projection');
  }
}

/** Single-endpoint HTTP/1.1 driver. Every call owns a fresh connection. */
export class Client {
  #config;
  #cluster;
  constructor(options = {}, mode) {
    if (mode === CLUSTER) { this.#cluster = clusterTransport(options); this.#config = this.#cluster.config; }
    else this.#config = configuration(options);
  }

  async #send(method, endpoint, body, headers, write, options, statuses = [200], maximum = this.#config.maxResponseBytes, validate = response => response) {
    if (this.#cluster) return this.#cluster.send(method, endpoint, body, headers, write, options, statuses, maximum, validate);
    return validate(await request(this.#config, method, endpoint, body, headers, write, options, statuses, maximum));
  }

  async #json(method, endpoint, value, options, { write = false, headers = {}, statuses = [200], expectedRevision, matchBodyRevision = true, validate = () => {} } = {}) {
    const body = value === undefined ? undefined : encode(value, this.#config.maxRequestBytes);
    return this.#send(method, endpoint, body,
      { ...(body ? { 'Content-Type': 'application/json' } : {}), ...headers }, write, options, statuses, this.#config.maxResponseBytes, response => {
        try {
          check(media(response.headers, ['application/json']));
          const actual = responseRevision(response.headers, expectedRevision);
          const result = decode(response.body);
          if (matchBodyRevision && Object.hasOwn(result, 'revision')) check(result.revision === actual);
          validate(result);
          return { result, revision: actual, headers: response.headers };
        } catch {
          throw new YamoraError('invalid JSON response or revision', { uncertain: write });
        }
      });
  }

  async health(options = {}) { keys(options, ['signal']); return (await this.#json('GET', '/healthz', undefined, options)).result; }
  async ready(options = {}) { keys(options, ['signal']); return (await this.#json('GET', '/readyz', undefined, options)).result; }
  /** Advisory source preflight before application-owned replica staging. */
  async requireReplicationSource(options = {}) {
    const ready = await this.ready(options);
    if (Object.hasOwn(ready, 'replication_policy_free')) {
      check(typeof ready.replication_policy_free === 'boolean');
      if (!ready.replication_policy_free)
        throw new YamoraError('schema_policy_replication_unsupported', { code: 'SCHEMA_POLICY_REPLICATION_UNSUPPORTED', status: 409 });
    }
    return ready;
  }
  async stats(options = {}) { keys(options, ['signal']); return (await this.#json('GET', '/v1/stats', undefined, options)).result; }
  async metrics(options = {}) {
    keys(options, ['signal']);
    const response = await this.#send('GET', '/metrics', undefined, {}, false, options);
    responseRevision(response.headers);
    check(media(response.headers, ['text/plain']) && isUtf8(response.body));
    return response.body.toString('utf8');
  }
  async collections(options = {}) {
    keys(options, ['signal', 'revision']); optionalRevision(options.revision);
    const response = await this.#json('GET', '/v1/collections', undefined, options, { expectedRevision: options.revision });
    check(names(response.result.collections, 65536));
    return { collections: response.result.collections, revision: response.revision };
  }
  async documentPage(collection, options = {}) {
    identifier(collection); keys(options, ['signal', 'revision', 'after', 'limit']); optionalRevision(options.revision);
    const limit = options.limit ?? 1000; integer(limit, 1, 1000);
    if (options.after !== undefined) { identifier(options.after); requireValue(options.revision !== undefined, 'cursor requires revision'); }
    const endpoint = `/v1/collections/${collection}/documents?limit=${limit}${options.after === undefined ? '' : `&after=${options.after}`}`;
    const { result, revision: actual } = await this.#json('GET', endpoint, undefined, options, { expectedRevision: options.revision });
    check(result.collection === collection && names(result.documents, limit, options.after ?? ''));
    cursor(result, result.documents.map(id => ({ id })));
    return { ...result, revision: actual };
  }
  async *documents(collection, options = {}) {
    keys(options, ['signal', 'revision', 'limit']);
    const pinned = { ...options };
    do {
      const page = await this.documentPage(collection, pinned);
      pinned.revision = page.revision;
      for (const document of page.documents) yield document;
      if (page.next_after === null) return;
      pinned.after = page.next_after;
    } while (true);
  }
  async get(collection, document, options = {}) {
    const endpoint = path(collection, document);
    keys(options, ['signal', 'revision']); optionalRevision(options.revision);
    const response = await this.#send('GET', endpoint, undefined, {}, false, options, [200],
      Math.min(this.#config.maxDocumentBytes, this.#config.maxResponseBytes));
    const actual = responseRevision(response.headers, options.revision);
    const etag = response.headers.etag;
    check(media(response.headers, ['application/yaml', 'text/yaml']) && typeof etag === 'string' && /^"[0-9a-f]{16}"$/.test(etag));
    return { source: response.body, etag: etag.slice(1, -1), revision: actual };
  }
  async put(collection, document, source, options = {}) {
    const endpoint = path(collection, document);
    const headers = conditions(options, ['signal', 'etag', 'createOnly', 'requestId'], true);
    const body = sourceBytes(source, this.#config.maxDocumentBytes);
    return this.#send('PUT', endpoint, body, { ...headers, 'Content-Type': 'application/yaml' }, true, options, [200, 201], this.#config.maxResponseBytes, response => {
      let result;
      try {
        check(media(response.headers, ['application/json']));
        result = decode(response.body);
        responseRevision(response.headers, result.revision);
      } catch { throw new YamoraError('invalid mutation receipt', { uncertain: true }); }
      mutationReceipt(result, collection, document);
      return result;
    });
  }
  async patch(collection, document, operators, options = {}) {
    const endpoint = path(collection, document);
    const headers = conditions(options, ['signal', 'etag', 'requestId']);
    requireValue(object(operators) && Object.keys(operators).length > 0, 'patch requires operators');
    const { result } = await this.#json('PATCH', endpoint, operators, options, { write: true, headers,
      validate: result => mutationReceipt(result, collection, document) });
    return result;
  }
  async delete(collection, document, options = {}) {
    const endpoint = path(collection, document);
    const headers = conditions(options, ['signal', 'etag', 'requestId']);
    return this.#send('DELETE', endpoint, undefined, headers, true, options, [204], 0, response => {
      try { return { revision: responseRevision(response.headers) }; }
      catch { throw new YamoraError('invalid delete receipt', { uncertain: true }); }
    });
  }
  async query(collection, spec = {}, options = {}) {
    identifier(collection); keys(options, ['signal']); querySpec(spec);
    const { result } = await this.#json('POST', `/v1/query/${collection}`, spec, options, { expectedRevision: spec.revision });
    check(Array.isArray(result.documents) && result.documents.length <= (spec.limit ?? 100) && REVISION.test(result.revision));
    check(result.documents.every(row => object(row) && typeof row.id === 'string' && IDENTIFIER.test(row.id) && Object.hasOwn(row, 'value')));
    cursor(result, result.documents);
    check(Object.hasOwn(result, 'matched') && (result.matched === null ? spec.include_count === false && !spec.count_only : nonnegative(result.matched) && result.matched >= result.documents.length));
    if (spec.count_only) check(result.documents.length === 0 && result.next_after === null);
    if (spec.explain) check(object(result.explain));
    return result;
  }
  async count(collection, filter = {}, options = {}) {
    keys(options, ['signal', 'revision']); optionalRevision(options.revision);
    const { signal, revision: pinned } = options;
    return (await this.query(collection, { filter, count_only: true, ...(pinned === undefined ? {} : { revision: pinned }) }, { signal })).matched;
  }
  async aggregate(collection, pipeline, options = {}) {
    identifier(collection); keys(options, ['signal', 'revision']); optionalRevision(options.revision);
    requireValue(Array.isArray(pipeline) && pipeline.length >= 1 && pipeline.length <= 32, 'pipeline requires 1..32 stages');
    const { result } = await this.#json('POST', `/v1/aggregate/${collection}`, { pipeline, ...(options.revision === undefined ? {} : { revision: options.revision }) }, options,
      { expectedRevision: options.revision });
    check(Array.isArray(result.documents) && result.documents.length <= 65536 && result.documents.every(object) && nonnegative(result.documents_examined) && REVISION.test(result.revision));
    return result;
  }
  async search(collection, spec, options = {}) {
    identifier(collection); keys(options, ['signal']); querySpec(spec, true); identifier(spec.index); text(spec.text);
    requireValue(Buffer.byteLength(spec.text) > 0 && Buffer.byteLength(spec.text) <= 8192 && (spec.mode === undefined || ['all', 'any'].includes(spec.mode)), 'invalid search');
    const { result } = await this.#json('POST', `/v1/search/${collection}`, spec, options, { expectedRevision: spec.revision });
    check(Array.isArray(result.documents) && result.documents.length <= (spec.limit ?? 100) && REVISION.test(result.revision));
    let previous = spec.after ?? '';
    for (const row of result.documents) {
      check(object(row) && typeof row.id === 'string' && IDENTIFIER.test(row.id) && row.id > previous && Object.hasOwn(row, 'value') && Number.isInteger(row.score) && row.score >= 1 && row.score <= 32);
      previous = row.id;
    }
    cursor(result, result.documents);
    check(nonnegative(result.documents_examined) && result.documents_examined >= result.documents.length && nonnegative(result.index_entries_examined) && result.index_entries_examined >= result.documents_examined);
    return result;
  }
  async indexes(options = {}) {
    keys(options, ['signal']);
    const { result, revision: actual } = await this.#json('GET', '/v1/indexes', undefined, options);
    try { validateIndexes(result.indexes); } catch { check(false); }
    return { ...result, revision: actual };
  }
  async setIndexes(indexes, options = {}) {
    keys(options, ['signal', 'revision', 'requestId']); validateIndexes(indexes);
    const { result } = await this.#json('PUT', '/v1/indexes', { indexes }, options, { write: true, headers: revisionHeaders(options),
      validate: result => check(result.status === 'committed' && result.operations === 1 && REVISION.test(result.revision), true) });
    return result;
  }
  async createIndex(index, options = {}) {
    keys(options, ['signal']); validateIndexes([index]);
    const action = async () => {
      const catalog = await this.indexes(options);
      requireValue(!catalog.indexes.some(item => item.collection === index.collection && item.name === index.name), 'index already exists');
      return this.setIndexes([...catalog.indexes, index], { ...options, revision: catalog.revision });
    };
    return this.#cluster ? this.#cluster.withBudget(action) : action();
  }
  async dropIndex(collection, name, options = {}) {
    identifier(collection); identifier(name); keys(options, ['signal']);
    const action = async () => {
      const catalog = await this.indexes(options);
      const indexes = catalog.indexes.filter(item => item.collection !== collection || item.name !== name);
      requireValue(indexes.length < catalog.indexes.length, 'index does not exist');
      return this.setIndexes(indexes, { ...options, revision: catalog.revision });
    };
    return this.#cluster ? this.#cluster.withBudget(action) : action();
  }
  async #indexBuild(method, endpoint, value, options, id) {
    const { result } = await this.#json(method, endpoint, value, options, { write: method !== 'GET',
      headers: method === 'POST' ? revisionHeaders(options) : {}, statuses: [method === 'GET' ? 200 : 202], matchBodyRevision: false });
    const terminal = ['succeeded', 'failed', 'cancelled'].includes(result.status);
    check(typeof result.id === 'string' && (/^[0-9a-f]{32}$/.test(result.id) || (result.id === '' && result.status === 'idle')) &&
      (id === undefined || id === result.id) && ['idle', 'running', 'succeeded', 'failed', 'cancelled'].includes(result.status) &&
      ['idle', 'scanning', 'catching_up', 'publishing', 'done'].includes(result.phase) &&
      ['', 'cancelled', 'deadline_exceeded', 'unique_constraint', 'history_unavailable', 'build_failed', 'worker_unavailable', 'publication_failed'].includes(result.error) &&
      nonnegative(result.documents_scanned) && nonnegative(result.transactions_replayed) && typeof result.cancel_requested === 'boolean' &&
      (result.status === 'succeeded' ? REVISION.test(result.revision) && result.error === '' : result.revision === '') &&
      (!terminal || result.phase === 'done') && (result.status !== 'running' || (result.phase !== 'idle' && result.phase !== 'done')), method !== 'GET');
    return result;
  }
  async startIndexBuild(indexes, options = {}) {
    keys(options, ['signal', 'revision']); validateIndexes(indexes);
    return this.#indexBuild('POST', '/v1/index-builds', { indexes }, options);
  }
  async indexBuild(id, options = {}) {
    keys(options, ['signal']);
    if (id !== undefined) requireValue(typeof id === 'string' && /^[0-9a-f]{32}$/.test(id), 'invalid index build ID');
    return this.#indexBuild('GET', `/v1/index-builds${id === undefined ? '' : `/${id}`}`, undefined, options, id);
  }
  async cancelIndexBuild(id, options = {}) {
    keys(options, ['signal']); requireValue(typeof id === 'string' && /^[0-9a-f]{32}$/.test(id), 'invalid index build ID');
    return this.#indexBuild('DELETE', `/v1/index-builds/${id}`, undefined, options, id);
  }
  async transaction(operations, options = {}) {
    keys(options, ['signal', 'revision', 'requestId']); optionalRevision(options.revision);
    requireValue(Array.isArray(operations) && operations.length >= 1 && operations.length <= 128, 'transaction requires 1..128 operations');
    const seen = new Set();
    const prepared = operations.map(op => {
      keys(op, ['collection', 'document', 'put', 'patch', 'delete', 'etag', 'create_only']);
      const target = path(op.collection, op.document);
      requireValue(!seen.has(target), 'duplicate transaction target'); seen.add(target);
      requireValue(['put', 'patch', 'delete'].filter(key => Object.hasOwn(op, key)).length === 1, 'operation requires exactly one mutation');
      const item = { ...op };
      if (Object.hasOwn(op, 'put')) item.put = sourceBytes(op.put, this.#config.maxDocumentBytes).toString('utf8');
      if (Object.hasOwn(op, 'patch')) requireValue(object(op.patch) && Object.keys(op.patch).length > 0, 'invalid patch');
      if (Object.hasOwn(op, 'delete')) requireValue(op.delete === true, 'delete must be true');
      if (op.etag !== undefined) revision(op.etag);
      if (op.create_only !== undefined) requireValue(typeof op.create_only === 'boolean' && Object.hasOwn(op, 'put'), 'create_only requires put');
      requireValue(!(op.create_only && op.etag !== undefined), 'conflicting write conditions');
      return item;
    });
    const operationCount = prepared.length;
    const { result } = await this.#json('POST', '/v1/transactions', { operations: prepared,
      ...(options.revision === undefined ? {} : { revision: options.revision }) }, options, { write: true,
      validate: result => check(result.status === 'committed' && result.operations === operationCount && REVISION.test(result.revision), true) });
    return result;
  }
  async changes(options = {}) {
    keys(options, ['signal', 'after', 'limit']);
    const limit = options.limit ?? 100; integer(limit, 1, 100);
    if (options.after !== undefined) changeToken(options.after);
    const endpoint = options.after === undefined ? '/v1/changes' : `/v1/changes?after=${options.after}&limit=${limit}`;
    const { result } = await this.#json('GET', endpoint, undefined, options);
    for (const key of ['next_after', 'oldest_after', 'checkpoint']) check(typeof result[key] === 'string' && CHANGE_TOKEN.test(result[key]));
    const identity = result.checkpoint.slice(0, 36);
    check(REVISION.test(result.revision) && result.next_after.startsWith(identity) && result.oldest_after.startsWith(identity) &&
      result.oldest_after <= result.next_after && result.next_after <= result.checkpoint && typeof result.has_more === 'boolean' &&
      result.has_more === (result.next_after < result.checkpoint) && Array.isArray(result.transactions) && result.transactions.length <= limit);
    if (options.after !== undefined) check(options.after.startsWith(identity) && options.after <= result.next_after);
    let previous = options.after ?? result.next_after;
    let previousRevision;
    for (const frame of result.transactions) {
      check(object(frame) && typeof frame.token === 'string' && CHANGE_TOKEN.test(frame.token) && frame.token.startsWith(identity) && frame.token > previous && frame.token <= result.checkpoint &&
        REVISION.test(frame.previous_revision) && REVISION.test(frame.revision) && (previousRevision === undefined || frame.previous_revision === previousRevision) &&
        typeof frame.resnapshot_required === 'boolean' && Array.isArray(frame.operations) && frame.operations.length <= 256 && (!frame.resnapshot_required || frame.operations.length === 0));
      for (const op of frame.operations) {
        check(object(op) && typeof op.collection === 'string' && IDENTIFIER.test(op.collection));
        if (Object.hasOwn(op, 'document')) {
          check(typeof op.document === 'string' && IDENTIFIER.test(op.document) && Object.keys(op).length === 3 &&
            ((typeof op.put === 'string' && Buffer.byteLength(op.put) <= this.#config.maxDocumentBytes) || op.delete === true));
        } else check(Object.keys(op).length === 2 && op.create_collection === true);
      }
      previous = frame.token; previousRevision = frame.revision;
    }
    check(result.transactions.length ? previous === result.next_after : !result.has_more && (options.after === undefined || options.after === result.next_after));
    return result;
  }
}

/** Verified HTTPS replica set; only configured seeds can receive credentials. */
export class ClusterClient extends Client {
  constructor(options) { super(options, CLUSTER); }
}

export { BinaryClient, BinaryUncertainWriteError } from './lib/binary-client.js';
