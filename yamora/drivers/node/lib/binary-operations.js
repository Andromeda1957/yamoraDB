import { isUtf8 } from 'node:buffer';
import { decode, decodeOperationResponse } from './codec.js';
import { LIMIT, ownedBytes, valid } from './binary-codec.js';

const cursor = /^v1\.[0-9a-f]{32}\.[0-9a-f]{16}$/;
export function operationInput(method, target, contentType, source, onPage) {
  const input = ok => { if (!ok) throw new TypeError('yamora: invalid binary operation'); };
  input(typeof method === 'string' && typeof target === 'string' && /^[\x21-\x7e]{1,1024}$/.test(target));
  const document = /^\/v1\/collections\/([a-z0-9-]{1,128})\/documents\/([a-z0-9-]{1,128})$/.exec(target);
  const query = /^\/v1\/(query|aggregate|search)\/([a-z0-9-]{1,128})$/.exec(target);
  const feed = target.startsWith('/v1/changes/stream?');
  const changes = /^\/v1\/changes(?:\?[^%#]*)?$/.test(target);
  input(method === 'PATCH' && document || method === 'POST' && (query || target === '/v1/transactions') || method === 'GET' && (changes || feed));
  input(Boolean(onPage) === feed);
  if (method === 'GET') {
    input(contentType === '' && (source === undefined || ownedBytes(source, 0).length === 0));
    const names = new Set();
    for (const item of (target.split('?')[1] ?? '').split('&').filter(Boolean)) {
      const match = /^(after|limit|duration_ms|heartbeat_ms)=([a-z0-9.]+)$/.exec(item);
      input(match && !names.has(match[1]) && (feed || !['duration_ms', 'heartbeat_ms'].includes(match[1])));
      names.add(match[1]); input(match[1] === 'after' ? cursor.test(match[2]) : /^[0-9]+$/.test(match[2]));
    }
    input(!feed || names.has('after'));
  } else input(typeof contentType === 'string' && contentType.length <= 95 && /^(application\/(?:json|yaml)|text\/yaml)(?:;[\x20-\x7e]*)?$/i.test(contentType));
  const bytes = source === undefined ? Buffer.alloc(0) : ownedBytes(source, LIMIT);
  input(isUtf8(bytes) && (typeof source !== 'string' || source.isWellFormed()));
  return { schema: 2, method: { GET: 1, POST: 5, PATCH: 6 }[method], target, contentType, source: bytes,
    collection: document?.[1] ?? query?.[2], document: document?.[2], mutation: method === 'PATCH' || target === '/v1/transactions', onPage };
}

// Keep authored bytes as the public result. The lossless existing decoder is
// used only for JSON structure/receipt/cursor checks, never serialization.
export function operationJSON(bytes, response = false) {
  const value = response ? decodeOperationResponse(bytes) : decode(bytes);
  const stack = [];
  for (const token of bytes.toString('utf8').matchAll(/"(?:\\.|[^"\\])*"|[{}\[\],:]/g)) {
    const text = token[0], top = stack.at(-1);
    if (text === '{' || text === '[') stack.push({ object: text === '{', keys: new Set(), key: text === '{' });
    else if (text === '}' || text === ']') stack.pop();
    else if (text === ',' && top?.object) top.key = true;
    else if (text[0] === '"' && top?.object && top.key) {
      const key = JSON.parse(text); valid(!top.keys.has(key)); top.keys.add(key); top.key = false;
    }
  }
  return value;
}

export function operationReceipt(op, meta, body) {
  const value = operationJSON(body, true);
  if (meta.status >= 400) return;
  valid(value.revision === meta.revision);
  if (!op.mutation) return;
  if (op.method === 6) {
    valid(Object.keys(value).length === 5 && value.status === 'stored' && value.collection === op.collection &&
      value.document === op.document && value.etag === meta.etag && value.revision === meta.revision);
  } else {
    valid(Object.keys(value).length === 3 && value.status === 'committed' && Number.isInteger(value.operations) &&
      value.operations >= 1 && value.operations <= 128 && value.revision === meta.revision);
    // YAML is validated by the native API. JSON envelopes also correlate count.
    if (op.contentType.split(';')[0].toLowerCase() === 'application/json') {
      const request = operationJSON(op.source); valid(Array.isArray(request.operations) && value.operations === request.operations.length);
    }
  }
}

export function feedPage(bytes, previous) {
  valid(bytes.length > 1 && bytes.at(-1) === 10);
  const page = operationJSON(bytes, true);
  if (Object.hasOwn(page, 'terminal')) {
    valid(page.terminal === true);
    valid(Number.isInteger(page.status) && page.status >= 400 && page.status <= 599 && page.after === previous &&
      page.detail !== null && typeof page.detail === 'object' && !Array.isArray(page.detail));
    return { after: previous, terminal: true };
  }
  valid(cursor.test(page.next_after) && cursor.test(page.checkpoint) && cursor.test(page.oldest_after) &&
    /^[0-9a-f]{16}$/.test(page.revision) && Array.isArray(page.transactions) && page.transactions.length <= 100 &&
    typeof page.has_more === 'boolean' && page.oldest_after <= page.next_after && page.next_after <= page.checkpoint &&
    page.has_more === (page.next_after < page.checkpoint) && (!previous || page.next_after >= previous) &&
    (!previous || page.next_after.slice(0, 36) === previous.slice(0, 36)));
  const identity = page.checkpoint.slice(0, 36);
  valid(page.next_after.startsWith(identity) && page.oldest_after.startsWith(identity));
  let last = previous ?? page.next_after, revision;
  for (const transaction of page.transactions) {
    valid(transaction && typeof transaction === 'object' && cursor.test(transaction.token) && transaction.token.startsWith(identity) &&
      transaction.token > last && transaction.token <= page.checkpoint && /^[0-9a-f]{16}$/.test(transaction.revision) &&
      /^[0-9a-f]{16}$/.test(transaction.previous_revision) && (revision === undefined || revision === transaction.previous_revision) &&
      typeof transaction.resnapshot_required === 'boolean' && Array.isArray(transaction.operations) && transaction.operations.length <= 256 &&
      (!transaction.resnapshot_required || transaction.operations.length === 0));
    const seen = new Set(); let sourceBytes = 0;
    for (const op of transaction.operations) {
      valid(op && typeof op === 'object' && typeof op.collection === 'string' && /^[a-z0-9-]{1,128}$/.test(op.collection));
      const identity = `${op.collection}/${op.document ?? ''}`; valid(!seen.has(identity)); seen.add(identity);
      if (typeof op.put === 'string') sourceBytes += Buffer.byteLength(op.put);
      if (Object.hasOwn(op, 'document')) valid(typeof op.document === 'string' && /^[a-z0-9-]{1,128}$/.test(op.document) && Object.keys(op).length === 3 &&
        (typeof op.put === 'string' && Buffer.byteLength(op.put) > 0 && Buffer.byteLength(op.put) <= LIMIT || op.delete === true));
      else valid(Object.keys(op).length === 2 && op.create_collection === true);
    }
    valid(sourceBytes <= LIMIT);
    last = transaction.token; revision = transaction.revision;
  }
  valid(page.transactions.length ? last === page.next_after : !page.has_more && (previous === undefined || previous === page.next_after));
  return { after: page.next_after, terminal: false };
}
