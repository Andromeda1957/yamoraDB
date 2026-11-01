import { isIP } from 'node:net';
import { createSecureContext } from 'node:tls';
import { randomBytes, X509Certificate } from 'node:crypto';
import { inspect } from 'node:util';
import { performance } from 'node:perf_hooks';
import { isUtf8 } from 'node:buffer';
import { YamoraError } from './transport.js';
import { execute } from './binary-transport.js';
import { LIMIT, ownedBytes } from './binary-codec.js';
import { operationInput } from './binary-operations.js';

function requireInput(ok, message = 'invalid binary option') { if (!ok) throw new TypeError(`yamora: ${message}`); }
function options(value, allowed) {
  requireInput(value !== null && typeof value === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(value)));
  for (const name of Reflect.ownKeys(value)) {
    const d = Object.getOwnPropertyDescriptor(value, name);
    requireInput(allowed.includes(name) && Object.hasOwn(d, 'value'), 'unknown option or accessor');
  }
}
function integer(n, low, high) { requireInput(Number.isInteger(n) && n >= low && n <= high); return n; }
function material(value) {
  requireInput(typeof value === 'string' || Buffer.isBuffer(value), 'bounded PEM bytes required');
  const bytes = ownedBytes(value, 1024 * 1024);
  requireInput(bytes.length > 0, 'bounded PEM bytes required'); return bytes;
}
function config(input) {
  options(input, ['host', 'port', 'servername', 'tls', 'timeoutMs', 'maxConcurrentCalls', 'maxFrameBytes', 'maxDocumentBytes']);
  const { host, port, servername } = input;
  requireInput(typeof host === 'string' && isIP(host) === 4, 'numeric private IPv4 required');
  const [a, b] = host.split('.').map(Number);
  requireInput(a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168), 'numeric private IPv4 required');
  requireInput(typeof servername === 'string' && servername.length <= 253 && (isIP(servername) === 4 || /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(servername)), 'verification servername required');
  options(input.tls, ['ca', 'cert', 'key']);
  requireInput(!isIP(servername) || servername === host, 'numeric verification identity must match endpoint');
  const tls = { ca: material(input.tls.ca) };
  try {
    const trust = tls.ca.toString('utf8');
    const certificates = trust.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
    requireInput(certificates?.length > 0 && certificates.length <= 128 && trust.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g, '').trim() === '');
    for (const pem of certificates) new X509Certificate(pem);
  } catch { throw new TypeError('yamora: invalid trust certificate bytes'); }
  requireInput((input.tls.cert === undefined) === (input.tls.key === undefined), 'paired static client identity required');
  if (input.tls.cert !== undefined) { tls.cert = material(input.tls.cert); tls.key = material(input.tls.key); }
  try { createSecureContext({ ...tls, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' }); }
  catch { throw new TypeError('yamora: invalid TLS material'); }
  return Object.freeze({ host, port: integer(port, 1, 65535), servername, tls: Object.freeze(tls),
    timeoutMs: integer(input.timeoutMs ?? 5000, 1, 30000), maxConcurrentCalls: integer(input.maxConcurrentCalls ?? 4, 1, 4),
    maxFrameBytes: integer(input.maxFrameBytes ?? 65536, 4096, 65536), maxDocumentBytes: integer(input.maxDocumentBytes ?? LIMIT, 1, LIMIT) });
}

/** Includes admission and synchronous decode time; never refreshed by progress. */
class Budget {
  constructor(timeout, signal) {
    this.signal = signal;
    this.deadline = performance.now() + timeout;
    this.controller = new AbortController();
    this.abort = () => this.controller.abort(new YamoraError('binary call cancelled', { code: 'ABORT_ERR' }));
    signal?.addEventListener('abort', this.abort, { once: true });
    this.timer = setTimeout(() => this.controller.abort(new YamoraError('binary call deadline exceeded', { code: 'TIMEOUT' })), timeout);
    if (signal?.aborted) this.abort();
  }
  check() {
    if (this.controller.signal.aborted) throw this.controller.signal.reason;
    if (performance.now() >= this.deadline) throw new YamoraError('binary call deadline exceeded', { code: 'TIMEOUT' });
  }
  remaining() { this.check(); return Math.max(1, Math.ceil(this.deadline - performance.now())); }
  close() { clearTimeout(this.timer); this.signal?.removeEventListener('abort', this.abort); }
}

function sourceReader(source) { return () => ownedBytes(source, LIMIT); }
function envelope({ method, target, contentType, requestId, conditions, source }) {
  const view = { method: ['GET', 'HEAD', 'PUT', 'DELETE', 'POST', 'PATCH'][method - 1], target, contentType: contentType ?? (method === 3 ? 'application/yaml' : ''),
    requestId, conditions, sourceLength: source.length };
  // Buffers cannot be frozen. Keep the owner private and return a copy on access.
  Object.defineProperty(view, 'source', { get: sourceReader(source), enumerable: false });
  Object.defineProperty(view, inspect.custom, { value: () => ({ ...view, source: '[redacted]', authorization: '[redacted]' }) });
  return Object.freeze(view);
}
export class BinaryUncertainWriteError extends YamoraError {
  constructor(op, cause) {
    super('binary mutation outcome uncertain; reconcile before explicit resubmission', { code: cause.code, status: cause.status, uncertain: true });
    Object.defineProperties(this, { requestId: { value: op.requestId, enumerable: true }, envelope: { value: envelope(op), enumerable: true } });
  }
}

/** Separate single-endpoint TLS binary CRUD; no routing, recovery or automatic replay. */
export class BinaryClient {
  #config; #active = 0; #waiting = [];
  constructor(input) { this.#config = config(input); }
  #release() {
    this.#active--;
    const next = this.#waiting.shift();
    if (next) { this.#active++; next(); }
  }
  #admit(budget) {
    budget.check();
    if (this.#active < this.#config.maxConcurrentCalls) { this.#active++; return undefined; }
    return new Promise((resolve, reject) => {
      const signal = budget.controller.signal;
      const accept = () => { signal.removeEventListener('abort', abort); resolve(); };
      const abort = () => { const index = this.#waiting.indexOf(accept); if (index >= 0) this.#waiting.splice(index, 1); reject(signal.reason); };
      this.#waiting.push(accept); signal.addEventListener('abort', abort, { once: true });
    });
  }
  async #call(method, collection, document, source, input, operation) {
    options(input, ['signal', 'timeoutMs', 'token', 'requestId', 'ifMatch', 'ifNoneMatch']);
    const signal = input.signal;
    requireInput(signal === undefined || signal instanceof AbortSignal);
    const budget = new Budget(integer(input.timeoutMs ?? this.#config.timeoutMs, 1, 30000), signal);
    let admitted = false;
    try {
      const waiting = this.#admit(budget); if (waiting) await waiting;
      admitted = true; budget.check();
      options(input, ['signal', 'timeoutMs', 'token', 'requestId', 'ifMatch', 'ifNoneMatch']);
      if (!operation) {
        requireInput(typeof collection === 'string' && /^[a-z0-9-]{1,128}$/.test(collection));
        requireInput(typeof document === 'string' && /^[a-z0-9-]{1,128}$/.test(document));
      }
      const { token, ifMatch, ifNoneMatch } = input;
      requireInput(token === undefined || (typeof token === 'string' && /^[\x21-\x7e]{1,512}$/.test(token)), 'invalid bearer token');
      for (const condition of [ifMatch, ifNoneMatch]) requireInput(condition === undefined || (typeof condition === 'string' && /^[\x20-\x7e]{0,31}$/.test(condition)), 'invalid condition');
      const requestId = input.requestId ?? randomBytes(16).toString('hex');
      requireInput(typeof requestId === 'string' && /^[0-9a-f]{32}$/.test(requestId) && !/^0+$/.test(requestId), 'nonzero lowercase request ID required');
      let bytes = Buffer.alloc(0);
      if (method === 3) {
        bytes = ownedBytes(source, this.#config.maxDocumentBytes);
        requireInput(isUtf8(bytes) && (typeof source !== 'string' || source.isWellFormed()), 'source must be UTF-8');
      }
      const extended = operation ? operationInput(operation.method, operation.target, operation.contentType, source, operation.onPage) : {};
      const op = Object.freeze({ method, collection, document, target: `/v1/collections/${collection}/documents/${document}`,
        source: bytes, token, requestId, conditions: Object.freeze({ ifMatch, ifNoneMatch }), ...extended });
      budget.check();
      return await execute(this.#config, op, budget, cause => new BinaryUncertainWriteError(op, cause));
    } finally { budget.close(); if (admitted) this.#release(); }
  }
  /** Raw schema-2 operation; HTTP APIs and schema-1 CRUD remain separate. */
  operation(method, target, contentType, source, input = {}) {
    return this.#call(0, undefined, undefined, source, input, { method, target, contentType });
  }
  /** Synchronous callback receives one owned, validated NDJSON page including LF. */
  feed(target, onPage, input = {}) {
    requireInput(typeof onPage === 'function');
    return this.#call(0, undefined, undefined, undefined, input, { method: 'GET', target, contentType: '', onPage });
  }
  get(collection, document, input = {}) { return this.#call(1, collection, document, undefined, input); }
  head(collection, document, input = {}) { return this.#call(2, collection, document, undefined, input); }
  put(collection, document, source, input = {}) { return this.#call(3, collection, document, source, input); }
  delete(collection, document, input = {}) { return this.#call(4, collection, document, undefined, input); }
}
