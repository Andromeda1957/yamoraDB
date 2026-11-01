import http from 'node:http';
import https from 'node:https';
import { isIP } from 'node:net';
import { checkServerIdentity, createSecureContext } from 'node:tls';
import { keys, integer, requireValue, MAX_DOCUMENT_BYTES, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES } from './validation.js';

export class YamoraError extends Error {
  constructor(message, { code = 'PROTOCOL_ERROR', status, uncertain = false } = {}) {
    super(`yamora: ${message}`);
    this.name = 'YamoraError';
    this.code = code;
    this.status = status;
    this.uncertain = uncertain;
  }
}

export function configuration(options) {
  keys(options, ['host', 'port', 'readToken', 'writeToken', 'timeoutMs', 'tls', 'maxDocumentBytes', 'maxRequestBytes', 'maxResponseBytes']);
  const config = { host: '127.0.0.1', port: 8765, timeoutMs: 5000, maxDocumentBytes: MAX_DOCUMENT_BYTES,
    maxRequestBytes: MAX_REQUEST_BYTES, maxResponseBytes: MAX_RESPONSE_BYTES, ...options };
  requireValue(typeof config.host === 'string' && isIP(config.host) === 4, 'numeric private IPv4 required');
  const [a, b] = config.host.split('.').map(Number);
  requireValue(a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168), 'numeric private IPv4 required');
  integer(config.port, 1, 65535);
  integer(config.timeoutMs, 1, 30000);
  integer(config.maxDocumentBytes, 1, MAX_DOCUMENT_BYTES);
  integer(config.maxRequestBytes, 1, MAX_REQUEST_BYTES);
  integer(config.maxResponseBytes, 1, MAX_RESPONSE_BYTES);
  for (const token of [config.readToken, config.writeToken]) {
    requireValue(token === undefined || (typeof token === 'string' && /^[\x21-\x7e]{32,512}$/.test(token)), 'invalid credential');
  }
  if (config.tls !== undefined) {
    keys(config.tls, ['ca', 'cert', 'key']);
    const material = {};
    for (const key of ['ca', 'cert', 'key']) {
      const item = config.tls[key];
      if (item === undefined) continue;
      requireValue((typeof item === 'string' || Buffer.isBuffer(item)) && item.length > 0 && Buffer.byteLength(item) <= 1024 * 1024, 'invalid TLS material');
      material[key] = Buffer.from(item);
    }
    requireValue((material.cert === undefined) === (material.key === undefined), 'TLS client certificate and key must be paired');
    try {
      config.secureContext = createSecureContext({ ...material, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' });
    } catch { throw new TypeError('yamora: invalid TLS material'); }
  }
  delete config.tls;
  return Object.freeze(config);
}

export function validateRequest(config, body, write, options) {
  keys(options, write ? ['signal', 'etag', 'createOnly', 'revision', 'requestId'] : ['signal', 'revision', 'limit', 'after']);
  if (options.signal !== undefined) requireValue(options.signal instanceof AbortSignal, 'invalid abort signal');
  if (options.requestId !== undefined) {
    requireValue(typeof options.requestId === 'string' && /^[0-9a-f]{32}$/.test(options.requestId) && !/^0+$/.test(options.requestId), 'invalid request ID');
  }
  requireValue(!body || body.length <= config.maxRequestBytes, 'request exceeds limit');
}

export function request(config, method, path, body, headers, write, options, statuses = [200], maximum = config.maxResponseBytes, timeoutMs = config.timeoutMs) {
  validateRequest(config, body, write, options);
  const token = write ? config.writeToken : config.readToken;
  const requestHeaders = { Accept: 'application/json, application/yaml', 'Accept-Encoding': 'identity', Connection: 'close', ...headers };
  if (body) requestHeaders['Content-Length'] = String(body.length);
  if (token !== undefined) requestHeaders.Authorization = `Bearer ${token}`;
  if (options.requestId !== undefined) {
    requestHeaders['X-Yamora-Request-Id'] = options.requestId;
  }
  return new Promise((resolve, reject) => {
    if (options.signal?.aborted) { reject(new YamoraError('request aborted', { code: 'ABORT_ERR' })); return; }
    const secure = config.secureContext !== undefined;
    const transport = secure ? https : http;
    // A private single-request agent also ignores NODE_USE_ENV_PROXY and global
    // agents. There is no pooled socket on which a library could replay a write.
    const agent = new transport.Agent({ keepAlive: false, proxyEnv: {} });
    let settled = false;
    let req;
    let response;
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      options.signal?.removeEventListener('abort', abort);
      response?.destroy();
      req?.destroy();
      agent.destroy();
      if (error) reject(error); else resolve(result);
    };
    const fail = (message, code = 'PROTOCOL_ERROR') => finish(new YamoraError(message, { code, uncertain: write }));
    const abort = () => fail('request aborted; reconcile mutations before retrying', 'ABORT_ERR');
    // Absolute wall-clock budget, including connect, TLS, headers and trickled
    // bodies; socket inactivity timeouts alone do not bound slow responses.
    const timer = setTimeout(() => fail('request deadline exceeded', 'TIMEOUT'), Math.max(1, timeoutMs));
    options.signal?.addEventListener('abort', abort, { once: true });
    try {
      req = transport.request({ host: config.host, port: config.port, method, path, headers: requestHeaders,
        agent, family: 4, maxHeaderSize: 16 * 1024, insecureHTTPParser: false,
        ...(secure ? { secureContext: config.secureContext, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3',
          rejectUnauthorized: true, checkServerIdentity: (_name, cert) => checkServerIdentity(config.host, cert), ALPNProtocols: ['http/1.1'] } : {}) }, res => {
        response = res;
        res.on('error', () => fail('incomplete response', 'TRUNCATED_RESPONSE'));
        if (!statuses.includes(res.statusCode)) {
          finish(new YamoraError(`HTTP ${res.statusCode}`, { code: 'HTTP_ERROR', status: res.statusCode,
            uncertain: write && !(res.statusCode >= 400 && res.statusCode < 500 && res.statusCode !== 408) }));
          return;
        }
        const seen = new Set();
        for (let i = 0; i < res.rawHeaders.length; i += 2) {
          const name = res.rawHeaders[i].toLowerCase();
          if (['content-length', 'transfer-encoding', 'content-type', 'content-encoding', 'etag', 'x-yamldb-revision'].includes(name)) {
            if (seen.has(name)) { fail('duplicate response metadata'); return; }
            seen.add(name);
          }
        }
        const length = res.headers['content-length'];
        if ((length !== undefined && (!/^(0|[1-9][0-9]*)$/.test(length) || Number(length) > maximum)) || res.headers['content-encoding'] !== undefined ||
          (res.headers['transfer-encoding'] !== undefined && res.headers['transfer-encoding'] !== 'chunked')) {
          fail('oversized or unsupported response framing', 'RESPONSE_LIMIT'); return;
        }
        const chunks = [];
        let received = 0;
        res.on('data', chunk => {
          received += chunk.length;
          if (received > maximum) { fail('response exceeds limit', 'RESPONSE_LIMIT'); return; }
          chunks.push(chunk);
        });
        res.on('end', () => {
          if (!res.complete || (length !== undefined && received !== Number(length))) { fail('incomplete response', 'TRUNCATED_RESPONSE'); return; }
          finish(null, { body: Buffer.concat(chunks, received), headers: res.headers, status: res.statusCode });
        });
        res.on('close', () => { if (!res.complete) fail('incomplete response', 'TRUNCATED_RESPONSE'); });
      });
      req.on('error', error => fail('transport failed; reconcile mutations before retrying',
        typeof error.code === 'string' && /^[A-Z0-9_]+$/.test(error.code) ? error.code : 'TRANSPORT_ERROR'));
      req.on('upgrade', (_res, socket) => { socket.destroy(); fail('unexpected protocol upgrade'); });
      req.end(body);
    } catch { fail('transport could not start', 'TRANSPORT_ERROR'); }
  });
}
