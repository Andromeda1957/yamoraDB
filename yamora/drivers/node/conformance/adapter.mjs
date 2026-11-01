import { readFileSync, writeFileSync, realpathSync, statSync } from 'node:fs';
import { join, isAbsolute } from 'node:path';
import { BinaryClient, BinaryUncertainWriteError, YamoraError } from '../index.js';

// Only public SDK values cross this boundary. The runner owns all assertions.
const required = ['host', 'port', 'server-name', 'ca-file', 'cert-file', 'key-file',
  'method', 'collection', 'document', 'source-file', 'request-id', 'timeout-ms',
  'max-frame-bytes', 'cancel-mode', 'output-dir'];
function args() {
  const result = Object.create(null), allowed = new Set([...required, 'token-file', 'if-match', 'if-none-match']);
  const argv = process.argv.slice(2);
  if (argv.length % 2) throw new Error();
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i].slice(2);
    if (!argv[i].startsWith('--') || !allowed.has(key) || Object.hasOwn(result, key)) throw new Error();
    result[key] = argv[i + 1];
  }
  if (required.some(key => !Object.hasOwn(result, key)) || result.host !== '127.0.0.1' ||
      result['server-name'] !== 'localhost' || result['max-frame-bytes'] !== '4096' ||
      !['GET', 'HEAD', 'PUT', 'DELETE'].includes(result.method) ||
      !['none', 'pre', 'external'].includes(result['cancel-mode']) ||
      !/^(?!0{32}$)[0-9a-f]{32}$/.test(result['request-id'])) throw new Error();
  for (const [key, limit] of [['port', 65535], ['timeout-ms', 30000]]) {
    if (!/^[1-9][0-9]*$/.test(result[key]) || Number(result[key]) > limit) throw new Error();
  }
  if (Number(result.port) === 8000) throw new Error();
  return result;
}
function read(path, limit = 16 * 1024 * 1024) {
  if (!isAbsolute(path) || !statSync(path).isFile() || statSync(path).size > limit) throw new Error();
  const value = readFileSync(path);
  if (value.length > limit) throw new Error();
  return value;
}
function kind(error) {
  if (!(error instanceof YamoraError)) throw new Error();
  switch (error.code) {
    case 'BINARY_STATUS': return 'status';
    case 'TIMEOUT': return 'deadline';
    case 'ABORT_ERR': return 'cancelled';
    case 'PROTOCOL_ERROR': return 'protocol';
    case 'TRUNCATED_RESPONSE': case 'TRANSPORT_ERROR': case 'TLS_ERROR':
    case 'BINARY_ERROR': case 'GOAWAY': return 'transport';
    default:
      // The SDK preserves native TLS/socket codes as its public typed code.
      if (typeof error.code === 'string' && /^(?:ERR_TLS_|ERR_SSL_|CERT_|DEPTH_|UNABLE_|SELF_SIGNED_|ECONN|EHOST|ENET|EPIPE|ETIMEDOUT)/.test(error.code)) return 'transport';
      throw new Error();
  }
}
function controls(mode, cancellation) {
  let pending = Buffer.alloc(0), failure = false;
  const malformed = () => { failure = true; cancellation.abort(); };
  const data = chunk => {
    pending = Buffer.concat([pending, chunk]);
    if (pending.length > 2 || pending[0] !== 67 || (pending.length === 2 && pending[1] !== 10)) malformed();
    else if (pending.length === 2) { cancellation.abort(); pending = Buffer.alloc(0); }
  };
  const end = () => { if (pending.length) malformed(); };
  if (mode === 'pre') cancellation.abort();
  if (mode === 'external') {
    process.stdin.on('data', data);
    process.stdin.on('end', end);
    process.stdin.on('error', malformed);
    process.stdin.resume();
  }
  return () => {
    process.stdin.pause();
    process.stdin.removeListener('data', data);
    process.stdin.removeListener('end', end);
    process.stdin.removeListener('error', malformed);
    if (failure || pending.length) throw new Error();
  };
}
async function main() {
  const a = args(), source = read(a['source-file']);
  if (a.method !== 'PUT' && source.length) throw new Error();
  const root = realpathSync(a['output-dir']);
  if (!isAbsolute(a['output-dir']) || !statSync(root).isDirectory()) throw new Error();
  const file = (name, bytes) => { writeFileSync(join(root, name), bytes, { flag: 'wx', mode: 0o600 }); return name; };
  const client = new BinaryClient({ host: a.host, port: Number(a.port), servername: a['server-name'],
    tls: { ca: read(a['ca-file'], 1024 * 1024), cert: read(a['cert-file'], 1024 * 1024), key: read(a['key-file'], 1024 * 1024) },
    timeoutMs: Number(a['timeout-ms']), maxConcurrentCalls: 1, maxFrameBytes: Number(a['max-frame-bytes']) });
  const cancellation = new AbortController();
  const options = { signal: cancellation.signal, requestId: a['request-id'] };
  if (Object.hasOwn(a, 'token-file')) options.token = read(a['token-file'], 512).toString('ascii');
  if (Object.hasOwn(a, 'if-match')) options.ifMatch = a['if-match'];
  if (Object.hasOwn(a, 'if-none-match')) options.ifNoneMatch = a['if-none-match'];
  const api = { status: null, body_file: null, etag: null, revision: null,
    representation_length: null, request_id: null, receipt: null };
  const observation = { schema: 'yamora-observation/1', outcome: 'success', error_kind: null,
    elapsed_ns: 0, api, envelope: null };
  const stop = controls(a['cancel-mode'], cancellation);
  let value, failure;
  const started = process.hrtime.bigint();
  try {
    switch (a.method) {
      case 'GET': value = await client.get(a.collection, a.document, options); break;
      case 'HEAD': value = await client.head(a.collection, a.document, options); break;
      case 'PUT': value = await client.put(a.collection, a.document, source, options); break;
      case 'DELETE': value = await client.delete(a.collection, a.document, options); break;
    }
  } catch (error) { failure = error; }
  finally { observation.elapsed_ns = Number(process.hrtime.bigint() - started); stop(); }
  if (failure) {
    observation.error_kind = kind(failure);
    observation.outcome = observation.error_kind;
    if (failure.status !== undefined) api.status = failure.status;
    if (failure instanceof BinaryUncertainWriteError && failure.uncertain === true) {
      const original = failure.envelope;
      // Identity is available publicly through the exception-owned target.
      const target = /^\/v1\/collections\/([a-z0-9-]+)\/documents\/([a-z0-9-]+)$/.exec(original.target);
      if (!target) throw new Error();
      observation.outcome = 'uncertain';
      observation.envelope = { method: original.method, collection: target[1], document: target[2],
        if_match: original.conditions.ifMatch ?? null, if_none_match: original.conditions.ifNoneMatch ?? null,
        request_id: original.requestId, source_file: file('envelope.bin', original.source) };
    } else if (failure.uncertain) throw new Error();
  } else {
    api.etag = value.etag ?? null;
    api.revision = value.revision ?? null;
    api.request_id = value.requestId ?? null;
    if (a.method === 'GET') api.body_file = file('body.bin', value.source);
    if (a.method === 'HEAD') api.representation_length = value.representationLength;
    if (a.method === 'PUT') api.receipt = { status: value.status, collection: value.collection,
      document: value.document, etag: value.etag, revision: value.revision };
  }
  const json = JSON.stringify(observation) + '\n';
  if (Buffer.byteLength(json) > 16384) throw new Error();
  process.stdout.write(json);
}
main().catch(() => { process.stderr.write('Node conformance adapter failed\n'); process.exitCode = 2; });
