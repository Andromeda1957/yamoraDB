import { isUtf8 } from 'node:buffer';
import { constants, lstatSync, openSync, closeSync, fstatSync, readSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, parse, resolve } from 'node:path';
import { ClusterClient, UncertainWriteError, YamoraError } from '../index.js';

const LINE = 16384, FILE = 131072;
const COMMAND = 'yamora-http-replica-command/2';
const fail = () => { throw new Error('invalid adapter session'); };
const need = condition => { if (!condition) fail(); };
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
function keys(value, names) {
  need(object(value) && Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name)));
}

// JSON.parse owns value decoding, including Node 22's original integer tokens.
// The bounded lexical pass rejects duplicate keys before JSON.parse loses them.
function json(bytes, maximum) {
  need(bytes.length <= maximum && isUtf8(bytes));
  const text = bytes.toString('utf8');
  let at = 0;
  const space = () => { while (/[\x20\t\r\n]/.test(text[at] ?? '\0')) at++; };
  function string() {
    const start = at++;
    while (at < text.length) {
      const ch = text[at++];
      if (ch === '"') return JSON.parse(text.slice(start, at));
      if (ch === '\\') at++;
    }
    fail();
  }
  function value(depth) {
    space();
    const ch = text[at];
    if (ch === '{' || ch === '[') {
      need(depth < 12); at++; space();
      const end = ch === '{' ? '}' : ']';
      const seen = new Set();
      if (text[at] === end) { at++; return; }
      do {
        if (ch === '{') {
          space(); need(text[at] === '"');
          const name = string(); need(!seen.has(name)); seen.add(name);
          space(); need(text[at++] === ':');
        }
        value(depth + 1); space();
        if (text[at] === end) { at++; return; }
        need(text[at++] === ',');
      } while (at < text.length);
      fail();
    } else if (ch === '"') string();
    else {
      const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(at));
      need(token !== null); at += token[0].length;
    }
  }
  value(0); space(); need(at === text.length);
  const result = JSON.parse(text, (_key, item, context) => {
    if (typeof item === 'number') {
      need(Number.isFinite(item) && /^-?(?:0|[1-9][0-9]*)$/.test(context.source));
      if (!Number.isSafeInteger(item)) return BigInt(context.source);
    }
    if (typeof item === 'string') need(item.isWellFormed());
    if (object(item)) need(Object.keys(item).every(name => name.isWellFormed()));
    return item;
  });
  need(object(result)); return result;
}
function stringify(value) {
  return JSON.stringify(value, (_key, item) => typeof item === 'bigint' ? JSON.rawJSON(item.toString()) : item);
}

function safePath(path, directory = false) {
  need(isAbsolute(path) && resolve(path) === path);
  let current = parse(path).root;
  for (const part of path.slice(current.length).split('/')) {
    need(part.length > 0); current = join(current, part);
    const info = lstatSync(current);
    need(!info.isSymbolicLink() && (current === path && !directory ? info.isFile() : info.isDirectory()));
  }
  return path;
}
function read(root, name, maximum = FILE) {
  need(typeof name === 'string' && /^[a-z0-9.-]+(?:\/[a-z0-9.-]+)*$/.test(name) &&
    name.split('/').every(part => part !== '.' && part !== '..'));
  const path = safePath(join(root, name));
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = fstatSync(fd); need(info.isFile() && info.size <= maximum);
    const bytes = Buffer.alloc(maximum + 1);
    let size = 0, got;
    do { got = readSync(fd, bytes, size, bytes.length - size, null); size += got; } while (got && size < bytes.length);
    need(size <= maximum); return Buffer.from(bytes.subarray(0, size));
  } finally { closeSync(fd); }
}
function configuration() {
  const args = process.argv.slice(2);
  need(args.length === 4 && args[0] === '--config' && args[2] === '--root');
  const root = safePath(args[3], true); need(args[1] === join(root, 'config.json'));
  const config = json(read(root, 'config.json', LINE), LINE);
  keys(config, ['schema', 'cluster_id', 'voters', 'seeds', 'tls', 'tokens', 'timeout_ms', 'attempt_timeout_ms']);
  need(config.schema === 'yamora-http-replica-config/2' &&
    typeof config.cluster_id === 'string' && /^(?!0{32}$)[0-9a-f]{32}$/.test(config.cluster_id) &&
    config.voters === 3 && config.timeout_ms === 15000 && config.attempt_timeout_ms === 3000);
  need(Array.isArray(config.seeds) && config.seeds.length === 3);
  const nodes = new Set(), ports = new Set();
  for (const seed of config.seeds) {
    keys(seed, ['host', 'port', 'node']);
    need(seed.host === '127.0.0.1' && Number.isInteger(seed.port) && seed.port >= 1 && seed.port <= 65535 &&
      seed.port !== 8000 && Number.isInteger(seed.node) && seed.node >= 1 && seed.node <= 3 &&
      !nodes.has(seed.node) && !ports.has(seed.port));
    nodes.add(seed.node); ports.add(seed.port);
  }
  keys(config.tls, ['ca_file', 'cert_file', 'key_file']);
  keys(config.tokens, ['read_file', 'write_file']);
  need(config.tls.ca_file === 'ca.pem' && config.tls.cert_file === 'client.pem' && config.tls.key_file === 'client.key' &&
    config.tokens.read_file === 'read.token' && config.tokens.write_file === 'write.token');
  const token = name => {
    const bytes = read(root, name, 512); need(isUtf8(bytes));
    const text = bytes.toString('utf8').replace(/\r?\n$/, '');
    need(/^[\x21-\x7e]{32,512}$/.test(text)); return text;
  };
  const client = new ClusterClient({
    seeds: config.seeds.map(({ host, port }) => ({ host, port })),
    tls: { ca: read(root, 'ca.pem', LINE), cert: read(root, 'client.pem', LINE), key: read(root, 'client.key', LINE) },
    readToken: token('read.token'), writeToken: token('write.token'),
    // The public Node SDK has one shared discovery/dispatch/retry budget.
    timeoutMs: config.timeout_ms, retryTimeoutMs: config.timeout_ms,
    maxDocumentBytes: FILE, maxRequestBytes: FILE, maxResponseBytes: FILE
  });
  return { root, client };
}
function primitive(command, root) {
  keys(command, ['schema', 'seq', 'action', 'method', 'collection', 'document', 'source_file', 'request_id', 'if_match', 'if_none_match']);
  const { method, collection, document, source_file: name, request_id: id, if_match: match, if_none_match: none } = command;
  need(['GET', 'PUT', 'PATCH', 'DELETE'].includes(method) &&
    [collection, document].every(value => typeof value === 'string' && /^[a-z0-9-]{1,128}$/.test(value)));
  need(method === 'GET' || collection !== 'yamldb-system');
  need(id === null || (typeof id === 'string' && /^(?!0{32}$)[0-9a-f]{32}$/.test(id)));
  need(match === null || (typeof match === 'string' && /^"[0-9a-f]{16}"$/.test(match)));
  need(none === null || (none === '*' && method === 'PUT' && match === null));
  need(method !== 'GET' || (id === null && match === null && none === null));
  const options = {};
  if (id !== null) options.requestId = id;
  if (match !== null) options.etag = match.slice(1, -1);
  if (none !== null) options.createOnly = true;
  let source;
  if (method === 'PUT' || method === 'PATCH') {
    need(typeof name === 'string' && /^input\/[a-z0-9-]{1,64}\.bin$/.test(name));
    source = read(root, name); need(source.length > 0 && isUtf8(source));
    if (method === 'PATCH') {
      source = json(source, FILE); keys(source, ['$inc']); keys(source.$inc, ['n']); need(source.$inc.n === 1);
      Object.freeze(source.$inc); Object.freeze(source);
    }
  } else need(name === null);
  // This buffer/object is adapter-owned, never reread or exposed to callers.
  return Object.freeze({ method, collection, document, source, options: Object.freeze(options) });
}
function invoke(client, saved, signal, requestId) {
  const { method, collection, document, source } = saved;
  const options = { ...saved.options, signal, ...(requestId === undefined ? {} : { requestId }) };
  if (method === 'GET') return client.get(collection, document, options);
  if (method === 'DELETE') return client.delete(collection, document, options);
  if (method === 'PUT') return client.put(collection, document, source, options);
  return client.patch(collection, document, source, options);
}
function kind(error) {
  need(error instanceof YamoraError);
  if (error.code === 'HTTP_ERROR') return 'status';
  if (error.code === 'TIMEOUT') return 'deadline';
  if (error.code === 'ABORT_ERR') return 'cancelled';
  if (['PROTOCOL_ERROR', 'RESPONSE_LIMIT'].includes(error.code)) return 'protocol';
  if (typeof error.code === 'string' && /^(?:TRUNCATED_RESPONSE|TRANSPORT_ERROR|ERR_TLS_|ERR_SSL_|ERR_OSSL_|CERT_|DEPTH_|UNABLE_|SELF_SIGNED_|ECONN|EHOST|ENET|EPIPE|ETIMEDOUT|EPROTO)/.test(error.code)) return 'transport';
  fail();
}
function observation(command) {
  return { schema: 'yamora-http-replica-observation/2', seq: command.seq, action: command.action,
    outcome: 'success', error_kind: null, elapsed_ns: 0,
    api: { status: null, body_file: null, etag: null, revision: null, receipt: null },
    sdk_request_id: null, envelope: null, recovery_mode: null, recovery_handle: null };
}

async function main() {
  const { root, client } = configuration();
  const handles = new Map();
  let seq = 0, busy = false, closed = false, broken = false, pending = Buffer.alloc(0), active;
  const stop = () => { broken = true; active?.abort(); };
  const emit = value => {
    const line = stringify(value) + '\n'; need(Buffer.byteLength(line) <= LINE);
    process.stdout.write(line);
  };
  async function execute(command) {
    need(command.schema === COMMAND && Number.isSafeInteger(command.seq) && command.seq === seq + 1 && command.seq <= 64);
    seq = command.seq;
    const result = observation(command);
    if (command.action === 'close') {
      keys(command, ['schema', 'seq', 'action']);
      result.outcome = 'closed'; closed = true; emit(result); process.stdin.destroy(); return;
    }
    let saved, original;
    if (command.action === 'call') {
      saved = primitive(command, root);
      // Keep room for uncertainty before a new mutation can reach the cluster.
      need(saved.method === 'GET' || handles.size < 16);
    }
    else {
      need(command.action === 'recover'); keys(command, ['schema', 'seq', 'action', 'handle']);
      need(typeof command.handle === 'string' && handles.has(command.handle));
      ({ saved, error: original } = handles.get(command.handle));
      result.recovery_handle = command.handle; result.recovery_mode = 'caller-reissue';
    }
    // The runner creates output directories; reject unsafe ones before dispatch.
    const output = `call-${String(seq).padStart(6, '0')}`;
    safePath(join(root, output), true);
    active = new AbortController();
    const watchdog = setTimeout(stop, 25000);
    let value, failure;
    const started = process.hrtime.bigint();
    try { value = await invoke(client, saved, active.signal, original?.requestId); }
    catch (error) { failure = error; }
    finally { result.elapsed_ns = Number(process.hrtime.bigint() - started); clearTimeout(watchdog); active = undefined; }
    need(!broken);
    if (failure) {
      if (failure instanceof UncertainWriteError) {
        need(failure.uncertain === true && typeof failure.requestId === 'string' && /^(?!0{32}$)[0-9a-f]{32}$/.test(failure.requestId));
        result.outcome = 'uncertain';
        result.error_kind = failure.cause === undefined ? null : kind(failure.cause);
        result.sdk_request_id = failure.requestId;
        if (command.action === 'call') {
          const handle = `h${handles.size + 1}`;
          handles.set(handle, { saved, error: failure });
          result.recovery_handle = handle; result.recovery_mode = 'caller-reissue';
        }
      } else { result.outcome = result.error_kind = kind(failure); need(!failure.uncertain); }
      result.api.status = failure.status ?? null;
    } else {
      result.api.etag = value.etag ?? null; result.api.revision = value.revision ?? null;
      if (saved.method === 'GET') {
        need(Buffer.isBuffer(value.source) && value.source.length <= FILE);
        safePath(join(root, output), true);
        writeFileSync(join(root, output, 'body.bin'), value.source, { flag: constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, mode: 0o600 });
        result.api.body_file = `${output}/body.bin`;
      } else if (saved.method === 'PUT' || saved.method === 'PATCH') {
        result.api.receipt = { status: value.status, collection: value.collection, document: value.document,
          etag: value.etag, revision: value.revision };
      }
    }
    emit(result);
  }
  // Read one bounded command at a time. Concurrent/pipelined input is invalid;
  // an incomplete stdin or interrupt aborts the SDK-owned in-flight work.
  await new Promise((done, reject) => {
    const invalid = () => { stop(); reject(new Error('invalid adapter session')); };
    const signal = () => invalid();
    process.once('SIGINT', signal); process.once('SIGTERM', signal);
    const finish = () => {
      process.removeListener('SIGINT', signal); process.removeListener('SIGTERM', signal);
      process.stdin.pause();
    };
    process.stdin.on('error', invalid);
    process.stdin.on('end', () => { if (!closed) invalid(); });
    process.stdin.on('data', chunk => {
      if (closed || busy || pending.length + chunk.length > LINE) { invalid(); return; }
      pending = Buffer.concat([pending, chunk]);
      const lf = pending.indexOf(10);
      if (lf < 0) return;
      if (lf !== pending.length - 1) { invalid(); return; }
      let command;
      try { need(!pending.includes(13)); command = json(pending.subarray(0, lf), LINE - 1); } catch { invalid(); return; }
      pending = Buffer.alloc(0); busy = true;
      execute(command).then(() => {
        busy = false;
        if (closed) { finish(); done(); }
      }, error => { finish(); stop(); reject(error); });
    });
  });
}

main().catch(() => {
  process.stdin.destroy();
  process.stderr.write('Node HTTP replica adapter failed\n');
  process.exitCode = 2;
});
