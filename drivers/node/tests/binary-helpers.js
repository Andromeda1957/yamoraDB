import tls from 'node:tls';
import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { certificates, listen, scratch, READ, WRITE } from './helpers.js';
import { BinaryClient, Client } from '../index.js';

export function independentBytes(value, encoding = 'utf8') {
  const bytes = typeof value === 'string' ? Buffer.from(value, encoding) : value;
  const out = Buffer.alloc(bytes.length); out.set(bytes); return out;
}
export function sourceEtag(bytes = SOURCE) {
  let hash = 1469598103934665603n;
  for (const byte of bytes) hash = BigInt.asUintN(64, (hash ^ BigInt(byte)) * 1099511628211n);
  return hash.toString(16).padStart(16, '0');
}
export const ID = '112233445566778899aabbccddeeff00';
export const REV = '0123456789abcdef';
export const SOURCE = independentBytes('# café\r\nvalue: 01 # inline\r\ntext: λ\r\n');
export const ETAG = sourceEtag();
export { certificates, READ, WRITE };
// These literal vectors and encoder belong to the independent test peer. Never
// import the production codec here, nor ask the native codec to encode its oracle.
export const HELLO = independentBytes('594d424601010000000000000000000c000100010001000000000001', 'hex');
export const END = independentBytes('594d4246010500000000000100000000', 'hex');
export function wire(type, stream, payload = Buffer.alloc(0)) {
  const bytes = Buffer.alloc(16 + payload.length);
  bytes.write('YMBF'); bytes[4] = 1; bytes[5] = type;
  bytes.writeUInt32BE(stream, 8); bytes.writeUInt32BE(payload.length, 12); payload.copy(bytes, 16); return bytes;
}
export function number(n, width) { const b = Buffer.alloc(width); if (width === 8) b.writeBigUInt64BE(BigInt(n)); else b.writeUIntBE(n, 0, width); return b; }
export function tlv(fields) {
  return Buffer.concat([number(1, 2), number(fields.length, 2), ...fields.flatMap(([id, value]) => [number(id, 2), number(value.length, 2), value])]);
}
export function fields(bytes) {
  const result = new Map(); let offset = 4;
  for (let i = 0; i < bytes.readUInt16BE(2); i++) {
    const id = bytes.readUInt16BE(offset), size = bytes.readUInt16BE(offset + 2); offset += 4;
    result.set(id, Buffer.from(bytes.subarray(offset, offset + size))); offset += size;
  }
  return result;
}
export function replyFields({ status = 200, body = SOURCE, representation = body.length, method = 1, id = ID, revision = REV, etag = ETAG } = {}) {
  const out = [[1, number(status, 2)], [2, Buffer.from(method <= 2 ? 'application/yaml' : 'application/json')],
    [3, number(body.length, 8)], [4, number(representation, 8)], [5, Buffer.from(revision)], [6, Buffer.from(`"${etag}"`)],
    [7, Buffer.from('a')], [8, Buffer.from('b')], [12, Buffer.from(id, 'hex')]];
  return out;
}
export function reply(options = {}) {
  const body = options.body ?? SOURCE;
  return Buffer.concat([wire(3, 1, tlv(replyFields({ ...options, body }))), ...(body.length ? [wire(4, 1, body)] : []), END]);
}
export function mutationBody(extra = {}) { return Buffer.from(JSON.stringify({ status: 'stored', collection: 'a', document: 'b', etag: ETAG, revision: REV, ...extra })); }
export async function peer(t, handler, { pem, hello = HELLO, server = {}, timeoutMs = 2000, onRequest, ...config } = {}) {
  pem ??= (await certificates(t)).pem;
  const sockets = new Set(); let connections = 0;
  const listener = tls.createServer({ cert: pem['server.pem'], key: pem['server.key'], minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', ALPNProtocols: ['yamora-binary/1'], ...server }, socket => {
    socket.on('error', () => {});
    if (hello) socket.write(hello);
    let pending = Buffer.alloc(0), request, parts = [], frames = [];
    socket.on('data', chunk => {
      pending = Buffer.concat([pending, chunk]);
      while (pending.length >= 16 && pending.length >= 16 + pending.readUInt32BE(12)) {
        const kind = pending[5], size = pending.readUInt32BE(12), bytes = Buffer.from(pending.subarray(16, 16 + size));
        pending = pending.subarray(16 + size); frames.push([kind, size]);
        if (kind === 2) { request = fields(bytes); onRequest?.(socket, request); }
        if (kind === 4) parts.push(bytes);
        if (kind === 5) Promise.resolve(handler(socket, request, Buffer.concat(parts), frames)).catch(error => socket.destroy(error));
      }
    });
  });
  listener.on('connection', socket => { connections++; sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  listener.on('tlsClientError', () => {});
  listener.closeAllConnections = () => { for (const socket of sockets) socket.destroy(); };
  const address = await listen(t, listener);
  const opts = { ...address, servername: address.host, tls: { ca: pem['ca.pem'] }, timeoutMs, ...config };
  return { address, pem, listener, config: opts, client: new BinaryClient(opts), connections: () => connections, sockets };
}
export const NATIVE = process.env.YAMORA_BINARY_NATIVE ?? process.env.YAMORA_TEST_BINARY;
export async function native(t, { mtls = false, legacy = false, policy = false } = {}) {
  // Missing dependencies are failures, including in the existing Node test glob.
  if (!NATIVE) throw new Error('set YAMORA_BINARY_NATIVE to the read-only integrated native sanitizer executable');
  const before = createHash('sha256').update(await readFile(NATIVE)).digest('hex');
  const root = await scratch(t, false), cert = await certificates(t);
  const database = join(root, 'data'); let child, exited, errors = '';
  const env = { ...process.env, TMPDIR: root,
    ASAN_OPTIONS: 'detect_leaks=1:halt_on_error=1:abort_on_error=1', UBSAN_OPTIONS: 'halt_on_error=1:print_stacktrace=1' };
  t.after(async () => {
    let force;
    try {
      if (child && exited) {
        if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
        force = setTimeout(() => child.kill('SIGKILL'), 10000);
        const [code, signal] = await exited;
        if (code !== 0 || signal || /Sanitizer|runtime error:/.test(errors)) throw new Error(`native failure: ${code}/${signal} ${errors}`);
      }
      const after = createHash('sha256').update(await readFile(NATIVE)).digest('hex');
      if (before !== after) throw new Error('read-only native executable digest changed');
    } finally { clearTimeout(force); await rm(root, { recursive: true, force: true }); }
  });
  await mkdir(database, { mode: 0o700 });
  await writeFile(join(root, 'read'), READ, { mode: 0o600 }); await writeFile(join(root, 'write'), WRITE, { mode: 0o600 });
  const init = spawnSync(NATIVE, ['--data-dir', database, '--init-disk', '--validate-only'], { timeout: 20000, encoding: 'utf8', env });
  if (init.status !== 0 || /Sanitizer|runtime error:/.test(init.stderr)) throw new Error(`native init failed: ${init.error ?? init.stderr}`);
  if (legacy) {
    const path = join(database, '.yamora-disk'), bytes = await readFile(path);
    const crc32c = data => { let crc = 0xffffffff; for (const b of data) { crc ^= b; for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ ((crc & 1) ? 0x82f63b78 : 0); } return (~crc) >>> 0; };
    for (const offset of [0, 4096]) { bytes.write('YAMDIS04', offset); bytes.writeUInt32LE(crc32c(bytes.subarray(offset, offset + 4092)), offset + 4092); }
    await writeFile(path, bytes);
  }
  const args = ['--data-dir', database, '--port', '0', '--binary-port', '0', '--auth-token-file', join(root, 'read'), '--write-auth-token-file', join(root, 'write'),
    '--tls-cert-file', join(cert.root, 'server.pem'), '--tls-key-file', join(cert.root, 'server.key'), '--io-timeout-ms', '10000'];
  if (mtls) args.push('--tls-client-ca-file', join(cert.root, 'ca.pem'));
  const scoped = 'scoped-' + 's'.repeat(32);
  if (policy) {
    await writeFile(join(root, 'scope'), scoped, { mode: 0o600 });
    await writeFile(join(root, 'access.yaml'), JSON.stringify({ version: 1, roles: { one: { read: ['allowed'], write: ['allowed'] } }, principals: { one: { token_file: join(root, 'scope'), roles: ['one'] } } }), { mode: 0o600 });
    args.push('--access-policy-file', join(root, 'access.yaml'));
  }
  child = spawn(NATIVE, args, { cwd: root, env, stdio: ['ignore', 'pipe', 'pipe'] });
  exited = new Promise(resolve => { child.once('exit', (code, signal) => resolve([code, signal])); child.once('error', () => resolve([-1, 'spawn'])); });
  child.stderr.on('data', chunk => { errors = (errors + chunk.toString()).slice(-16000); });
  let timer;
  const ports = await Promise.race([new Promise((resolve, reject) => {
    let banner = ''; const found = {};
    child.once('error', reject);
    child.stdout.on('data', chunk => {
      banner += chunk.toString(); if (banner.length > 8192) { reject(new Error('unbounded startup')); return; }
      for (const match of banner.matchAll(/^(yamora|binary) listening on 127\.0\.0\.1:(\d+)/gm)) found[match[1]] = Number(match[2]);
      if (found.yamora && found.binary) resolve(found);
    });
  }), exited.then(() => { throw new Error(`native exited during startup: ${errors}`); }), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('native startup timeout')), 15000); })]).finally(() => clearTimeout(timer));
  if (Object.values(ports).includes(8000)) throw new Error('owner port allocated');
  const tlsOptions = { ca: cert.pem['ca.pem'], ...(mtls ? { cert: cert.pem['client.pem'], key: cert.pem['client.key'] } : {}) };
  const config = { host: '127.0.0.1', port: ports.binary, servername: '127.0.0.1', tls: tlsOptions, timeoutMs: 30000 };
  return { config, client: new BinaryClient(config), pem: cert.pem, scoped, http: new Client({ host: config.host, port: ports.yamora, tls: tlsOptions, readToken: READ, writeToken: WRITE, timeoutMs: 30000, maxDocumentBytes: 16 * 1024 * 1024 }) };
}
