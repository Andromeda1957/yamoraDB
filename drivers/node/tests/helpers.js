import http from 'node:http';
import net from 'node:net';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { Client } from '../index.js';

export const REV = '0123456789abcdef';
export const READ = 'r'.repeat(32);
export const WRITE = 'w'.repeat(32);
export const binary = process.env.YAMORA_TEST_BINARY;
export const CATALOG_INDEX = { collection: 'a', name: 'n', fields: ['n'] };
export const CATALOG_RECEIPT = { status: 'committed', operations: 1, revision: REV };
export const INVALID_CATALOG_RECEIPTS = [
  ['failed', { status: 'failed', operations: 0, revision: REV }],
  ['wrong count', { ...CATALOG_RECEIPT, operations: 2 }],
  ['string count', { ...CATALOG_RECEIPT, operations: '1' }],
  ['boolean count', { ...CATALOG_RECEIPT, operations: true }],
  ['array count', { ...CATALOG_RECEIPT, operations: [1] }],
  ['numeric status', { ...CATALOG_RECEIPT, status: 1 }],
  ['array status', { ...CATALOG_RECEIPT, status: ['committed'] }],
  ['missing status', { operations: 1, revision: REV }],
  ['missing count', { status: 'committed', revision: REV }],
  ['revision only', { revision: REV }]
];
export function catalogMutations() {
  return [
    ['setIndexes', client => client.setIndexes([CATALOG_INDEX])],
    ['createIndex', client => client.createIndex(CATALOG_INDEX)],
    ['dropIndex', client => client.dropIndex(CATALOG_INDEX.collection, CATALOG_INDEX.name)]
  ];
}

export function json(res, value, revision = REV, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'X-YamlDB-Revision': revision });
  res.end(typeof value === 'string' ? value : JSON.stringify(value));
}

export async function listen(t, server) {
  // Never use the owner's 8000 port, even if the OS happened to allocate it.
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  if (server.address().port === 8000) { await new Promise(resolve => server.close(resolve)); return listen(t, server); }
  t.after(async () => { server.closeAllConnections?.(); await new Promise(resolve => server.close(resolve)); });
  return { host: '127.0.0.1', port: server.address().port };
}
export async function httpFixture(t, handler, options = {}) {
  const address = await listen(t, http.createServer(handler));
  return { address, client: new Client({ ...address, ...options }) };
}
export async function rawFixture(t, reply, options = {}) {
  let connections = 0;
  const sockets = new Set();
  const server = net.createServer(socket => {
    connections++;
    sockets.add(socket); socket.on('close', () => sockets.delete(socket));
    socket.once('data', () => reply(socket));
  });
  const address = await listen(t, server);
  t.after(() => { for (const socket of sockets) socket.destroy(); });
  // Close active sockets before the listen cleanup waits for server.close.
  server.closeAllConnections = () => { for (const socket of sockets) socket.destroy(); };
  return { address, client: new Client({ ...address, ...options }), connections: () => connections };
}
export async function scratch(t, cleanup = true) {
  const validation = spawnSync('python3', ['-c',
    'import json, os; from tools.ci.yamora_driver_ci.runner import scratch_parent; print(json.dumps(str(scratch_parent(os.environ["TMPDIR"]))))'
  ], { encoding: 'utf8', timeout: 15000, env: process.env });
  if (validation.status !== 0) throw new Error(`TMPDIR must name an existing owned disk-backed managed directory: ${validation.error?.code ?? validation.stderr}`);
  const root = JSON.parse(validation.stdout);
  const folder = await mkdtemp(join(root, 'node-'));
  if (cleanup) t.after(() => rm(folder, { recursive: true, force: true }));
  return folder;
}
export async function certificates(t) {
  const root = await scratch(t);
  function openssl(args) {
    const run = spawnSync('openssl', args, { cwd: root, timeout: 15000, encoding: 'utf8', env: { ...process.env, TMPDIR: root } });
    if (run.status !== 0) throw new Error(`openssl failed: ${run.error?.code ?? run.stderr}`);
  }
  openssl(['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1', '-subj', '/CN=Node test CA', '-addext', 'basicConstraints=critical,CA:TRUE']);
  for (const [name, usage, ip] of [['server', 'serverAuth', '127.0.0.1'], ['wrong', 'serverAuth', '127.0.0.2'], ['client', 'clientAuth', '127.0.0.1']]) {
    openssl(['req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', `${name}.key`, '-out', `${name}.csr`, '-subj', `/CN=${name}`]);
    await writeFile(join(root, `${name}.ext`), `basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=${usage}\nsubjectAltName=IP:${ip}\n`, { mode: 0o600 });
    openssl(['x509', '-req', '-in', `${name}.csr`, '-CA', 'ca.pem', '-CAkey', 'ca.key', '-set_serial', String(name === 'server' ? 2 : name === 'wrong' ? 3 : 4), '-out', `${name}.pem`, '-days', '1', '-extfile', `${name}.ext`]);
  }
  const pem = {};
  for (const name of ['ca.pem', 'server.pem', 'server.key', 'wrong.pem', 'wrong.key', 'client.pem', 'client.key']) pem[name] = await readFile(join(root, name));
  return { root, pem };
}

export async function daemon(t, tls) {
  const root = await scratch(t, false);
  let child;
  let exited;
  let stderr = '';
  // Register before initialization so failures at every setup stage clean up.
  t.after(async () => {
    let timer;
    let forced;
    try {
      if (!child || !exited) return;
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
      forced = setTimeout(() => child.kill('SIGKILL'), 5000);
      const result = await Promise.race([exited, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('daemon did not exit')), 10000); })]);
      if (result.code !== 0 || /ERROR: AddressSanitizer|runtime error:|LeakSanitizer/.test(stderr)) throw new Error(`daemon failed: ${JSON.stringify(result)} ${stderr}`);
    } finally { clearTimeout(timer); clearTimeout(forced); await rm(root, { recursive: true, force: true }); }
  });
  const database = join(root, 'database');
  await mkdir(database, { mode: 0o700 });
  await writeFile(join(root, 'read.token'), READ, { mode: 0o600 });
  await writeFile(join(root, 'write.token'), WRITE, { mode: 0o600 });
  const init = spawnSync(binary, ['--data-dir', database, '--init-disk', '--validate-only'], { timeout: 15000, encoding: 'utf8', env: { ...process.env, TMPDIR: root } });
  if (init.status !== 0) throw new Error(`daemon initialization failed: ${init.error?.code ?? init.stderr}`);
  const args = ['--data-dir', database, '--port', '0', '--auth-token-file', join(root, 'read.token'), '--write-auth-token-file', join(root, 'write.token')];
  if (tls) args.push('--tls-cert-file', join(tls.root, 'server.pem'), '--tls-key-file', join(tls.root, 'server.key'), '--tls-client-ca-file', join(tls.root, 'ca.pem'));
  child = spawn(binary, args, { cwd: root, env: { ...process.env, TMPDIR: root }, stdio: ['ignore', 'pipe', 'pipe'] });
  child.stderr.on('data', chunk => { stderr = (stderr + chunk.toString()).slice(-16000); });
  exited = new Promise(resolve => {
    child.once('exit', (code, signal) => resolve({ code, signal }));
    child.once('error', () => resolve({ code: null, signal: 'spawn_error' }));
  });
  let timer;
  const address = await Promise.race([
    new Promise((resolve, reject) => {
      let banner = '';
      child.once('error', reject);
      child.stdout.on('data', chunk => {
        banner += chunk.toString();
        const match = /^yamora listening on (127\.0\.0\.1):([0-9]+) /.exec(banner);
        if (match) resolve({ host: match[1], port: Number(match[2]) });
      });
    }),
    exited.then(result => { throw new Error(`daemon exited before ready: ${JSON.stringify(result)} ${stderr}`); }),
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('daemon startup timed out')), 15000); })
  ]).finally(() => clearTimeout(timer));
  if (address.port === 8000) throw new Error('daemon allocated owner port');
  const config = { ...address, readToken: READ, writeToken: WRITE, timeoutMs: 15000,
    ...(tls ? { tls: { ca: tls.pem['ca.pem'], cert: tls.pem['client.pem'], key: tls.pem['client.key'] } } : {}) };
  return { client: new Client(config), config };
}
