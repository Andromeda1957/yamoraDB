import net from 'node:net';
import { spawn, spawnSync } from 'node:child_process';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as pause } from 'node:timers/promises';
import { configuration, request } from '../lib/transport.js';
import { binary, certificates, scratch, listen, READ, WRITE } from './helpers.js';

export async function nativeCluster(t) {
  const tls = await certificates(t);
  const root = await scratch(t, false);
  const nodes = [];
  const reservations = [];
  t.after(async () => {
    try {
      const failures = [];
      for (const reservation of reservations) reservation.close();
      for (const node of nodes) {
        try { await stop(node.index); } catch (error) { failures.push(error); }
      }
      if (failures.length) throw new AggregateError(failures, 'native cluster teardown failed');
    } finally { await rm(root, { recursive: true, force: true }); }
  });
  async function file(name, content) {
    const path = join(root, name); await writeFile(path, content, { mode: 0o600 }); return path;
  }
  const peers = [];
  for (let i = 0; i < 3; i++) {
    const reservation = net.createServer();
    const address = await listen({ after() {} }, reservation);
    reservations.push(reservation);
    peers.push({ id: i + 1, name: `node${i + 1}.test`, address: address.host, port: address.port });
  }
  const read = await file('read.token', READ), write = await file('write.token', WRITE);
  const seeds = [];
  const tlsOptions = { ca: tls.pem['ca.pem'], cert: tls.pem['client.pem'], key: tls.pem['client.key'] };
  for (let i = 0; i < 3; i++) {
    const name = `node${i + 1}`;
    const run = args => {
      const result = spawnSync('openssl', args, { cwd: root, timeout: 15000, encoding: 'utf8' });
      if (result.status !== 0) throw new Error(`peer certificate failed: ${result.error?.code ?? result.stderr}`);
    };
    run(['req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', `${name}.key`, '-out', `${name}.csr`, '-subj', `/CN=${name}.test`]);
    const ext = await file(`${name}.ext`, `basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:${name}.test,IP:127.0.0.1\n`);
    run(['x509', '-req', '-in', `${name}.csr`, '-CA', join(tls.root, 'ca.pem'), '-CAkey', join(tls.root, 'ca.key'), '-set_serial', String(i + 10), '-out', `${name}.pem`, '-days', '1', '-extfile', ext]);
    const data = join(root, `data${i}`), journal = join(root, `journal${i}`);
    await mkdir(data, { mode: 0o700 }); await mkdir(journal, { mode: 0o700 });
    const spec = await file(`config${i}.json`, JSON.stringify({
      cluster: '01020304000000000000000000000000', node: i + 1, journal_dir: journal,
      peer_tls: { cert_file: join(root, `${name}.pem`), key_file: join(root, `${name}.key`), ca_file: join(tls.root, 'ca.pem') },
      peers, request_timeout_ms: 3000, journal_cache_bytes: 1048576
    }));
    const args = ['--data-dir', data, '--port', '0', '--workers', '4', '--cluster-config-file', spec,
      '--auth-token-file', read, '--write-auth-token-file', write, '--cache-bytes', '1048576',
      '--tls-cert-file', join(tls.root, 'server.pem'), '--tls-key-file', join(tls.root, 'server.key'),
      '--tls-client-ca-file', join(tls.root, 'ca.pem'), '--io-timeout-ms', '3000'];
    nodes.push({ index: i, args, child: null, stderr: '' });
  }
  for (const reservation of reservations) await new Promise(resolve => reservation.close(resolve));
  reservations.length = 0;
  for (const node of nodes) {
    const child = spawn(binary, node.args, { cwd: root, env: { ...process.env, TMPDIR: root }, stdio: ['ignore', 'pipe', 'pipe'] });
    node.child = child;
    child.stderr.on('data', chunk => { node.stderr = (node.stderr + chunk).slice(-32000); });
    node.exited = new Promise(resolve => {
      child.once('exit', (code, signal) => resolve({ code, signal }));
      child.once('error', () => resolve({ code: null, signal: 'spawn_error' }));
    });
    let timer;
    try {
      seeds.push(await Promise.race([
        new Promise(resolve => {
          let banner = '';
          child.stdout.on('data', chunk => {
            banner += chunk;
            const match = /^yamora listening on (127\.0\.0\.1):([0-9]+) /.exec(banner);
            if (match) resolve({ host: match[1], port: Number(match[2]) });
          });
        }),
        node.exited.then(result => { throw new Error(`native startup failed: ${JSON.stringify(result)} ${node.stderr}`); }),
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('native startup timed out')), 15000); })
      ]));
      if (seeds.at(-1).port === 8000) throw new Error('native member allocated owner port');
    } finally { clearTimeout(timer); }
  }
  async function stop(index, crash = false) {
    const node = nodes[index];
    if (!node.child) return;
    node.child.kill(crash ? 'SIGKILL' : 'SIGTERM');
    let force;
    try {
      force = setTimeout(() => node.child?.kill('SIGKILL'), 5000);
      const result = await node.exited;
      node.child = null;
      if ((crash ? result.signal !== 'SIGKILL' : result.code !== 0) || /AddressSanitizer|LeakSanitizer|runtime error:/.test(node.stderr))
        throw new Error(`native member ${index} failed: ${JSON.stringify(result)} ${node.stderr}`);
    } finally { clearTimeout(force); }
  }
  const config = { seeds, tls: tlsOptions, readToken: READ, writeToken: WRITE, timeoutMs: 20000 };
  const endpoints = seeds.map(seed => configuration({ ...seed, tls: tlsOptions, readToken: READ, writeToken: WRITE, timeoutMs: 500 }));
  async function leader() {
    const deadline = performance.now() + 15000;
    while (performance.now() < deadline) {
      for (let i = 0; i < nodes.length; i++) {
        if (!nodes[i].child) continue;
        try {
          const response = await request(endpoints[i], 'GET', '/v1/cluster/leader', undefined, {}, false, {});
          if (JSON.parse(response.body).role === 'leader') return i;
        } catch { /* Elections and stopped endpoints are expected here. */ }
      }
      await pause(25);
    }
    throw new Error('native leader election timed out');
  }
  await leader();
  return { config, tls, stop, leader, endpoints, nodes };
}
