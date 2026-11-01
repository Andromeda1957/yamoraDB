import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getEventListeners } from 'node:events';
import { inspect } from 'node:util';
import { setTimeout as pause } from 'node:timers/promises';
import net from 'node:net';
import { BinaryClient, BinaryUncertainWriteError, YamoraError } from '../index.js';
import { peer, certificates, ID, REV, ETAG, sourceEtag, SOURCE, END, wire, number, tlv, reply, replyFields, mutationBody } from './binary-helpers.js';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { listen } from './helpers.js';

const call = { token: 'synthetic-secret', requestId: ID };

test('binary independent TLS peer: fragmented exact YAML, HEAD and 204; one socket per call', async t => {
  let count = 0;
  const fixture = await peer(t, async (socket, request, body) => {
    count++;
    assert.equal(request.get(5).toString(), `Bearer ${call.token}`);
    assert.equal(request.get(8).toString('hex'), ID);
    const method = request.get(1)[0];
    const data = method === 1 ? SOURCE : method === 3 ? mutationBody() : Buffer.alloc(0);
    if (method === 3) assert.deepEqual(body, SOURCE);
    const answer = reply({ method, status: method === 4 ? 204 : 200, body: data, representation: method === 2 ? SOURCE.length : data.length });
    for (let i = 0; i < answer.length; i += 3) { socket.write(answer.subarray(i, i + 3)); await pause(1); }
  });
  assert.deepEqual((await fixture.client.get('a', 'b', call)).source, SOURCE);
  assert.equal((await fixture.client.head('a', 'b', call)).representationLength, SOURCE.length);
  assert.equal((await fixture.client.put('a', 'b', SOURCE, call)).etag, ETAG);
  assert.equal((await fixture.client.delete('a', 'b', call)).revision, REV);
  assert.equal(count, 4); assert.equal(fixture.connections(), 4);
});

test('binary trust and options are owned; rejects opaque TLS hooks, public endpoints and invalid IDs', async t => {
  const { pem } = await certificates(t);
  const fixture = await peer(t, socket => socket.end(reply()), { pem });
  const copied = { ...fixture.config, tls: { ca: Buffer.from(pem['ca.pem']) } };
  const client = new BinaryClient(copied); copied.tls.ca.fill(0); copied.host = '8.8.8.8';
  assert.deepEqual((await client.get('a', 'b', call)).source, SOURCE);
  for (const change of [{ host: 'localhost' }, { host: '8.8.8.8' }, { servername: '' }, { maxConcurrentCalls: 5 }, { maxFrameBytes: 4095 },
    { tls: { ca: pem['ca.pem'], checkServerIdentity() {} } }, { tls: { ca: 'garbage' } }, { tls: { ca: pem['ca.pem'], cert: pem['client.pem'] } }]) assert.throws(() => new BinaryClient({ ...fixture.config, ...change }), TypeError);
  for (const requestId of ['', '0'.repeat(32), ID.toUpperCase(), 'z'.repeat(32)]) await assert.rejects(client.put('a', 'b', SOURCE, { ...call, requestId }), TypeError);
  await assert.rejects(client.put('a', 'b', new Uint8Array(new SharedArrayBuffer(32)), call), TypeError);
  await assert.rejects(client.get('../a', 'b', call), TypeError);
  await assert.rejects(client.put('a', 'b', '\ud800', call), TypeError);
});

test('binary verified TLS identity, trust, ALPN, TLS1.3, and optional mTLS fail closed', async t => {
  const { pem } = await certificates(t);
  for (const server of [{ ALPNProtocols: ['http/1.1'] }, { cert: pem['wrong.pem'], key: pem['wrong.key'] },
    { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' }, { ca: pem['ca.pem'], requestCert: true, rejectUnauthorized: true }]) {
    const fixture = await peer(t, socket => socket.end(reply()), { pem, server });
    await assert.rejects(fixture.client.get('a', 'b', call), error => error instanceof YamoraError && !error.uncertain);
  }
  const fixture = await peer(t, socket => socket.end(reply()), { pem, server: { ca: pem['ca.pem'], requestCert: true, rejectUnauthorized: true }, tls: { ca: pem['ca.pem'], cert: pem['client.pem'], key: pem['client.key'] } });
  assert.deepEqual((await fixture.client.get('a', 'b', call)).source, SOURCE);
  const material = { ca: Buffer.from(pem['ca.pem']), cert: Buffer.from(pem['client.pem']), key: Buffer.from(pem['client.key']) };
  const copied = new BinaryClient({ ...fixture.config, tls: material });
  for (const bytes of Object.values(material)) bytes.fill(0);
  assert.deepEqual((await copied.get('a', 'b', call)).source, SOURCE);
  const old = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  try {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    const wrong = new BinaryClient({ ...fixture.config, servername: 'untrusted.example' });
    await assert.rejects(wrong.get('a', 'b', call), error => !error.uncertain);
  } finally { if (old === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED; else process.env.NODE_TLS_REJECT_UNAUTHORIZED = old; }
});

test('binary dispatched ambiguity: partial, malformed, wrong identity/ID, ERROR, GOAWAY and EOF never replay', async t => {
  const invalidReceipt = mutationBody({ document: 'other' });
  const cases = [
    ['partial receipt', reply({ method: 3, body: mutationBody() }).subarray(0, -18)],
    ['semantic receipt', reply({ method: 3, body: invalidReceipt })],
    ['wrong ID', reply({ method: 3, body: mutationBody(), id: 'aa'.repeat(16) })],
    ['oversized acknowledgement', wire(3, 1, tlv(replyFields({ method: 3, body: Buffer.alloc(4097) })))],
    ['ERROR1', wire(7, 1, number(1, 4))], ['GOAWAY', wire(10, 0)], ['EOF', Buffer.alloc(0)],
    ['wrong stream', Buffer.from('594d4246010300000000000300000001ff', 'hex')],
    ['advertised huge frame', Buffer.from('594d42460104000000000001ffffffff', 'hex')],
    ['repeated RESPONSE', Buffer.concat([wire(3, 1, tlv(replyFields({ method: 3, body: mutationBody() }))), reply({ method: 3, body: mutationBody() })])],
    ['DATA before RESPONSE', wire(4, 1, Buffer.from('x'))],
    ['missing END', reply({ method: 3, body: mutationBody() }).subarray(0, -16)],
    ['trailing frame', Buffer.concat([reply({ method: 3, body: mutationBody() }), END])]
  ];
  const { pem } = await certificates(t);
  for (const [label, answer] of cases) await t.test(label, async sub => {
    const fixture = await peer(sub, async socket => {
      for (let i = 0; i < answer.length; i += 7) { socket.write(answer.subarray(i, i + 7)); await pause(1); }
      socket.end();
    }, { pem });
    const source = Buffer.from(SOURCE), opts = { ...call, ifMatch: `"${REV}"` };
    const pending = fixture.client.put('a', 'b', source, opts);
    source.fill(0); opts.requestId = 'aa'.repeat(16); opts.ifMatch = '*';
    await assert.rejects(pending, error => {
      assert.ok(error instanceof BinaryUncertainWriteError, `uncertainty invariant: ${label}`);
      assert.equal(error.uncertain, true); assert.equal(error.requestId, ID);
      assert.deepEqual(error.envelope.source, SOURCE);
      const copy = error.envelope.source; copy.fill(0); assert.deepEqual(error.envelope.source, SOURCE);
      assert.equal(error.envelope.conditions.ifMatch, `"${REV}"`);
      assert.ok(Object.isFrozen(error.envelope) && Object.isFrozen(error.envelope.conditions));
      assert.ok(!JSON.stringify(error).includes(call.token) && !inspect(error).includes(call.token));
      assert.ok(!JSON.stringify(error).includes('café') && !inspect(error).includes('café'));
      return true;
    });
    assert.equal(fixture.connections(), 1, 'automatic replay invariant');
  });
});

test('binary absolute deadline and cancellation span HELLO, fragmented response and admission', async t => {
  const { pem } = await certificates(t);
  let reached = 0;
  const fixture = await peer(t, () => { reached++; }, { pem, timeoutMs: 160, maxConcurrentCalls: 1 });
  const abort = new AbortController();
  const first = fixture.client.put('a', 'b', SOURCE, { ...call, signal: abort.signal, timeoutMs: 1000 });
  const firstFailure = assert.rejects(first, error => error instanceof BinaryUncertainWriteError && error.code === 'ABORT_ERR');
  while (reached === 0) await pause(2);
  const large = Buffer.alloc(16 * 1024 * 1024, 32);
  let copies = 0;
  const original = Buffer.alloc;
  t.mock.method(Buffer, 'alloc', function (...args) { if (args[0] === large.length) copies++; return Reflect.apply(original, Buffer, args); });
  const waitingAbort = new AbortController();
  const waiters = Array.from({ length: 8 }, (_, index) => fixture.client.put('a', 'b', large, { ...call, timeoutMs: 60, ...(index % 2 ? { signal: waitingAbort.signal } : {}) }));
  const waiterFailures = waiters.map(p => assert.rejects(p, error => !error.uncertain && ['ABORT_ERR', 'TIMEOUT'].includes(error.code)));
  waitingAbort.abort(); await Promise.all(waiterFailures);
  assert.equal(copies, 0, 'admission copy invariant'); assert.equal(fixture.connections(), 1);
  assert.equal(getEventListeners(waitingAbort.signal, 'abort').length, 0);
  abort.abort(); await firstFailure;
  assert.equal(getEventListeners(abort.signal, 'abort').length, 0);
  await assert.rejects(fixture.client.put('a', 'b', SOURCE, call), error => error instanceof BinaryUncertainWriteError && error.code === 'TIMEOUT');
  assert.equal(fixture.connections(), 2, 'capacity release invariant');
  const stalledHello = await peer(t, () => {}, { pem, hello: null, timeoutMs: 60 });
  await assert.rejects(stalledHello.client.put('a', 'b', SOURCE, call), error => error.code === 'TIMEOUT' && !error.uncertain);
  const trickle = await peer(t, async socket => { const answer = reply(); for (const byte of answer) { if (socket.destroyed) break; socket.write(Buffer.from([byte])); await pause(5); } }, { pem, timeoutMs: 80 });
  await assert.rejects(trickle.client.get('a', 'b', call), error => error.code === 'TIMEOUT');
});

test('binary cancellation and deadline bound TCP/TLS; callbacks and owned sockets are joined', async t => {
  const sockets = new Set();
  const server = net.createServer(socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); socket.on('data', () => {}); });
  server.closeAllConnections = () => { for (const socket of sockets) socket.destroy(); };
  const address = await listen(t, server), { pem } = await certificates(t);
  const client = new BinaryClient({ ...address, servername: address.host, tls: { ca: pem['ca.pem'] }, timeoutMs: 60 });
  for (let i = 0; i < 3; i++) {
    const controller = new AbortController();
    const result = client.put('a', 'b', SOURCE, { ...call, signal: controller.signal });
    const rejected = assert.rejects(result, error => !error.uncertain && error.code === (i === 0 ? 'TIMEOUT' : 'ABORT_ERR'));
    if (i !== 0) { await pause(10); controller.abort(); }
    await rejected;
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  }
});

test('binary queued successful call snapshots only on admission, retains cancellation isolation', async t => {
  const held = [], requests = [], { pem } = await certificates(t);
  const fixture = await peer(t, (socket, fields, source) => { requests.push(source); held.push(socket); }, { pem, maxConcurrentCalls: 1 });
  const firstAbort = new AbortController(), secondAbort = new AbortController();
  const first = fixture.client.put('a', 'b', SOURCE, { ...call, signal: firstAbort.signal });
  const failed = assert.rejects(first, error => error instanceof BinaryUncertainWriteError);
  while (!held.length) await pause(2);
  const source = Buffer.from(SOURCE);
  const second = fixture.client.put('a', 'b', source, { ...call, signal: secondAbort.signal });
  source.fill(32); // Waiting calls snapshot on admission, rather than on enqueue.
  firstAbort.abort(); await failed;
  while (held.length < 2) await pause(2);
  assert.deepEqual(requests[1], source);
  assert.equal(held[1].destroyed, false, 'cancellation closes only its own socket');
  const tag = sourceEtag(requests[1]);
  held[1].end(reply({ method: 3, etag: tag, body: mutationBody({ etag: tag }) }));
  assert.equal((await second).status, 'stored');
  assert.equal(getEventListeners(firstAbort.signal, 'abort').length, 0);
  assert.equal(getEventListeners(secondAbort.signal, 'abort').length, 0);
});

test('binary pre-dispatch cancellation and validation release capacity without opening a socket', async t => {
  const fixture = await peer(t, socket => socket.end(reply()), { maxConcurrentCalls: 1 });
  const aborted = new AbortController(); aborted.abort();
  await assert.rejects(fixture.client.put('a', 'b', SOURCE, { ...call, signal: aborted.signal }), error => error.code === 'ABORT_ERR' && !error.uncertain);
  await assert.rejects(fixture.client.put('a', 'b', Buffer.from([0xff]), call), TypeError);
  assert.equal(fixture.connections(), 0);
  assert.deepEqual((await fixture.client.get('a', 'b', call)).source, SOURCE);
});

test('binary DNS servername verifies certificate independently of the numeric endpoint', async t => {
  const cert = await certificates(t);
  const extension = join(cert.root, 'dns.ext'), output = join(cert.root, 'dns.pem');
  await writeFile(extension, 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:database.internal\n');
  const signed = spawnSync('openssl', ['x509', '-req', '-in', join(cert.root, 'server.csr'), '-CA', join(cert.root, 'ca.pem'), '-CAkey', join(cert.root, 'ca.key'), '-set_serial', '17', '-out', output, '-days', '1', '-extfile', extension], { encoding: 'utf8', timeout: 15000 });
  assert.equal(signed.status, 0, signed.stderr);
  const pem = { ...cert.pem, 'server.pem': await readFile(output) };
  let sni;
  const fixture = await peer(t, socket => { sni = socket.servername; socket.end(reply()); }, { pem, servername: 'database.internal' });
  assert.deepEqual((await fixture.client.get('a', 'b', call)).source, SOURCE);
  assert.equal(sni, 'database.internal');
  const wrong = new BinaryClient({ ...fixture.config, servername: 'different.internal' });
  await assert.rejects(wrong.get('a', 'b', call), error => error.code === 'ERR_TLS_CERT_ALTNAME_INVALID');
});

test('binary cancellation joins a backpressured fragmented16MiB sender and releases capacity', { timeout: 15000 }, async t => {
  let observed;
  const dispatched = new Promise(resolve => { observed = resolve; });
  const fixture = await peer(t, socket => socket.end(reply()), {
    maxConcurrentCalls: 1, maxFrameBytes: 4096, timeoutMs: 5000,
    onRequest(socket, fields) { if (fields.get(1)[0] === 3) { socket.pause(); observed(); } }
  });
  const source = Buffer.alloc(16 * 1024 * 1024, 'x'), abort = new AbortController();
  const pending = fixture.client.put('a', 'b', source, { ...call, signal: abort.signal });
  const rejected = assert.rejects(pending, error => error instanceof BinaryUncertainWriteError && error.code === 'ABORT_ERR' && error.envelope.sourceLength === source.length);
  await dispatched;
  await pause(20); abort.abort(); await rejected;
  assert.equal(getEventListeners(abort.signal, 'abort').length, 0);
  assert.deepEqual((await fixture.client.get('a', 'b', call)).source, SOURCE);
  assert.equal(fixture.connections(), 2);
});
