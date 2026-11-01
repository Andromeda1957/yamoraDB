import { test } from 'node:test';
import assert from 'node:assert/strict';
import tls from 'node:tls';
import { BinaryClient, BinaryUncertainWriteError } from '../index.js';
import { native, ID, SOURCE, READ, WRITE } from './binary-helpers.js';
import { listen } from './helpers.js';

const read = { token: READ }, write = { token: WRITE, requestId: ID };

test('binary native ASan TLS+mTLS: exact source, HTTP interoperability, conditions, roles, HEAD and DELETE204', { timeout: 60000 }, async t => {
  const fixture = await native(t, { mtls: true, policy: true });
  const { client, http, config } = fixture;
  const stored = await client.put('a', 'b', SOURCE, { ...write, ifNoneMatch: '*' });
  assert.equal(stored.status, 'stored');
  const observed = await http.get('a', 'b'); assert.deepEqual(observed.source, SOURCE);
  assert.equal(observed.etag, stored.etag); assert.equal(observed.revision, stored.revision);
  assert.deepEqual((await client.get('a', 'b', read)).source, SOURCE);
  const head = await client.head('a', 'b', read);
  assert.equal(head.representationLength, SOURCE.length); assert.equal(head.etag, stored.etag);
  for (const invoke of [() => client.put('a', 'b', SOURCE, { ...write, ifNoneMatch: '*' }),
    () => client.put('a', 'b', SOURCE, { ...write, ifMatch: '"0000000000000000"' }),
    () => client.delete('a', 'b', { ...write, ifMatch: '"0000000000000000"' })]) {
    await assert.rejects(invoke(), error => error.status === 412 && !error.uncertain);
  }
  const replacement = Buffer.from('# HTTP → binary\r\nvalue: 2\r\n');
  await http.put('a', 'b', replacement, { etag: stored.etag });
  assert.deepEqual((await client.get('a', 'b', read)).source, replacement);
  for (const token of [undefined, 'incorrect', READ]) await assert.rejects(client.put('a', 'b', SOURCE, { token }), error => error.status === 401 && !error.uncertain);
  await assert.rejects(client.get('a', 'b'), error => error.status === 401);
  await assert.rejects(client.head('a', 'b'), error => error.status === 401);
  const scoped = { token: fixture.scoped };
  await client.put('allowed', 'item', SOURCE, scoped);
  assert.deepEqual((await client.get('allowed', 'item', scoped)).source, SOURCE);
  for (const action of ['get', 'put', 'delete']) {
    const result = action === 'put' ? client.put('private', 'item', SOURCE, scoped) : client[action]('private', 'item', scoped);
    await assert.rejects(result, error => error.status === 403 && !error.uncertain);
  }
  const noIdentity = new BinaryClient({ ...config, tls: { ca: config.tls.ca } });
  await assert.rejects(noIdentity.get('a', 'b', read), error => !error.uncertain);
  const latest = await client.get('a', 'b', read);
  const deleted = await client.delete('a', 'b', { ...write, ifMatch: `"${latest.etag}"` });
  assert.match(deleted.revision, /^[0-9a-f]{16}$/);
  await assert.rejects(http.get('a', 'b'), error => error.status === 404);
});

test('binary native ASan: exact 16MiB source over 4KiB frames and immutable legacy256KiB profile', { timeout: 120000 }, async t => {
  const large = await native(t);
  const client = new BinaryClient({ ...large.config, maxFrameBytes: 4096 });
  const prefix = Buffer.from('# café\r\nvalue: 01\r\n# ');
  const source = Buffer.concat([prefix, Buffer.alloc(16 * 1024 * 1024 - prefix.length - 2, 'x'), Buffer.from('\r\n')]);
  assert.equal(source.length, 16 * 1024 * 1024);
  await client.put('a', 'b', source, write);
  assert.deepEqual((await client.get('a', 'b', read)).source, source);
  assert.equal((await client.head('a', 'b', read)).representationLength, source.length);
  assert.deepEqual((await large.http.get('a', 'b')).source, source);
  await assert.rejects(client.put('a', 'too-large', Buffer.alloc(source.length + 1), write), TypeError);
  const old = await native(t, { legacy: true });
  const excess = Buffer.concat([Buffer.from('value: 1\n# '), Buffer.alloc(256 * 1024, 'x')]);
  await assert.rejects(old.client.put('a', 'b', excess, write), error => error.status === 413 && !error.uncertain);
  await assert.rejects(old.client.get('a', 'b', read), error => error.status === 404);
  await old.client.put('a', 'b', SOURCE, write);
  assert.deepEqual((await old.http.get('a', 'b')).source, SOURCE);
});

test('binary native ASan: committed partial receipt is uncertain; verify source BEFORE explicit recovery; standalone IDs do not deduplicate', { timeout: 60000 }, async t => {
  const fixture = await native(t), sockets = new Set(); let requests = 0;
  const proxy = tls.createServer({ cert: fixture.pem['server.pem'], key: fixture.pem['server.key'], minVersion: 'TLSv1.3', ALPNProtocols: ['yamora-binary/1'] }, downstream => {
    requests++;
    const upstream = tls.connect({ host: fixture.config.host, port: fixture.config.port, ca: fixture.config.tls.ca,
      rejectUnauthorized: true, minVersion: 'TLSv1.3', ALPNProtocols: ['yamora-binary/1'] });
    sockets.add(upstream); upstream.on('close', () => sockets.delete(upstream));
    upstream.on('error', () => downstream.destroy()); downstream.on('error', () => upstream.destroy());
    downstream.on('close', () => upstream.destroy());
    downstream.pipe(upstream);
    let pending = Buffer.alloc(0), cut = false;
    upstream.on('data', bytes => {
      if (cut) return;
      pending = Buffer.concat([pending, bytes]);
      while (pending.length >= 16) {
        const length = pending.readUInt32BE(12);
        assert.ok(length <= 65536);
        if (pending.length < 16 + length) return;
        const frame = pending.subarray(0, 16 + length); pending = pending.subarray(16 + length);
        if (frame[5] === 4) {
          // Actual native receipt DATA is emitted only after durable execution.
          // Deliver an incomplete body, not a simulated pre-dispatch failure.
          cut = true; downstream.end(frame.subarray(0, 21)); upstream.destroy(); return;
        }
        downstream.write(frame);
      }
    });
  });
  proxy.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  proxy.closeAllConnections = () => { for (const socket of sockets) socket.destroy(); };
  const address = await listen(t, proxy);
  const client = new BinaryClient({ ...fixture.config, ...address });
  let failure;
  await assert.rejects(client.put('a', 'b', SOURCE, { ...write, ifNoneMatch: '*' }), error => {
    failure = error; return error instanceof BinaryUncertainWriteError && error.requestId === ID;
  });
  assert.equal(requests, 1, 'no automatic mutation replay');
  // This assertion deliberately precedes every explicit resubmission or recovery.
  assert.deepEqual((await fixture.http.get('a', 'b')).source, SOURCE, 'committed source invariant before recovery');
  assert.deepEqual(failure.envelope.source, SOURCE);
  await assert.rejects(fixture.client.put('a', 'b', failure.envelope.source, { ...write, ...failure.envelope.conditions }), error => error.status === 412 && !error.uncertain);
  const changed = Buffer.from('value: 7\n');
  await fixture.client.put('a', 'b', changed, write); // same ID, different operation
  assert.deepEqual((await fixture.http.get('a', 'b')).source, changed);
});
