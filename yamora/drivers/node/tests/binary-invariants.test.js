import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { BinaryClient, BinaryUncertainWriteError, YamoraError } from '../index.js';
import { responseMetadata, frame, requestMetadata, sourceTag } from '../lib/binary-codec.js';
import { peer, certificates, ID, REV, SOURCE, reply, replyFields, tlv, mutationBody, independentBytes, sourceEtag } from './binary-helpers.js';
const op = { method: 3, requestId: ID, collection: 'a', document: 'b' };

test('binary invariant: request ID', () => {
  assert.throws(() => responseMetadata(tlv(replyFields({ method: 3, body: Buffer.alloc(1), id: 'ab'.repeat(16) })), op, 16777216), /invalid binary protocol/, 'ID correlation invariant');
});
test('binary invariant: acknowledgement bound', () => {
  assert.throws(() => responseMetadata(tlv(replyFields({ method: 3, body: Buffer.alloc(4097) })), op, 16777216), /invalid binary protocol/, 'bounded acknowledgement invariant');
});
test('binary invariant: unique ascending TLVs', () => {
  const fields = replyFields({ method: 3, body: Buffer.alloc(1) });
  [fields[0], fields[1]] = [fields[1], fields[0]];
  assert.throws(() => responseMetadata(tlv(fields), op, 16777216), /invalid binary protocol/, 'ascending TLV invariant');
});
test('binary invariant: owned mutation envelope', async t => {
  const fixture = await peer(t, socket => socket.end());
  const source = Buffer.from(SOURCE);
  const pending = fixture.client.put('a', 'b', source, { requestId: ID });
  source.fill(0);
  let envelope;
  await assert.rejects(pending, error => { assert.ok(error instanceof BinaryUncertainWriteError); envelope = error.envelope; return true; });
  assert.deepEqual(envelope.source, SOURCE, 'owned source invariant');
});


test('binary invariant: GET source fingerprint', async t => {
  const fixture = await peer(t, socket => socket.end(reply({ etag: REV })));
  await assert.rejects(fixture.client.get('a', 'b', { requestId: ID }), error => error.code === 'PROTOCOL_ERROR' && !error.uncertain, 'GET source fingerprint invariant');
});
test('binary invariant: PUT source fingerprint', async t => {
  const fixture = await peer(t, socket => socket.end(reply({ method: 3, etag: REV, body: mutationBody({ etag: REV }) })));
  await assert.rejects(fixture.client.put('a', 'b', SOURCE, { requestId: ID }), error => error instanceof BinaryUncertainWriteError && error.requestId === ID && error.envelope.source.equals(SOURCE), 'PUT source fingerprint invariant');
});
for (const [name, condition, status] of [['create status', { ifNoneMatch: '*' }, 200], ['match status', { ifMatch: '"0123456789abcdef"' }, 201]]) {
  test(`binary invariant: ${name}`, async t => {
    const tag = sourceEtag();
    const fixture = await peer(t, socket => socket.end(reply({ method: 3, status, etag: tag, body: mutationBody({ etag: tag }) })));
    await assert.rejects(fixture.client.put('a', 'b', SOURCE, { requestId: ID, ...condition }), error => error instanceof BinaryUncertainWriteError && error.requestId === ID && error.envelope.source.equals(SOURCE), `${name} invariant`);
  });
}
function overwritten(backings, observe) {
  const buffers = [...new Set(backings)], saved = buffers.map(buffer => independentBytes(new Uint8Array(buffer)));
  try { for (const buffer of buffers) new Uint8Array(buffer).fill(0); return observe(); }
  finally { buffers.forEach((buffer, index) => new Uint8Array(buffer).set(saved[index])); }
}
test('binary invariant: source backing isolation', async t => {
  const fixture = await peer(t, socket => socket.end());
  const source = Buffer.from(SOURCE); let envelope;
  await assert.rejects(fixture.client.put('a', 'b', source, { requestId: ID }), error => { envelope = error.envelope; return error instanceof BinaryUncertainWriteError; });
  const observed = overwritten([source.buffer], () => independentBytes(envelope.source));
  assert.deepEqual(observed, SOURCE, 'source backing isolation invariant');
});
test('binary invariant: trust backing isolation', async t => {
  const tag = sourceEtag();
  const fixture = await peer(t, socket => socket.end(reply({ etag: tag })));
  const ca = Buffer.from(fixture.pem['ca.pem']);
  const client = new BinaryClient({ ...fixture.config, tls: { ca } });
  const result = overwritten([ca.buffer], () => client.get('a', 'b', { requestId: ID }));
  await assert.doesNotReject(result, 'trust backing isolation invariant');
});
test('binary invariant: envelope backing isolation', async t => {
  const fixture = await peer(t, socket => socket.end());
  let envelope;
  await assert.rejects(fixture.client.put('a', 'b', SOURCE, { requestId: ID }), error => { envelope = error.envelope; return error instanceof BinaryUncertainWriteError; });
  const copy = envelope.source, other = envelope.source;
  const observed = overwritten([copy.buffer], () => [independentBytes(other), independentBytes(envelope.source)]);
  assert.deepEqual(observed, [SOURCE, SOURCE], 'envelope backing isolation invariant');
});
test('binary invariant: outbound backing isolation', () => {
  const before = Buffer.allocUnsafe(1);
  const metadata = requestMetadata({ ...op, target: '/v1/collections/a/documents/b', source: independentBytes('x: 1\n'), conditions: {}, token: 'synthetic-bearer' }, 30000);
  const bytes = frame(2, 1, metadata), savedMetadata = independentBytes(metadata), savedFrame = independentBytes(bytes);
  const after = Buffer.allocUnsafe(1);
  const intact = overwritten([before.buffer, after.buffer], () => metadata.equals(savedMetadata) && bytes.equals(savedFrame));
  assert.ok(intact, 'outbound backing isolation invariant');
});
for (const name of ['shadowed bound', 'subclass bound', 'proxied input', 'shared shadow']) {
  test(`binary invariant: ${name}`, async t => {
    const fixture = await peer(t, socket => socket.end(), { maxDocumentBytes: 16 });
    let source, conversions = 0, copied = 0;
    if (name === 'shared shadow') {
      source = new Uint8Array(new SharedArrayBuffer(2)); source.set([120, 10]);
      Object.defineProperty(source, 'buffer', { value: new ArrayBuffer(2) });
    } else if (name === 'proxied input') {
      source = new Proxy(new Uint8Array([120, 10]), { get(target, key) {
        if (key === 'byteLength') return 1;
        if (key === 'valueOf') return () => { conversions++; return Buffer.alloc(8193, 120); };
        return Reflect.get(target, key, target);
      } });
    } else {
      class Input extends Uint8Array {}
      source = name === 'subclass bound' ? new Input(8193) : new Uint8Array(8193); source.fill(120);
      Object.defineProperty(source, 'byteLength', { value: 1 });
    }
    const original = Buffer.from;
    t.mock.method(Buffer, 'from', function (...args) { const result = Reflect.apply(original, Buffer, args); if (args[0] === source) copied += result.length; return result; });
    const result = await fixture.client.put('a', 'b', source, { requestId: ID }).then(() => undefined, error => error);
    assert.ok(result instanceof TypeError && fixture.connections() === 0 && conversions === 0 && copied === 0, `${name} intrinsic bound invariant`);
  });
}
test('binary invariant: conversion hooks ignored', async t => {
  let conversions = 0, observed;
  const source = new Uint8Array([120, 10]);
  Object.defineProperty(source, 'valueOf', { value() { conversions++; return Buffer.alloc(8193, 120); } });
  const fixture = await peer(t, (socket, fields, body) => { observed = independentBytes(body); socket.end(); });
  await assert.rejects(fixture.client.put('a', 'b', source, { requestId: ID }), BinaryUncertainWriteError);
  assert.ok(conversions === 0 && observed.equals(independentBytes('x\n')), 'conversion hooks invariant');
});
test('binary invariant: subclass intrinsic copy', async t => {
  class Input extends Uint8Array {}
  const source = new Input([120, 10]);
  Object.defineProperties(source, { length: { value: 1 }, byteLength: { value: 1 }, byteOffset: { value: 8192 }, buffer: { value: new ArrayBuffer(0) } });
  let observed;
  const fixture = await peer(t, (socket, fields, body) => { observed = independentBytes(body); socket.end(); });
  await assert.rejects(fixture.client.put('a', 'b', source, { requestId: ID }), BinaryUncertainWriteError);
  assert.deepEqual(observed, independentBytes('x\n'), 'subclass intrinsic copy invariant');
});
test('binary invariant: envelope owner lifetime', async () => {
  // A short-lived sentinel in the private credential slot makes context retention
  // observable without printing a token or claiming an output disclosure.
  const script = `
    import { BinaryUncertainWriteError, YamoraError } from ${JSON.stringify(new URL('../index.js', import.meta.url).href)};
    function make() {
      const token = { sentinel: true };
      const error = new BinaryUncertainWriteError({ method: 3, target: '/v1/collections/a/documents/b', requestId: '${ID}', conditions: Object.freeze({}), source: Buffer.alloc(2), token }, new YamoraError('test'));
      return { error, weak: new WeakRef(token) };
    }
    const held = make();
    for (let i = 0; i < 6; i++) { await new Promise(resolve => setImmediate(resolve)); global.gc(); }
    if (held.error.envelope.source.length !== 2) throw new Error('invalid envelope setup');
    process.stdout.write(held.weak.deref() === undefined ? 'released' : 'retained');
  `;
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, ['--expose-gc', '--input-type=module', '--eval', script], { encoding: 'utf8', timeout: 10000, env });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, 'released', 'envelope credential owner lifetime invariant');
});


test('binary invariant: identity backing isolation', async t => {
  const { pem } = await certificates(t);
  const fixture = await peer(t, socket => socket.end(reply()), { pem, server: { requestCert: true, rejectUnauthorized: true, ca: pem['ca.pem'] } });
  const identity = { ca: Buffer.from(pem['ca.pem']), cert: Buffer.from(pem['client.pem']), key: Buffer.from(pem['client.key']) };
  const client = new BinaryClient({ ...fixture.config, tls: identity });
  const result = overwritten([identity.cert.buffer, identity.key.buffer], () => client.get('a', 'b', { requestId: ID }));
  await assert.doesNotReject(result, 'identity backing isolation invariant');
});
test('binary invariant: fingerprint budget', () => {
  let checks = 0;
  assert.throws(() => sourceTag(Buffer.alloc(4096 * 3), { check() { if (++checks === 3) throw new Error('budget stopped'); } }), /budget stopped/, 'fingerprint budget invariant');
});


test('binary invariant: admission copy bound', async t => {
  let observed;
  const reached = new Promise(resolve => { observed = resolve; });
  const fixture = await peer(t, () => observed(), { maxConcurrentCalls: 1 });
  const activeAbort = new AbortController();
  const active = fixture.client.put('a', 'b', SOURCE, { requestId: ID, signal: activeAbort.signal });
  const activeResult = assert.rejects(active, BinaryUncertainWriteError);
  await reached;
  const source = Buffer.alloc(16 * 1024 * 1024, 32), waitingAbort = new AbortController();
  let copies = 0;
  const original = Buffer.alloc;
  t.mock.method(Buffer, 'alloc', function (...args) { if (args[0] === source.length) copies++; return Reflect.apply(original, Buffer, args); });
  const waiting = fixture.client.put('a', 'b', source, { requestId: ID, signal: waitingAbort.signal });
  const waitingResult = assert.rejects(waiting, error => error.code === 'ABORT_ERR' && !error.uncertain);
  waitingAbort.abort(); await waitingResult;
  activeAbort.abort(); await activeResult;
  assert.equal(copies, 0, 'admission copy bound invariant');
});

test('binary invariant: trust intrinsic bound', t => {
  const ca = Buffer.alloc(1024 * 1024 + 1, 32);
  Object.defineProperty(ca, 'byteLength', { value: 1 });
  let copied = 0, checking = false, rejected;
  const from = Buffer.from, alloc = Buffer.alloc;
  t.mock.method(Buffer, 'from', function (...args) { const result = Reflect.apply(from, Buffer, args); if (checking && args[0] === ca) copied += result.length; return result; });
  t.mock.method(Buffer, 'alloc', function (...args) { if (checking) copied += args[0]; return Reflect.apply(alloc, Buffer, args); });
  checking = true;
  try { new BinaryClient({ host: '127.0.0.1', port: 1, servername: '127.0.0.1', tls: { ca } }); }
  catch (error) { rejected = error; }
  finally { checking = false; }
  assert.ok(rejected instanceof TypeError && copied === 0, 'trust intrinsic bound invariant');
});
