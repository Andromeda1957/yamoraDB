import { test } from 'node:test';
import assert from 'node:assert/strict';
import { BinaryClient, BinaryUncertainWriteError } from '../index.js';
import { peer, ID, REV, wire, number, tlv, END } from './binary-helpers.js';
import { decode } from '../lib/codec.js';

const HELLO2 = wire(1, 0, Buffer.concat([number(1, 2), number(2, 2), number(4096, 4), number(1, 4)]));
function response(body, { mode = 0, schema = 2, id = ID, status = 200, etag, missingMode = false } = {}) {
  const fields = [[1, number(status, 2)], [2, Buffer.from(mode ? 'application/x-ndjson' : 'application/json')],
    [3, number(mode ? 0 : body.length, 8)], [4, number(mode ? 0 : body.length, 8)], [5, Buffer.from(REV)]];
  if (etag) fields.push([6, Buffer.from(`"${etag}"`)]);
  fields.push([12, Buffer.from(id, 'hex')]);
  if (!missingMode) fields.push([13, number(mode, 1)]);
  const meta = tlv(fields); meta.writeUInt16BE(schema);
  return Buffer.concat([wire(3, 1, meta), ...(body.length ? [wire(4, 1, body)] : []), END]);
}
const opts = { token: 'read-synthetic', requestId: ID };
test('schema2 response envelopes have a separate bounded depth budget', async t => {
  const mapping = '{"deep":' + '{"n":'.repeat(63) + '{}' + '}'.repeat(64);
  const values = ['{"value":' + '['.repeat(64) + '0' + ']'.repeat(64) + '}', mapping, '{"edge":[' + mapping + ']}'];
  for (const [number, value] of values.entries()) await t.test(`accepted edge ${number}`, async sub => {
    const body = Buffer.from(`{"revision":"${REV}","documents":[${value}]}`);
    const fixture = await peer(sub, socket => socket.end(response(body)), { hello: HELLO2 });
    let result, failure;
    try { result = await fixture.client.operation('POST', '/v1/query/a', 'application/json', '{}', opts); }
    catch (error) { failure = error; }
    assert.equal(failure, undefined, 'native domain edge response was rejected');
    assert.deepEqual(result.body, body);
  });
  assert.throws(() => decode(Buffer.from('{"v":' + '['.repeat(64) + '0' + ']'.repeat(64) + '}')), /nesting/);
  const invalid = ['['.repeat(80) + '0' + ']'.repeat(80), '1,"v":2'].map(value => Buffer.from(`{"revision":"${REV}","v":${value}}`));
  invalid.push(Buffer.concat([Buffer.from(`{"revision":"${REV}","v":"`), Buffer.from([255]), Buffer.from('"}')]));
  for (const body of invalid) {
    const fixture = await peer(t, socket => socket.end(response(body)), { hello: HELLO2 });
    await assert.rejects(fixture.client.operation('POST', '/v1/query/a', 'application/json', '{}', opts));
  }
  const source = '{"operations":[{}],"v":' + '['.repeat(64) + '0' + ']'.repeat(64) + '}';
  const receipt = Buffer.from(`{"status":"committed","operations":1,"revision":"${REV}"}`);
  const fixture = await peer(t, socket => socket.end(response(receipt)), { hello: HELLO2 });
  await assert.rejects(fixture.client.operation('POST', '/v1/transactions', 'application/json', source, opts), error => error instanceof BinaryUncertainWriteError);
});
test('schema2 legacy peer is typed unsupported before any mutation REQUEST', async t => {
  let requests = 0;
  const fixture = await peer(t, () => { requests++; });
  await assert.rejects(fixture.client.operation('PATCH', '/v1/collections/a/documents/b', 'application/json', '{}', opts),
    error => error.code === 'BINARY_UNSUPPORTED' && !error.uncertain);
  assert.equal(requests, 0);
});
test('schema2 negotiates a protocol2-only peer through the advertised common range', async t => {
  const hello = wire(1, 0, Buffer.concat([number(2, 2), number(2, 2), number(4096, 4), number(1, 4)]));
  const body = Buffer.from(`{"revision":"${REV}"}`);
  const fixture = await peer(t, socket => socket.end(response(body)), { hello });
  const value = await fixture.client.operation('POST', '/v1/query/a', 'application/json', '{}', opts);
  assert.deepEqual(value.body, body);
});
test('schema2 public operation preserves raw numeric specification and response', async t => {
  const spec = Buffer.from('{"filter":{"wide":18446744073709551615},"limit":1}');
  const result = Buffer.from(`{"revision":"${REV}","documents":[{"n":18446744073709551615}],"next_after":"a"}`);
  const fixture = await peer(t, (socket, fields, body) => {
    assert.equal(fields.get(1)[0], 5); assert.equal(fields.get(2).toString(), '/v1/query/a');
    assert.equal(fields.get(3).toString(), 'application/json'); assert.equal(fields.get(5).toString(), 'Bearer read-synthetic');
    assert.deepEqual(body, spec); socket.end(response(result));
  }, { hello: HELLO2 });
  assert.equal(typeof fixture.client.operation, 'function', 'public finite operation API is required');
  assert.deepEqual((await fixture.client.operation('POST', '/v1/query/a', 'application/json', spec, opts)).body, result);
});

test('schema2 guards request targets and response schema/mode/ID before publication', async t => {
  for (const change of [{ schema: 1 }, { missingMode: true }, { mode: 1 }, { id: 'ab'.repeat(16) }]) {
    const fixture = await peer(t, socket => socket.end(response(Buffer.from(`{"revision":"${REV}"}`), change)), { hello: HELLO2 });
    await assert.rejects(fixture.client.operation('POST', '/v1/query/a', 'application/json', Buffer.from('{}'), opts), error => !error.uncertain, 'schema and mode correlation invariant');
  }
  const fixture = await peer(t, socket => socket.end(response(Buffer.from('{}'))), { hello: HELLO2 });
  for (const target of ['/metrics', '/v1/query/../a', '/v1/query/a?x=1', '/v1/transactions/extra']) {
    await assert.rejects(fixture.client.operation('POST', target, 'application/json', Buffer.from('{}'), opts), TypeError);
  }
  assert.equal(fixture.connections(), 0);
});

test('schema2 PATCH and transaction validate receipts and retain exact uncertainty envelope', async t => {
  const source = Buffer.from('{"$inc":{"n":1}}'), target = '/v1/collections/a/documents/b';
  const fixture = await peer(t, socket => socket.end(), { hello: HELLO2 });
  await assert.rejects(fixture.client.operation('PATCH', target, 'application/json', source, { ...opts, ifMatch: '' }), error => {
    assert.ok(error instanceof BinaryUncertainWriteError); assert.equal(error.envelope.method, 'PATCH');
    assert.equal(error.envelope.target, target); assert.equal(error.envelope.contentType, 'application/json');
    assert.equal(error.envelope.conditions.ifMatch, ''); assert.deepEqual(error.envelope.source, source); return true;
  });
});

test('schema2 feed publishes only complete raw validated pages and keeps prefix on truncation', async t => {
  const cursor = 'v1.' + '0'.repeat(32) + '.' + '0'.repeat(16), first = Buffer.from(`{"transactions":[],"next_after":"${cursor}","checkpoint":"${cursor}","oldest_after":"${cursor}","revision":"${REV}","has_more":false}\n`);
  const fixture = await peer(t, socket => { const bytes = response(Buffer.concat([first, Buffer.from('{"unfinished":')] ), { mode: 1 }); socket.end(bytes.subarray(0, -16)); }, { hello: HELLO2 });
  const pages = [];
  await assert.rejects(fixture.client.feed(`/v1/changes/stream?after=${cursor}&duration_ms=100`, page => pages.push(page), opts));
  assert.deepEqual(pages, [first]);
});

test('schema2 cancellation inside completed callback retains the newly delivered cursor', async t => {
  const identity = 'v1.' + '0'.repeat(32) + '.', before = identity + '0'.repeat(16), after = identity + '0'.repeat(15) + '1';
  const page = Buffer.from(JSON.stringify({ transactions: [{ token: after, previous_revision: '0'.repeat(16), revision: REV,
    resnapshot_required: false, operations: [{ collection: 'a', document: 'b', put: 'n: 1\r\n' }] }],
    next_after: after, oldest_after: before, checkpoint: after, revision: REV, has_more: false }) + '\n');
  const fixture = await peer(t, socket => socket.end(response(page, { mode: 1 })), { hello: HELLO2 });
  const cancellation = new AbortController(); let delivered;
  await assert.rejects(fixture.client.feed(`/v1/changes/stream?after=${before}`, raw => { delivered = raw; cancellation.abort(); }, { ...opts, signal: cancellation.signal }), error => {
    assert.equal(error.code, 'ABORT_ERR'); assert.equal(error.response.resumeAfter, after, 'completed callback cursor invariant'); return true;
  });
  assert.deepEqual(delivered, page);
});

test('schema2 callback page backing storage cannot corrupt another delivered page', async t => {
  const cursor = 'v1.' + '0'.repeat(32) + '.' + '0'.repeat(16);
  const page = Buffer.from(JSON.stringify({ transactions: [], next_after: cursor, checkpoint: cursor,
    oldest_after: cursor, revision: REV, has_more: false }) + '\n');
  const fixture = await peer(t, socket => socket.end(response(Buffer.concat(Array(8).fill(page)), { mode: 1 })), { hello: HELLO2 });
  const previous = []; let delivered = 0;
  let failure, corrupted = false;
  try {
    await fixture.client.feed(`/v1/changes/stream?after=${cursor}`, raw => {
      delivered++;
      for (const old of previous) new Uint8Array(old.buffer).fill(0);
      corrupted ||= !raw.equals(page);
      previous.push(raw);
    }, opts);
  } catch (error) { failure = error; }
  assert.equal(failure, undefined, 'owned callback storage must permit consumer backing writes without aborting delivery');
  assert.equal(corrupted, false, 'previous callback backing mutation cannot reach the next page');
  assert.equal(delivered, 8);
});
