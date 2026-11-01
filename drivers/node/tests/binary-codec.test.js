import { test } from 'node:test';
import assert from 'node:assert/strict';
import { frame, header, hello, peerHello, requestMetadata, responseMetadata, sourceTag } from '../lib/binary-codec.js';
import { HELLO, END, ID, REV, SOURCE, replyFields, tlv, number, sourceEtag } from './binary-helpers.js';
const op = { method: 1, target: '/v1/collections/a/documents/b', collection: 'a', document: 'b', source: Buffer.alloc(0), conditions: {}, requestId: ID };

test('binary literal wire goldens: header, HELLO and network-order request TLVs', () => {
  assert.deepEqual(frame(5, 1), END);
  assert.deepEqual(frame(1, 0, hello(65536)), HELLO);
  const expected = Buffer.from('0001000600010001010002001d2f76312f636f6c6c656374696f6e732f612f646f63756d656e74732f620003000000040008000000000000000000080010112233445566778899aabbccddeeff000009000400007530', 'hex');
  assert.deepEqual(requestMetadata(op, 30000), expected);
  const literal = Buffer.from('000100060001000200c8000200106170706c69636174696f6e2f79616d6c0003000800000000000000000004000800000000000000000005001030313233343536373839616263646566000c0010112233445566778899aabbccddeeff00', 'hex');

  const complete = Buffer.from('000100070001000200c8000200106170706c69636174696f6e2f79616d6c000300080000000000000000000400080000000000000000000500103031323334353637383961626364656600060012223031323334353637383961626364656622000c0010112233445566778899aabbccddeeff00', 'hex');
  assert.equal(responseMetadata(complete, { ...op, method: 2 }, 16777216).etag, REV);
  // Successful HEAD must carry an ETag, so this independently frozen metadata is
  // intentionally rejected rather than converted to a success by framing alone.
  assert.throws(() => responseMetadata(literal, { ...op, method: 2 }, 16777216));
});

test('binary headers reject malformed advertised allocation before payload', () => {
  for (const mutate of [b => { b[0] = 0; }, b => { b[4] = 2; }, b => { b[6] = 1; }, b => { b[5] = 11; }, b => { b.writeUInt32BE(2, 8); }, b => { b.writeUInt32BE(0xffffffff, 12); }, b => { b[5] = 4; }]) {
    const bytes = Buffer.from(END); mutate(bytes); assert.throws(() => header(bytes, 4096), /invalid binary protocol/);
  }
  for (const [offset, value] of [[0, 0], [2, 0], [4, 4095], [4, 1048577], [8, 0], [8, 129]]) {
    const bytes = Buffer.from(HELLO.subarray(16)); if (offset < 4) bytes.writeUInt16BE(value, offset); else bytes.writeUInt32BE(value, offset);
    assert.throws(() => peerHello(bytes, 65536));
  }
  assert.equal(peerHello(Buffer.from('000100020000100000000080', 'hex'), 65536), 4096);
});

test('binary response TLVs reject ordering, widths, bounds, correlation and method semantics', () => {
  const base = replyFields();
  assert.equal(responseMetadata(tlv(base), op, 16777216).revision, REV);
  const bad = [base.slice().reverse(), [...base, base.at(-1)], base.filter(([id]) => id !== 5), [[13, Buffer.alloc(0)]],
    base.map(([id, v]) => [id, id === 3 ? number(16777217, 8) : v]), base.map(([id, v]) => [id, id === 3 ? number(1, 4) : v]),
    base.map(([id, v]) => [id, id === 12 ? Buffer.alloc(16) : v]), base.map(([id, v]) => [id, id === 5 ? Buffer.from(REV.toUpperCase()) : v]),
    base.map(([id, v]) => [id, id === 6 ? Buffer.from(REV) : v]), base.map(([id, v]) => [id, id === 7 ? Buffer.from('other') : v]),
    base.map(([id, v]) => [id, id === 1 ? number(201, 2) : v])];
  for (const values of bad) assert.throws(() => responseMetadata(tlv(values), op, 16777216));
  assert.throws(() => responseMetadata(Buffer.concat([tlv(base), Buffer.from([0])]), op, 16777216));
  assert.throws(() => responseMetadata(tlv(base), { ...op, method: 2 }, 16777216));
  assert.throws(() => responseMetadata(tlv(replyFields({ status: 204 })), { ...op, method: 4 }, 16777216));
  assert.throws(() => responseMetadata(tlv(replyFields({ method: 3, body: Buffer.alloc(4097) })), { ...op, method: 3 }, 16777216));
});


test('binary raw-source fingerprint uses native seed, prime and exact bytes', () => {
  const vectors = [Buffer.alloc(0), SOURCE, Buffer.from('# same\r\nx: 01 # comment\r\n'), Buffer.from('# same\nx: 01 # comment\n'), Buffer.from(Array.from({ length: 256 }, (_, i) => i))];
  for (const bytes of vectors) assert.equal(sourceTag(bytes, { check() {} }), sourceEtag(bytes));
  assert.equal(sourceTag(Buffer.alloc(0), { check() {} }), '14650fb0739d0383');
  assert.notEqual(sourceTag(vectors[2], { check() {} }), sourceTag(vectors[3], { check() {} }));
});
