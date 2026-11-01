import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { Client, YamoraError } from '../index.js';
import { encode } from '../lib/codec.js';
import { httpFixture, rawFixture, json, REV, READ, WRITE,
  CATALOG_INDEX, INVALID_CATALOG_RECEIPTS, catalogMutations } from './helpers.js';

test('replication source guard validates advertised capability without dispatching a write', async t => {
  let readiness;
  const observed = [];
  const { client } = await httpFixture(t, (req, res) => {
    observed.push([req.method, req.url]);
    json(res, readiness);
  });
  for (const allowed of [false, null, 'false', 'true', 0, 1, [], {}]) {
    readiness = { revision: REV, replication_policy_free: allowed };
    await assert.rejects(client.requireReplicationSource(), error => error instanceof YamoraError &&
      error.code === (allowed === false ? 'SCHEMA_POLICY_REPLICATION_UNSUPPORTED' : 'PROTOCOL_ERROR') &&
      error.uncertain === false && error.status === (allowed === false ? 409 : undefined));
  }
  for (const fields of [{}, { replication_policy_free: true }, { nested: { replication_policy_free: false } }]) {
    readiness = { revision: REV, ...fields };
    assert.deepEqual(await client.requireReplicationSource(), readiness);
  }
  assert.equal(observed.length, 11);
  assert.ok(observed.every(([method, path]) => method === 'GET' && path === '/readyz'));
});

test('reject invalid endpoints, credentials, limits and TLS escape hatches', () => {
  for (const host of ['localhost', 'http://127.0.0.1', '127.1', '0127.0.0.1', '0.0.0.0', '169.254.169.254', '8.8.8.8', '100.64.0.1', '172.32.0.1', '192.0.0.1', '::1', '127.0.0.1\n'])
    assert.throws(() => new Client({ host }), TypeError, host);
  for (const host of ['127.2.3.4', '10.0.0.1', '172.16.0.1', '172.31.255.255', '192.168.1.1']) assert.ok(new Client({ host }));
  for (const port of [0, -1, 65536, 1.5, true, '8765', NaN]) assert.throws(() => new Client({ port }), TypeError);
  for (const token of ['', 'x'.repeat(31), 'x'.repeat(513), `${READ}\r\n`, `${READ} `, `${READ}\u0085`, `${READ}\0`]) {
    assert.throws(() => new Client({ readToken: token }), TypeError);
    assert.throws(() => new Client({ writeToken: token }), TypeError);
  }
  for (const timeoutMs of [0, -1, 30001, Infinity, '1000']) assert.throws(() => new Client({ timeoutMs }), TypeError);
  for (const tls of [null, false, { rejectUnauthorized: false }, { minVersion: 'TLSv1.2' }, { checkServerIdentity: () => undefined }, { secureContext: {} }, { cert: 'unpaired' }])
    assert.throws(() => new Client({ tls }), TypeError);
  assert.throws(() => new Client({ maxRequestBytes: 0 }), TypeError);
  assert.throws(() => new Client({ maxResponseBytes: 64 * 1024 * 1024 + 1 }), TypeError);
  assert.throws(() => new Client({ proxy: 'http://example.com' }), TypeError);
  const client = new Client({ readToken: READ, writeToken: WRITE });
  assert.equal(JSON.stringify(client), '{}');
  assert.ok(!inspect(client).includes(READ));
});

test('invalid identifiers, conditions, sources and structured inputs fail before connecting', async () => {
  const client = new Client({ port: 1 });
  for (const id of ['', '../x', 'UPPER', 'x/y', 'x?y', '%2f', 'x'.repeat(129), 'x\n']) {
    await assert.rejects(client.get(id, 'valid'), TypeError);
    await assert.rejects(client.get('valid', id), TypeError);
  }
  for (const options of [{ etag: 'bad' }, { etag: REV, createOnly: true }, { createOnly: 'yes' }, { requestId: '0'.repeat(32) }, { headers: {} }])
    await assert.rejects(client.put('a', 'b', 'x: 1\n', options), TypeError);
  for (const source of ['', '\ud800', Buffer.from([0xff]), new Uint8Array([0xc3])]) await assert.rejects(client.put('a', 'b', source), TypeError);
  for (const value of [NaN, Infinity, 9007199254740992, 1n << 63n, undefined, () => 1, new Date(), '\ud800'])
    await assert.rejects(client.patch('a', 'b', { $set: { n: value } }), TypeError);
  const cycle = {}; cycle.self = cycle;
  await assert.rejects(client.patch('a', 'b', cycle), /complexity/);
  await assert.rejects(client.patch('a', 'b', { get $set() { throw new Error('getter executed'); } }), /accessors/);
  await assert.rejects(client.patch('a', 'b', { $set: { x: { toJSON: () => 1 } } }), /serialization hooks/);
  const sparse = Array(1); sparse.extra = 1;
  await assert.rejects(client.patch('a', 'b', { $set: { sparse } }), /dense/);
  await assert.rejects(client.query('a', { after: 'b' }), /revision/);
  await assert.rejects(client.query('a', { limit: 1001 }), TypeError);
  await assert.rejects(client.documentPage('a', { after: 'b' }), /revision/);
  await assert.rejects(client.transaction([{ collection: 'a', document: 'b', put: 'x: 1', delete: true }]), TypeError);
  await assert.rejects(client.transaction([{ collection: 'a', document: 'b', delete: true }, { collection: 'a', document: 'b', delete: true }]), /duplicate/);
  await assert.rejects(new Client({ maxDocumentBytes: 3 }).put('a', 'b', 'x: 1'), /limit/);
  await assert.rejects(new Client({ maxRequestBytes: 8 }).patch('a', 'b', { $set: { n: 1 } }), /limit/);
});

test('exact authored YAML, independent tokens, conditions and manual request ID', async t => {
  const authored = Buffer.from('# exact\r\nname: "café"  # preserved\r\nvalue: 1\r\n');
  const observed = [];
  const { client } = await httpFixture(t, (req, res) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      observed.push({ method: req.method, headers: req.headers, body: Buffer.concat(chunks) });
      if (req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/yaml; charset=utf-8', 'X-YamlDB-Revision': REV, ETag: `"${REV}"` }); res.end(authored);
      } else if (req.method === 'DELETE') { res.writeHead(204, { 'X-YamlDB-Revision': REV }); res.end(); }
      else json(res, { status: 'stored', collection: 'people', document: 'alex', etag: REV, revision: REV });
    });
  }, { readToken: READ, writeToken: WRITE });
  await client.put('people', 'alex', authored, { createOnly: true, requestId: '1'.repeat(32) });
  const document = await client.get('people', 'alex', { revision: REV });
  assert.deepEqual(document.source, authored); assert.equal(document.etag, REV);
  await client.patch('people', 'alex', { $inc: { value: 1n } }, { etag: document.etag });
  await client.delete('people', 'alex', { etag: REV });
  assert.deepEqual(observed[0].body, authored);
  assert.equal(observed[0].headers['if-none-match'], '*');
  assert.equal(observed[0].headers['x-yamora-request-id'], '1'.repeat(32));
  assert.equal(observed[1].headers.authorization, `Bearer ${READ}`);
  for (const i of [0, 2, 3]) assert.equal(observed[i].headers.authorization, `Bearer ${WRITE}`);
  assert.equal(observed[2].headers['if-match'], `"${REV}"`);
  assert.equal(observed[3].headers['if-match'], `"${REV}"`);
  assert.equal(observed[2].body.toString(), '{"$inc":{"value":1}}');
  assert.ok(observed.every(item => item.headers.connection === 'close'));
});

test('redirect and conditional errors are surfaced without body or credential leakage', async t => {
  let requests = 0;
  const { client } = await httpFixture(t, (req, res) => {
    requests++;
    res.writeHead(req.method === 'GET' ? 302 : 412, { Location: 'http://127.0.0.1:1/stolen' });
    res.end(`remote secret ${READ}`);
  }, { readToken: READ, writeToken: WRITE });
  await assert.rejects(client.health(), error => error instanceof YamoraError && error.status === 302 && !error.message.includes(READ));
  await assert.rejects(client.put('a', 'b', 'x: 1'), error => error.status === 412 && error.uncertain === false);
  assert.equal(requests, 2);
});

test('mutation disconnect and malformed acknowledgement are uncertain and never replayed', async t => {
  const { client, connections } = await rawFixture(t, socket => socket.destroy());
  await assert.rejects(client.put('a', 'b', 'x: 1'), error => error instanceof YamoraError && error.uncertain);
  assert.equal(connections(), 1);
  const broken = await httpFixture(t, (_req, res) => json(res, { status: 'stored', etag: REV, revision: REV, collection: 'wrong', document: 'b' }));
  await assert.rejects(broken.client.put('a', 'b', 'x: 1'), error => error.uncertain);
});

test('standalone catalog mutations reject malformed committed receipts without replay', async t => {
  for (const [method, run] of catalogMutations()) {
    for (const [variant, invalid] of INVALID_CATALOG_RECEIPTS) {
      await t.test(`${method}/${variant}`, async t => {
        let writes = 0;
        const { client } = await httpFixture(t, (req, res) => {
          if (req.method === 'GET') json(res, { indexes: method === 'dropIndex' ? [CATALOG_INDEX] : [], revision: REV });
          else { writes++; json(res, invalid); }
        });
        await assert.rejects(run(client), error => error instanceof YamoraError && error.uncertain && error.code === 'PROTOCOL_ERROR');
        assert.equal(writes, 1);
      });
    }
  }
});

test('proxy environment is ignored even with NODE_USE_ENV_PROXY', async t => {
  const { address } = await httpFixture(t, (_req, res) => json(res, { status: 'ok' }));
  let proxies = 0;
  const proxy = await httpFixture(t, (_req, res) => { proxies++; res.writeHead(502); res.end(); });
  const old = { HTTP_PROXY: process.env.HTTP_PROXY, HTTPS_PROXY: process.env.HTTPS_PROXY, ALL_PROXY: process.env.ALL_PROXY, NO_PROXY: process.env.NO_PROXY, NODE_USE_ENV_PROXY: process.env.NODE_USE_ENV_PROXY };
  try {
    for (const key of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY']) process.env[key] = `http://127.0.0.1:${proxy.address.port}`;
    process.env.NO_PROXY = ''; process.env.NODE_USE_ENV_PROXY = '1';
    assert.equal((await new Client(address).health()).status, 'ok');
    assert.equal(proxies, 0);
    // Set the opt-in before process startup too, so global agents really enable
    // Node's environment proxy support while our private agent remains direct.
    await promisify(execFile)(process.execPath, ['--input-type=module', '-e',
      `import { Client } from ${JSON.stringify(new URL('../index.js', import.meta.url).href)}; await new Client({port:${address.port}}).health();`],
    { env: { ...process.env }, timeout: 5000 });
    assert.equal(proxies, 0);
  } finally { for (const [key, value] of Object.entries(old)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; } }
});

test('absolute deadline covers trickled bodies; cancellation stops active requests', async t => {
  const { client } = await rawFixture(t, socket => {
    socket.write('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{');
    const timer = setInterval(() => socket.write(' '), 10);
    socket.on('close', () => clearInterval(timer));
  }, { timeoutMs: 100 });
  const before = performance.now();
  await assert.rejects(client.health(), error => error.code === 'TIMEOUT');
  assert.ok(performance.now() - before < 2000);
  const controller = new AbortController();
  const pending = client.put('a', 'b', 'x: 1', { signal: controller.signal });
  controller.abort();
  await assert.rejects(pending, error => error.code === 'ABORT_ERR' && error.uncertain);
  await assert.rejects(client.health({ signal: AbortSignal.abort() }), error => error.code === 'ABORT_ERR' && !error.uncertain);
});

test('truncated, oversized, compressed and duplicate response metadata fail closed', async t => {
  const cases = [
    ['Content-Length: 6\r\n', '{}', 'TRUNCATED_RESPONSE'],
    ['Content-Length: 99999\r\n', '{}', 'RESPONSE_LIMIT'],
    ['Transfer-Encoding: chunked\r\n', '9\r\n123456789\r\n0\r\n\r\n', 'RESPONSE_LIMIT'],
    ['Content-Encoding: gzip\r\n', '{}', 'RESPONSE_LIMIT'],
    ['X-YamlDB-Revision: fedcba9876543210\r\n', '{}', 'PROTOCOL_ERROR'],
    ['Content-Type: application/yaml\r\n', '{}', 'PROTOCOL_ERROR']
  ];
  for (const [headers, body, code] of cases) {
    await t.test(code + headers.split(':')[0], async t => {
      const fixture = await rawFixture(t, socket => socket.end(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-YamlDB-Revision: ${REV}\r\n${headers}Connection: close\r\n\r\n${body}`), { maxResponseBytes: 8 });
      await assert.rejects(fixture.client.health(), error => error.code === code);
    });
  }
  const unframed = await rawFixture(t, socket => socket.end(`HTTP/1.1 200 OK\r\nX-YamlDB-Revision: ${REV}\r\nContent-Type: application/json\r\n\r\n${' '.repeat(64)}`), { maxResponseBytes: 8 });
  await assert.rejects(unframed.client.health(), error => error.code === 'RESPONSE_LIMIT');
});

test('structured JSON preserves int64 and YAML line breaks without accepting malformed replies', async t => {
  let sent;
  const { client } = await httpFixture(t, (req, res) => {
    let body = ''; req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      sent = body;
      json(res, `{"documents":[{"id":"one","value":{"n":9223372036854775807,"negative":-9223372036854775808}}],"matched":1,"next_after":null,"revision":"${REV}"}`);
    });
  });
  const result = await client.query('a', { filter: { n: 9223372036854775807n, text: 'a\u0085 b\u2028 c\u2029 d' } });
  assert.equal(result.documents[0].value.n, 9223372036854775807n);
  assert.equal(result.documents[0].value.negative, -9223372036854775808n);
  assert.match(sent, /9223372036854775807/);
  assert.match(sent, /\\u0085 b\\u2028 c\\u2029 d/);
  for (const body of ['{"x":1e999}', '{"x":"\\ud800"}', '{"x":' + '['.repeat(66) + '0' + ']'.repeat(66) + '}', 'null', '{broken']) {
    const fixture = await httpFixture(t, (_req, res) => json(res, body));
    await assert.rejects(fixture.client.health(), error => error.code === 'PROTOCOL_ERROR');
  }
});

test('document pages pin revisions and reject stale or nonprogressing pages', async t => {
  let reads = 0;
  const { client } = await httpFixture(t, (req, res) => {
    reads++;
    if (req.url.includes('after=')) json(res, { collection: 'a', documents: ['b'], next_after: null }, 'fedcba9876543210');
    else json(res, { collection: 'a', documents: ['a'], next_after: 'a' });
  });
  const seen = [];
  await assert.rejects(async () => { for await (const id of client.documents('a', { limit: 1 })) seen.push(id); }, YamoraError);
  assert.deepEqual(seen, ['a']); assert.equal(reads, 2);
  const fixture = await httpFixture(t, (_req, res) => json(res, { collection: 'a', documents: [], next_after: 'a' }));
  await assert.rejects(fixture.client.documentPage('a'), YamoraError);
});

const maximum = 1024 * 1024;

test('toJSON enumerable data fields encode as ordinary JSON properties', () => {
  for (const value of ['text', null, false, 7, { nested: 'value' }, ['value']]) {
    const input = { filter: { toJSON: value }, $set: { toJSON: value } };
    assert.deepEqual(JSON.parse(encode(input, maximum).toString()), input);
  }
  const data = Object.assign(Object.create(null), { toJSON: 'text' });
  assert.equal(encode({ filter: data }, maximum).toString(), '{"filter":{"toJSON":"text"}}');
});

test('toJSON callable, accessor and custom-prototype hooks reject without execution', () => {
  let calls = 0;
  const hook = () => { calls++; return 'rewritten'; };
  const accessor = {};
  Object.defineProperty(accessor, 'toJSON', { enumerable: true, get: hook });
  const prototypeAccessor = {};
  Object.defineProperty(prototypeAccessor, 'toJSON', { get: hook });
  for (const input of [{ toJSON: hook }, accessor, Object.create({ toJSON: hook }), Object.create(prototypeAccessor), { field: hook }]) {
    assert.throws(() => encode({ filter: input }, maximum), TypeError);
    assert.equal(calls, 0);
  }
});

test('inherited standard-prototype toJSON hooks reject without execution', () => {
  let calls = 0;
  const hook = () => { calls++; return 'rewritten'; };
  for (const [prototype, input] of [[Object.prototype, { field: 'value' }], [Array.prototype, ['value']], [BigInt.prototype, 7n]]) {
    const original = Object.getOwnPropertyDescriptor(prototype, 'toJSON');
    try {
      for (const descriptor of [{ value: hook }, { get: hook }]) {
        Object.defineProperty(prototype, 'toJSON', { ...descriptor, configurable: true });
        assert.throws(() => encode(input, maximum), TypeError);
        assert.equal(calls, 0);
      }
    } finally {
      if (original) Object.defineProperty(prototype, 'toJSON', original);
      else delete prototype.toJSON;
    }
  }
});
