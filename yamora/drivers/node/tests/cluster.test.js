import { test } from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { execFile } from 'node:child_process';
import { promisify, inspect } from 'node:util';
import * as sdk from '../index.js';
import { certificates, listen, json, REV, READ, WRITE, rawFixture,
  CATALOG_INDEX, CATALOG_RECEIPT, INVALID_CATALOG_RECEIPTS, catalogMutations } from './helpers.js';

const leader = { node: 1, leader: 1, term: 1, role: 'leader' };
const receipt = { status: 'stored', collection: 'a', document: 'b', etag: REV, revision: REV };
const config = (seeds, pem, extra = {}) => ({ seeds, tls: { ca: pem['ca.pem'] }, readToken: READ, writeToken: WRITE, timeoutMs: 3000, ...extra });
async function server(t, pem, handler) {
  return listen(t, https.createServer({ cert: pem['server.pem'], key: pem['server.key'], minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' }, handler));
}
async function body(req) {
  const chunks = []; for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks);
}

test('cluster requires distinct trusted numeric private HTTPS seeds', async t => {
  const { pem } = await certificates(t);
  assert.equal(typeof sdk.ClusterClient, 'function');
  const valid = config([{ host: '127.0.0.1', port: 8765 }], pem);
  for (const extra of [{ seeds: [] }, { seeds: Array(10).fill(valid.seeds[0]) }, { seeds: [valid.seeds[0], valid.seeds[0]] },
    { seeds: [{ host: 'localhost', port: 8765 }] }, { seeds: [{ host: '8.8.8.8', port: 8765 }] },
    { seeds: [{ host: '127.0.0.1', port: 0 }] }, { seeds: [{ ...valid.seeds[0], url: 'https://evil.test' }] },
    { host: '127.0.0.1' }, { port: 8765 }, { tls: undefined }, { tls: { rejectUnauthorized: false } },
    { retryTimeoutMs: 0 }, { retryTimeoutMs: 30001 }, { proxy: 'http://127.0.0.1:1' }])
    assert.throws(() => new sdk.ClusterClient({ ...valid, ...extra }), TypeError);
  assert.ok(new sdk.ClusterClient(valid) instanceof sdk.Client);
});

test('retry owns YAML bytes, preconditions, generated identity and immutable seed/TLS configuration', async t => {
  const { pem } = await certificates(t);
  const seen = [];
  let source;
  const a = await server(t, pem, async (req, res) => {
    if (req.url === '/v1/cluster/leader') { source.fill(120); json(res, leader); return; }
    seen.push({ headers: req.headers, bytes: await body(req) }); req.socket.destroy();
  });
  const b = await server(t, pem, async (req, res) => {
    if (req.url === '/v1/cluster/leader') { json(res, leader); return; }
    seen.push({ headers: req.headers, bytes: await body(req) }); json(res, receipt, REV, 201);
  });
  const ca = Buffer.from(pem['ca.pem']);
  const seeds = [{ ...a }, { ...b }];
  const options = { createOnly: true };
  const client = new sdk.ClusterClient(config(seeds, pem, { tls: { ca } }));
  assert.equal(JSON.stringify(client), '{}'); assert.ok(!inspect(client).includes(WRITE));
  source = Buffer.from('# exact\r\nn: 1\r\n');
  const saved = client.put('a', 'b', source, options);
  ca.fill(0); seeds[1].port = 1; seeds.length = 0; options.createOnly = false;
  assert.deepEqual(await saved, receipt);
  assert.equal(seen.length, 2);
  assert.deepEqual(seen[0].bytes, Buffer.from('# exact\r\nn: 1\r\n'));
  assert.deepEqual(seen[1].bytes, seen[0].bytes);
  assert.match(seen[0].headers['x-yamora-request-id'], /^[0-9a-f]{32}$/);
  assert.equal(seen[1].headers['x-yamora-request-id'], seen[0].headers['x-yamora-request-id']);
  assert.equal(seen[1].headers['if-none-match'], '*');
  assert.equal(seen[1].headers.authorization, `Bearer ${WRITE}`);
});

test('all mutation receipts remain inside the generated identity error boundary', async t => {
  const { pem } = await certificates(t);
  const operations = [
    ['put', c => c.put('a', 'b', 'n: 1\n'), receipt],
    ['patch', c => c.patch('a', 'b', { $inc: { n: 1n } }), receipt],
    ['transaction', c => c.transaction([{ collection: 'a', document: 'b', patch: { $inc: { n: 1n } } }]), { status: 'committed', operations: 1, revision: REV }],
    ['catalog', c => c.setIndexes([]), CATALOG_RECEIPT]
  ];
  for (const [name, run, good] of operations) {
    for (const variant of ['json', 'revision', 'receipt', 'status', '500', 'bytes', ...(['put', 'patch'].includes(name) ? ['etag', 'coercion'] : [])]) {
      await t.test(`${name}/${variant}`, async t => {
        let id;
        const seed = await server(t, pem, async (req, res) => {
          if (req.url === '/v1/cluster/leader') { json(res, leader); return; }
          await body(req); id = req.headers['x-yamora-request-id'];
          if (variant === '500') { res.writeHead(500); res.end(READ); }
          else if (variant === 'bytes') { res.writeHead(200, { 'Content-Length': '9999' }); res.end(); }
          else json(res, variant === 'json' ? '{broken' : variant === 'receipt' ? {} : variant === 'etag' ? { ...good, etag: 1234567890123456 } :
            variant === 'coercion' ? { ...good, etag: { toString: 'hostile data' } } : good,
            variant === 'revision' ? 'fedcba9876543210' : REV, variant === 'status' ? 202 : 200);
        });
        const client = new sdk.ClusterClient(config([seed], pem, { maxResponseBytes: 512 }));
        await assert.rejects(run(client), error => error instanceof sdk.UncertainWriteError && error instanceof sdk.YamoraError &&
          error.uncertain && error.requestId === id && error.cause instanceof sdk.YamoraError && /^[0-9a-f]{32}$/.test(id) && !error.message.includes(READ));
      });
    }
  }
  const seed = await server(t, pem, (req, res) => {
    if (req.url === '/v1/cluster/leader') json(res, leader);
    else { res.writeHead(204); res.end(); }
  });
  await assert.rejects(new sdk.ClusterClient(config([seed], pem)).delete('a', 'b'), error => error instanceof sdk.UncertainWriteError && error.requestId.length === 32);
});

test('catalog mutations reject malformed committed receipts and recover the same generated ID and exact request', async t => {
  const { pem } = await certificates(t);
  for (const [method, run] of catalogMutations()) {
    for (const [variant, invalid] of INVALID_CATALOG_RECEIPTS) {
      await t.test(`${method}/${variant}`, async t => {
        const writes = [];
        const seed = await server(t, pem, async (req, res) => {
          if (req.url === '/v1/cluster/leader') { json(res, leader); return; }
          if (req.method === 'GET') { json(res, { indexes: method === 'dropIndex' ? [CATALOG_INDEX] : [], revision: REV }); return; }
          writes.push({ bytes: await body(req), id: req.headers['x-yamora-request-id'], condition: req.headers['if-match'] });
          json(res, writes.length === 1 ? invalid : CATALOG_RECEIPT);
        });
        const client = new sdk.ClusterClient(config([seed], pem));
        let failure;
        await assert.rejects(run(client), error => {
          failure = error;
          return error instanceof sdk.UncertainWriteError && error.uncertain && error.requestId === writes[0].id &&
            /^[0-9a-f]{32}$/.test(error.requestId) && error.cause instanceof sdk.YamoraError && error.cause.code === 'PROTOCOL_ERROR';
        });
        assert.equal(writes.length, 1, 'malformed receipt must not silently retry');
        const saved = writes[0];
        const recovered = await client.setIndexes(JSON.parse(saved.bytes).indexes, { requestId: failure.requestId,
          ...(saved.condition === undefined ? {} : { revision: saved.condition.slice(1, -1) }) });
        assert.deepEqual(recovered, CATALOG_RECEIPT);
        assert.equal(writes.length, 2);
        assert.deepEqual(writes[1], saved, 'recovery changed the identity, serialized catalog or precondition');
      });
    }
  }
});

test('validation and conflicts are definitive; an earlier ambiguous dispatch survives later authentication failure', async t => {
  const { pem } = await certificates(t);
  let status = 412, count = 0, id;
  const seed = await server(t, pem, async (req, res) => {
    if (req.url === '/v1/cluster/leader') { res.writeHead(count ? 401 : 200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(leader)); return; }
    count++; id = req.headers['x-yamora-request-id']; await body(req);
    if (status === 0) req.socket.destroy();
    else { res.writeHead(status); res.end(); }
  });
  for (status of [400, 401, 403, 409, 412, 413, 422]) {
    count = 0;
    const client = new sdk.ClusterClient(config([seed], pem));
    await assert.rejects(client.patch('a', 'b', { $inc: { n: 1 } }), error => error.status === status && !error.uncertain);
    assert.equal(count, 1);
  }
  status = 0; count = 0;
  const client = new sdk.ClusterClient(config([seed], pem));
  await assert.rejects(client.put('a', 'b', 'n: 1'), error => error instanceof sdk.UncertainWriteError && error.requestId === id && error.cause.status === 401);
  count = 0;
  await assert.rejects(client.patch('a', 'b', { $inc: { n: 1n << 63n } }), TypeError);
  assert.equal(count, 0);
});

test('discovery never follows redirects or advertised endpoints and ignores stale follower hints', async t => {
  const { pem } = await certificates(t);
  let stolen = 0, dispatched = 0;
  const trap = await server(t, pem, (_req, res) => { stolen++; json(res, leader); });
  for (const redirect of [false, true]) {
    const first = await server(t, pem, (_req, res) => {
      if (redirect) { res.writeHead(307, { Location: `https://127.0.0.1:${trap.port}/stolen` }); res.end(); }
      else json(res, { ...leader, role: 'follower', leader: 9, endpoint: `https://127.0.0.1:${trap.port}` });
    });
    const last = await server(t, pem, (req, res) => {
      if (req.url === '/v1/cluster/leader') json(res, leader);
      else { dispatched++; json(res, { status: 'ok' }); }
    });
    assert.equal((await new sdk.ClusterClient(config([first, last], pem)).health()).status, 'ok');
  }
  assert.equal(stolen, 0); assert.equal(dispatched, 2);
});

test('one overall deadline reserves failover time after a stalled seed or cached leader', async t => {
  const { pem } = await certificates(t);
  const stalled = await rawFixture(t, () => {});
  const good = await server(t, pem, (req, res) => json(res, req.url === '/v1/cluster/leader' ? leader : { status: 'ok' }));
  const client = new sdk.ClusterClient(config([stalled.address, good], pem, { timeoutMs: 800 }));
  const start = performance.now();
  assert.equal((await client.health()).status, 'ok');
  assert.ok(performance.now() - start < 1800);
  let hang = false;
  const first = await server(t, pem, (req, res) => { if (!hang) json(res, req.url === '/v1/cluster/leader' ? leader : { status: 'ok' }); });
  const cached = new sdk.ClusterClient(config([first, good], pem, { timeoutMs: 800 }));
  await cached.health(); hang = true;
  assert.equal((await cached.health()).status, 'ok');
  const only = new sdk.ClusterClient(config([stalled.address, first], pem, { timeoutMs: 160, retryTimeoutMs: 30000 }));
  const before = performance.now();
  await assert.rejects(only.health(), error => error instanceof sdk.YamoraError);
  assert.ok(performance.now() - before < 1000, 'caller timeout was consumed more than once');
});

test('abort cancels discovery, dispatch and retry backoff without consuming the full deadline', async t => {
  const { pem } = await certificates(t);
  for (const phase of ['discovery', 'dispatch', 'backoff']) {
    await t.test(phase, async t => {
      const controller = new AbortController();
      let sent = 0;
      const seed = await server(t, pem, (req, res) => {
        if (phase === 'discovery') { controller.abort(); return; }
        if (req.url === '/v1/cluster/leader') { json(res, leader); return; }
        sent++;
        if (phase === 'dispatch') controller.abort();
        else { res.writeHead(503); res.end(); setTimeout(() => controller.abort(), 10); }
      });
      const client = new sdk.ClusterClient(config([seed], pem));
      const start = performance.now();
      await assert.rejects(client.patch('a', 'b', { $inc: { n: 1 } }, { signal: controller.signal }), error =>
        phase === 'discovery' ? error.code === 'ABORT_ERR' && !error.uncertain : error instanceof sdk.UncertainWriteError && error.cause.code === 'ABORT_ERR');
      assert.ok(performance.now() - start < 1500); assert.equal(sent, phase === 'discovery' ? 0 : 1);
      await assert.rejects(client.health({ signal: AbortSignal.abort() }), error => error.code === 'ABORT_ERR');
    });
  }
});

test('truncated acknowledgement retries identical serialized BigInt bytes and caller identity', async t => {
  const { pem } = await certificates(t);
  const input = { $inc: { n: 9223372036854775807n } };
  const options = { etag: REV, requestId: 'a'.repeat(32) };
  const seen = [];
  const first = await server(t, pem, async (req, res) => {
    if (req.url === '/v1/cluster/leader') { json(res, leader); return; }
    seen.push({ headers: req.headers, bytes: await body(req) });
    input.$inc.n = 2n; options.requestId = 'b'.repeat(32); options.etag = '0'.repeat(16);
    res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': '99', 'X-YamlDB-Revision': REV }); res.end('{');
  });
  const second = await server(t, pem, async (req, res) => {
    if (req.url === '/v1/cluster/leader') { json(res, leader); return; }
    seen.push({ headers: req.headers, bytes: await body(req) }); json(res, receipt);
  });
  assert.deepEqual(await new sdk.ClusterClient(config([first, second], pem)).patch('a', 'b', input, options), receipt);
  assert.equal(seen.length, 2); assert.equal(seen[0].bytes.toString(), '{"$inc":{"n":9223372036854775807}}');
  assert.deepEqual(seen[1].bytes, seen[0].bytes);
  for (const call of seen) {
    assert.equal(call.headers['x-yamora-request-id'], 'a'.repeat(32));
    assert.equal(call.headers['if-match'], `"${REV}"`);
  }
});

test('late concurrent failure cannot invalidate a newer cached leader', async t => {
  const { pem } = await certificates(t);
  let oldResponse, held;
  const waiting = new Promise(resolve => { held = resolve; });
  let hold = false, discoveries = 0, reads = 0;
  const first = await server(t, pem, (req, res) => {
    if (req.url === '/v1/cluster/leader') { discoveries++; json(res, leader); return; }
    if (!hold) { json(res, { status: 'first' }); return; }
    reads++;
    if (reads === 1) { oldResponse = res; held(); }
    else { res.writeHead(503); res.end(); }
  });
  let freshDiscoveries = 0;
  const second = await server(t, pem, (req, res) => {
    if (req.url === '/v1/cluster/leader') { freshDiscoveries++; json(res, leader); }
    else json(res, { status: 'second' });
  });
  const client = new sdk.ClusterClient(config([first, second], pem));
  await client.health(); hold = true;
  const slow = client.health(); await waiting;
  assert.equal((await client.health()).status, 'second');
  oldResponse.writeHead(503); oldResponse.end();
  assert.equal((await slow).status, 'second');
  assert.equal((await client.health()).status, 'second');
  assert.equal(discoveries, 1);
  assert.equal(freshDiscoveries, 1, 'late failure invalidated the newer route');
});

test('late concurrent discovery cannot replace a newer cached route', async t => {
  const { pem } = await certificates(t);
  let oldResponse, held, discoveries = 0;
  const waiting = new Promise(resolve => { held = resolve; });
  const first = await server(t, pem, (req, res) => {
    if (req.url !== '/v1/cluster/leader') { json(res, { status: 'first' }); return; }
    if (++discoveries === 1) { oldResponse = res; held(); }
    else { res.writeHead(503); res.end(); }
  });
  const second = await server(t, pem, (req, res) => json(res, req.url === '/v1/cluster/leader' ? leader : { status: 'second' }));
  const client = new sdk.ClusterClient(config([first, second], pem));
  const slow = client.health(); await waiting;
  assert.equal((await client.health()).status, 'second');
  json(oldResponse, leader);
  assert.equal((await slow).status, 'first');
  assert.equal((await client.health()).status, 'second');
});

test('warming discovery has backoff and a hard total endpoint-attempt bound', async t => {
  const { pem } = await certificates(t);
  let calls = 0;
  const seeds = [];
  for (let i = 0; i < 9; i++) seeds.push(await server(t, pem, (_req, res) => { calls++; json(res, { node: 1, leader: 0, term: 0, role: 'candidate' }); }));
  const start = performance.now();
  await assert.rejects(new sdk.ClusterClient(config(seeds, pem)).health(), sdk.YamoraError);
  assert.equal(calls, 32);
  assert.ok(performance.now() - start >= 300, 'warming spun without backoff');
});

test('discovery response cap, unsafe leader metadata and trickled dispatch all stay bounded', async t => {
  const { pem } = await certificates(t);
  const good = await server(t, pem, (req, res) => json(res, req.url === '/v1/cluster/leader' ? leader : { status: 'ok' }));
  for (const value of ['x'.repeat(600), { ...leader, term: 0 }, { ...leader, leader: 2 },
    { ...leader, node: 10, leader: 10 }, { ...leader, role: 'follower' },
    '{"node":1,"leader":1,"term":18446744073709551616,"role":"leader"}']) {
    const bad = await server(t, pem, (_req, res) => json(res, value));
    assert.equal((await new sdk.ClusterClient(config([bad, good], pem)).health()).status, 'ok');
  }
  const highTerm = await server(t, pem, (req, res) => json(res, req.url === '/v1/cluster/leader' ?
    '{"node":1,"leader":1,"term":18446744073709551615,"role":"leader"}' : { status: 'ok' }));
  assert.equal((await new sdk.ClusterClient(config([highTerm], pem)).health()).status, 'ok');
  const trickled = await server(t, pem, (req, res) => {
    if (req.url === '/v1/cluster/leader') { json(res, leader); return; }
    res.writeHead(200, { 'Content-Type': 'application/json', 'X-YamlDB-Revision': REV }); res.write('{');
    const timer = setInterval(() => res.write(' '), 10); res.once('close', () => clearInterval(timer));
  });
  const before = performance.now();
  await assert.rejects(new sdk.ClusterClient(config([trickled], pem, { timeoutMs: 180 })).patch('a', 'b', { $inc: { n: 1 } }),
    error => error instanceof sdk.UncertainWriteError && error.requestId.length === 32 && error.cause.code === 'TIMEOUT');
  assert.ok(performance.now() - before < 1200);
});

test('catalog read/modify/write consumes the caller timeout once', async t => {
  const { pem } = await certificates(t);
  let writes = 0;
  const seed = await server(t, pem, (req, res) => {
    if (req.url === '/v1/cluster/leader') { json(res, leader); return; }
    if (req.method === 'PUT') writes++;
    const timer = setTimeout(() => json(res, req.method === 'GET' ? { indexes: [], revision: REV } : CATALOG_RECEIPT), 150);
    res.once('close', () => clearTimeout(timer));
  });
  await assert.rejects(new sdk.ClusterClient(config([seed], pem, { timeoutMs: 240 })).createIndex({ collection: 'a', name: 'n', fields: ['n'] }),
    error => error instanceof sdk.UncertainWriteError && error.cause.code === 'TIMEOUT');
  assert.equal(writes, 1);
});

test('HTTPS cluster bypasses startup-enabled environment proxies and global agents', async t => {
  const { pem } = await certificates(t);
  let stolen = 0;
  const proxy = await server(t, pem, (_req, res) => { stolen++; res.writeHead(502); res.end(); });
  const seed = await server(t, pem, (req, res) => json(res, req.url === '/v1/cluster/leader' ? leader : { status: 'ok' }));
  const env = { ...process.env, NODE_USE_ENV_PROXY: '1', NO_PROXY: '', no_proxy: '' };
  for (const key of ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy']) env[key] = `https://127.0.0.1:${proxy.port}`;
  await promisify(execFile)(process.execPath, ['--input-type=module', '-e',
    `import { ClusterClient } from ${JSON.stringify(new URL('../index.js', import.meta.url).href)};
     import https from 'node:https';
     https.globalAgent.createConnection = () => { throw new Error('global agent used'); };
     await new ClusterClient(${JSON.stringify(config([seed], pem, { tls: { ca: pem['ca.pem'].toString() } }))}).health();`],
  { env, timeout: 5000 });
  assert.equal(stolen, 0);
});

test('discovery enforces trust, IP SAN and mutual TLS before tokens reach HTTP', async t => {
  const { pem } = await certificates(t);
  let calls = 0;
  const mutual = await listen(t, https.createServer({ cert: pem['server.pem'], key: pem['server.key'], ca: pem['ca.pem'],
    requestCert: true, rejectUnauthorized: true, minVersion: 'TLSv1.3' }, (req, res) => {
    calls++; assert.equal(req.socket.getProtocol(), 'TLSv1.3');
    assert.equal(req.headers.authorization, `Bearer ${READ}`);
    json(res, req.url === '/v1/cluster/leader' ? leader : { status: 'ok' });
  }));
  await assert.rejects(new sdk.ClusterClient(config([mutual], pem, { timeoutMs: 120 })).health(), sdk.YamoraError);
  await assert.rejects(new sdk.ClusterClient(config([mutual], pem, { tls: {}, timeoutMs: 120 })).health(), sdk.YamoraError);
  assert.equal(calls, 0);
  assert.equal((await new sdk.ClusterClient(config([mutual], pem, { tls: { ca: pem['ca.pem'], cert: pem['client.pem'], key: pem['client.key'] } })).health()).status, 'ok');
  assert.equal(calls, 2);
  const wrong = await listen(t, https.createServer({ cert: pem['wrong.pem'], key: pem['wrong.key'], minVersion: 'TLSv1.3' }, (_req, res) => { calls++; json(res, leader); }));
  await assert.rejects(new sdk.ClusterClient(config([wrong], pem, { timeoutMs: 120 })).health(), sdk.YamoraError);
  assert.equal(calls, 2);
});
