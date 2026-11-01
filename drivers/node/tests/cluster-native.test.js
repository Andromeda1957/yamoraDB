import { test } from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { ClusterClient, Client, YamoraError, UncertainWriteError } from '../index.js';
import { configuration, request } from '../lib/transport.js';
import { binary, listen, json, CATALOG_INDEX } from './helpers.js';
import { nativeCluster } from './cluster-helpers.js';

test('native three-node mTLS: representative APIs, lost committed reply, leader loss and exact-once identities', { skip: !binary, timeout: 90000 }, async t => {
  const cluster = await nativeCluster(t);
  const client = new ClusterClient(cluster.config);
  const authored = '# exact source\r\nname: Alpha\r\ncount: 0 # retained\r\nwide: 9223372036854775807\r\n';
  const putId = '1'.repeat(32);
  const put = await client.put('manifests', 'counter', authored, { createOnly: true, requestId: putId });
  assert.deepEqual(await client.put('manifests', 'counter', authored, { createOnly: true, requestId: putId }), put);
  assert.equal((await client.get('manifests', 'counter')).source.toString(), authored);
  assert.equal((await client.health()).status, 'ok');
  assert.ok(await client.stats()); assert.match(await client.metrics(), /yamldb_uptime_seconds/);
  assert.ok((await client.collections()).collections.includes('manifests'));
  assert.deepEqual((await client.documentPage('manifests')).documents, ['counter']);
  assert.deepEqual((await client.query('manifests', { filter: { wide: 9223372036854775807n } })).documents.map(row => row.id), ['counter']);
  assert.equal((await client.query('manifests')).documents[0].value.wide, 9223372036854775807n);
  await assert.rejects(new ClusterClient({ ...cluster.config, maxDocumentBytes: 16 }).get('manifests', 'counter'),
    error => error.code === 'RESPONSE_LIMIT' && !error.uncertain);
  assert.equal((await client.aggregate('manifests', [{ $group: { _id: null, total: { $sum: '$count' } } }])).documents[0].total, 0);
  await assert.rejects(client.patch('manifests', 'counter', { $inc: { count: 1 } }, { etag: '0'.repeat(16) }), error => error.status === 412 && !error.uncertain);
  await assert.rejects(new ClusterClient({ ...cluster.config, writeToken: cluster.config.readToken }).patch('manifests', 'counter', { $inc: { count: 1 } }), error => error.status === 401 && !error.uncertain);
  await assert.rejects(new Client({ ...cluster.config.seeds[0], tls: { ca: cluster.tls.pem['ca.pem'] } }).health(), YamoraError);

  const checkpoint = await client.changes();
  const oldLeader = await cluster.leader();
  let dropped = false, upstreamReceipt, id, firstBody;
  const gateway = await listen(t, https.createServer({ cert: cluster.tls.pem['server.pem'], key: cluster.tls.pem['server.key'],
    ca: cluster.tls.pem['ca.pem'], requestCert: true, rejectUnauthorized: true, minVersion: 'TLSv1.3' }, async (req, res) => {
    try {
      if (dropped) { res.writeHead(503); res.end(); return; }
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      const bytes = Buffer.concat(chunks);
      const upstream = configuration({ ...cluster.config.seeds[oldLeader], tls: cluster.config.tls,
        readToken: cluster.config.readToken, writeToken: cluster.config.writeToken, timeoutMs: 10000 });
      const response = await request(upstream, req.method, req.url, bytes.length ? bytes : undefined,
        { ...(bytes.length ? { 'Content-Type': req.headers['content-type'] } : {}) }, req.method === 'PATCH',
        req.method === 'PATCH' ? { requestId: req.headers['x-yamora-request-id'] } : {}, [200]);
      if (req.method === 'PATCH') {
        dropped = true; id = req.headers['x-yamora-request-id']; firstBody = bytes; upstreamReceipt = JSON.parse(response.body);
        await cluster.stop(oldLeader, true); req.socket.destroy(); return;
      }
      res.writeHead(response.status, response.headers); res.end(response.body);
    } catch { res.writeHead(503); res.end(); }
  }));
  const routed = new ClusterClient({ ...cluster.config, seeds: [gateway, ...cluster.config.seeds] });
  const recovered = await routed.patch('manifests', 'counter', { $inc: { count: 1n } });
  assert.equal(dropped, true); assert.match(id, /^[0-9a-f]{32}$/);
  assert.equal(firstBody.toString(), '{"$inc":{"count":1}}');
  assert.deepEqual(recovered, upstreamReceipt);
  assert.deepEqual(await client.patch('manifests', 'counter', { $inc: { count: 1n } }, { requestId: id }), recovered);
  assert.equal((await client.get('manifests', 'counter')).source.toString(), authored.replace('count: 0', 'count: 1'));
  const changes = await client.changes({ after: checkpoint.next_after });
  assert.equal(changes.transactions.flatMap(frame => frame.operations).filter(op => op.document === 'counter').length, 1);

  const txId = '2'.repeat(32);
  const operations = [{ collection: 'manifests', document: 'counter', patch: { $inc: { count: 1n } } },
    { collection: 'manifests', document: 'second', put: 'name: Beta\nwide: -9223372036854775808\n', create_only: true }];
  const tx = await client.transaction(operations, { requestId: txId });
  assert.deepEqual(await client.transaction(operations, { requestId: txId }), tx);
  assert.equal((await client.query('manifests', { filter: { name: 'Beta' } })).documents[0].value.wide, -9223372036854775808n);
  const indexes = [{ collection: 'manifests', name: 'count', fields: ['count'] }, { collection: 'manifests', name: 'text', fields: ['$source'], type: 'text' }];
  const catalog = await client.setIndexes(indexes, { requestId: '3'.repeat(32) });
  assert.deepEqual(await client.setIndexes(indexes, { requestId: '3'.repeat(32) }), catalog);
  assert.equal((await client.indexes()).indexes.length, 2);
  assert.equal((await client.search('manifests', { index: 'text', text: 'retained' })).documents[0].id, 'counter');
  const deleted = await client.delete('manifests', 'second', { requestId: '4'.repeat(32) });
  await client.put('manifests', 'second', 'name: recreated\n');
  assert.deepEqual(await client.delete('manifests', 'second', { requestId: '4'.repeat(32) }), deleted);
  assert.equal((await client.get('manifests', 'second')).source.toString(), 'name: recreated\n');
  await Promise.all(Array.from({ length: 8 }, () => client.patch('manifests', 'counter', { $inc: { count: 1n } })));
  assert.match((await client.get('manifests', 'counter')).source.toString(), /count: 10 # retained/);
  assert.equal(await client.count('manifests'), 2);
  await client.createIndex({ collection: 'manifests', name: 'name', fields: ['name'] });
  await client.dropIndex('manifests', 'name');
  await assert.rejects(client.startIndexBuild([]), error => error.status === 405 && !error.uncertain);
  const elected = await cluster.leader();
  for (let i = 0; i < 3; i++) if (i !== elected && i !== oldLeader) await cluster.stop(i, true);
  const isolated = new ClusterClient({ ...cluster.config, timeoutMs: 700 });
  const before = performance.now();
  await assert.rejects(isolated.get('manifests', 'counter'), error => error.code === 'TIMEOUT');
  assert.ok(performance.now() - before < 2000);
  await assert.rejects(isolated.get('manifests', 'counter', { signal: AbortSignal.timeout(80) }),
    error => error.code === 'ABORT_ERR' && !error.uncertain);
});

test('native three-node mTLS: all catalog mutations recover committed malformed receipts with the same ID', { skip: !binary, timeout: 60000 }, async t => {
  const cluster = await nativeCluster(t);
  await new ClusterClient(cluster.config).put('a', 'b', 'n: 1\n');
  const target = await cluster.leader();
  const upstream = configuration({ ...cluster.config.seeds[target], tls: cluster.config.tls,
    readToken: cluster.config.readToken, writeToken: cluster.config.writeToken, timeoutMs: 10000 });
  let corrupt = false, writes = [];
  const gateway = await listen(t, https.createServer({ cert: cluster.tls.pem['server.pem'], key: cluster.tls.pem['server.key'],
    ca: cluster.tls.pem['ca.pem'], requestCert: true, rejectUnauthorized: true, minVersion: 'TLSv1.3' }, async (req, res) => {
    try {
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      const bytes = Buffer.concat(chunks);
      const write = req.method === 'PUT';
      const response = await request(upstream, req.method, req.url, bytes.length ? bytes : undefined,
        { ...(bytes.length ? { 'Content-Type': req.headers['content-type'] } : {}),
          ...(req.headers['if-match'] === undefined ? {} : { 'If-Match': req.headers['if-match'] }) }, write,
        write ? { requestId: req.headers['x-yamora-request-id'] } : {}, [200]);
      if (write) {
        const receipt = JSON.parse(response.body);
        writes.push({ bytes, id: req.headers['x-yamora-request-id'], condition: req.headers['if-match'], receipt });
        if (corrupt) { corrupt = false; json(res, { status: 'failed', operations: 0, revision: receipt.revision }, receipt.revision); return; }
      }
      res.writeHead(response.status, response.headers); res.end(response.body);
    } catch { res.writeHead(503); res.end(); }
  }));
  const client = new ClusterClient({ ...cluster.config, seeds: [gateway] });
  const other = { ...CATALOG_INDEX, name: 'other' };
  for (const [method, run, names] of [
    ['setIndexes', () => client.setIndexes([CATALOG_INDEX]), ['n']],
    ['createIndex', () => client.createIndex(other), ['n', 'other']],
    ['dropIndex', () => client.dropIndex('a', 'other'), ['n']]
  ]) {
    await t.test(method, async () => {
      writes = []; corrupt = true;
      let failure;
      await assert.rejects(run(), error => { failure = error; return error instanceof UncertainWriteError && error.requestId === writes[0]?.id; });
      assert.equal(writes.length, 1);
      const saved = writes[0];
      assert.equal(saved.receipt.status, 'committed'); assert.equal(saved.receipt.operations, 1);
      const recovered = await client.setIndexes(JSON.parse(saved.bytes).indexes, { requestId: failure.requestId,
        ...(saved.condition === undefined ? {} : { revision: saved.condition.slice(1, -1) }) });
      assert.deepEqual(recovered, saved.receipt);
      assert.equal(writes.length, 2); assert.deepEqual(writes[1], saved);
      assert.deepEqual((await client.indexes()).indexes.map(index => index.name).sort(), names);
    });
  }
});
