import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as pause } from 'node:timers/promises';
import { Client, YamoraError } from '../index.js';
import { binary, daemon, certificates } from './helpers.js';

test('native daemon: toJSON fields stay ordinary document data', { skip: !binary, timeout: 30000 }, async t => {
  const { client } = await daemon(t);
  const source = '# ordinary field\r\ntoJSON: text\r\n';
  const stored = await client.put('a', 'b', source);
  await t.test('query matches a toJSON data field', async () => {
    const found = await client.query('a', { filter: { toJSON: 'text' } });
    assert.deepEqual(found.documents.map(row => row.id), ['b']);
    assert.equal(found.documents[0].value.toJSON, 'text');
  });
  await t.test('patch updates a toJSON data field and preserves source', async () => {
    await client.patch('a', 'b', { $set: { toJSON: 'updated' } }, { etag: stored.etag });
    assert.equal((await client.get('a', 'b')).source.toString(), '# ordinary field\r\ntoJSON: "updated"\r\n');
    const changed = await client.query('a', { filter: { toJSON: 'updated' } });
    assert.deepEqual(changed.documents.map(row => row.id), ['b']);
    assert.equal((await client.query('a', { filter: { toJSON: 'text' } })).documents.length, 0);
  });
});

test('native daemon: exact YAML, conditions, queries, catalogs, transactions and changes', { skip: !binary, timeout: 60000 }, async t => {
  const { client, config } = await daemon(t);
  assert.equal((await client.health()).status, 'ok');
  assert.equal((await client.ready()).storage, 'native-disk-v2');
  assert.ok(await client.stats());
  assert.match(await client.metrics(), /yamldb_uptime_seconds/);
  await assert.rejects(new Client({ ...config, readToken: 'invalid'.repeat(5) }).collections(), error => error.status === 401);
  await assert.rejects(new Client({ ...config, writeToken: config.readToken }).put('people', 'one', 'n: 1\n'), error => error.status === 401);
  const authored = Buffer.from('# keep comments\r\nname: Alpha\r\nn: 1 # keep inline\r\nwide: 9223372036854775807\r\n');
  const first = await client.put('people', 'one', authored, { createOnly: true });
  assert.deepEqual((await client.get('people', 'one', { revision: first.revision })).source, authored);
  for (const attempt of [
    () => client.put('people', 'one', authored, { createOnly: true }),
    () => client.patch('people', 'one', { $inc: { n: 1 } }, { etag: '0'.repeat(16) }),
    () => client.delete('people', 'one', { etag: '0'.repeat(16) })
  ]) await assert.rejects(attempt(), error => error.status === 412 && !error.uncertain);
  const updated = await client.patch('people', 'one', { $inc: { n: 1 } }, { etag: first.etag });
  const patched = await client.get('people', 'one');
  assert.match(patched.source.toString(), /^# keep comments\r\n/);
  assert.match(patched.source.toString(), /n: 2 # keep inline\r\n/);
  assert.notEqual(updated.etag, first.etag);
  const created = await client.createIndex({ collection: 'people', name: 'by-name', fields: ['name'], unique: true });
  assert.equal(created.status, 'committed'); assert.equal(created.operations, 1);
  await client.createIndex({ collection: 'people', name: 'words', fields: ['$source'], type: 'text' });
  const catalog = await client.indexes();
  assert.equal(catalog.indexes.length, 2);
  const replaced = await client.setIndexes(catalog.indexes, { revision: catalog.revision });
  assert.equal(replaced.status, 'committed'); assert.equal(replaced.operations, 1);
  const checkpoint = await client.changes();
  const exact = '# transaction\r\nname: Beta\r\nn: 8\r\nwide: -9223372036854775808\r\n';
  const receipt = await client.transaction([
    { collection: 'people', document: 'two', put: exact, create_only: true },
    { collection: 'people', document: 'one', patch: { $set: { name: 'Omega' } }, etag: updated.etag }
  ], { revision: replaced.revision });
  assert.equal(receipt.operations, 2);
  assert.equal((await client.get('people', 'two')).source.toString(), exact);
  const query = await client.query('people', { sort: { n: 'desc' }, limit: 1, explain: true });
  assert.equal(query.documents[0].id, 'two');
  assert.equal(query.documents[0].value.wide, -9223372036854775808n);
  const next = await client.query('people', { sort: { n: 'desc' }, limit: 1, after: query.next_after, revision: query.revision });
  assert.equal(next.documents[0].value.wide, 9223372036854775807n);
  assert.equal(await client.count('people'), 2);
  assert.equal((await client.query('people', { filter: { wide: 9223372036854775807n } })).documents[0].id, 'one');
  assert.deepEqual((await client.aggregate('people', [{ $group: { _id: null, total: { $sum: '$n' } } }])).documents, [{ _id: null, total: 10 }]);
  assert.equal((await client.search('people', { index: 'words', text: 'keep comments' })).documents[0].id, 'one');
  const collections = await client.collections(); assert.ok(collections.collections.includes('people'));
  const ids = []; for await (const id of client.documents('people', { limit: 1 })) ids.push(id);
  assert.deepEqual(ids, ['one', 'two']);
  const changes = await client.changes({ after: checkpoint.next_after, limit: 1 });
  assert.equal(changes.transactions.length, 1);
  assert.equal(changes.transactions[0].operations.find(op => op.document === 'two').put, exact);
  assert.equal(changes.next_after, changes.transactions[0].token);
  const before = (await client.ready()).revision;
  await assert.rejects(client.transaction([
    { collection: 'people', document: 'one', patch: { $set: { n: 99 } } },
    { collection: 'people', document: 'two', delete: true, etag: '0'.repeat(16) }
  ]), error => error.status === 412);
  assert.equal((await client.ready()).revision, before);
  await client.delete('people', 'two');
  await assert.rejects(client.query('people', { after: query.next_after, revision: query.revision }), error => error.status === 412);
  await assert.rejects(client.get('people', 'two'), error => error.status === 404);
  const dropped = await client.dropIndex('people', 'by-name');
  assert.equal(dropped.status, 'committed'); assert.equal(dropped.operations, 1);
  assert.equal((await client.indexes()).indexes.length, 1);
});

test('native daemon: verified mTLS CRUD and actual authentication failures', { skip: !binary, timeout: 60000 }, async t => {
  const tls = await certificates(t);
  const { client, config } = await daemon(t, tls);
  const authored = '# mTLS exact\r\nname: café\r\n';
  const stored = await client.put('services', 'api', authored, { createOnly: true });
  assert.equal((await client.get('services', 'api')).source.toString(), authored);
  await client.delete('services', 'api', { etag: stored.etag });
  await assert.rejects(new Client({ ...config, tls: {} }).health(), YamoraError);
  await assert.rejects(new Client({ ...config, tls: { ca: tls.pem['ca.pem'] } }).health(), YamoraError);
});

test('native daemon: online catalog jobs and large exact sources', { skip: !binary, timeout: 60000 }, async t => {
  const { client } = await daemon(t);
  assert.equal((await client.indexBuild()).status, 'idle');
  const source = '# large exact source\r\nn: 1\r\ntext: ' + 'é'.repeat(160000) + '\r\n';
  const stored = await client.put('examples', 'large', source);
  assert.equal((await client.get('examples', 'large')).source.toString(), source);
  const job = await client.startIndexBuild([{ collection: 'examples', name: 'number', fields: ['n'] }], { revision: stored.revision });
  let done = job;
  const deadline = performance.now() + 10000;
  while (done.status === 'running' && performance.now() < deadline) {
    await pause(25);
    done = await client.indexBuild(job.id);
  }
  assert.equal(done.status, 'succeeded');
  assert.ok(done.documents_scanned >= 1);
  await client.put('examples', 'later', 'n: 2\n');
  // Job publication revision is deliberately older than the HTTP head here.
  assert.equal((await client.indexBuild(job.id)).revision, done.revision);
  await assert.rejects(client.cancelIndexBuild(job.id), error => error.status === 409);
  await assert.rejects(client.startIndexBuild([], { revision: stored.revision }), error => error.status === 412);
});
