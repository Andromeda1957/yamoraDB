import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { spawn } from 'node:child_process';
import { mkdir, readFile, writeFile, copyFile, symlink, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { certificates, scratch, listen, READ, WRITE, REV, json } from './helpers.js';

// Synthetic TLS peers exercise adapter controls only, never native qualification.
const adapter = fileURLToPath(new URL('../conformance/http_replica.mjs', import.meta.url));
const SCHEMA = 'yamora-http-replica-command/2';
const ID = '1'.repeat(32);
const SOURCE = Buffer.from('# receipt\r\nn: 0 # keep\r\n');
function sourceTag(source) {
  let value = 1469598103934665603n;
  for (const byte of source) value = BigInt.asUintN(64, (value ^ BigInt(byte)) * 1099511628211n);
  return value.toString(16).padStart(16, '0');
}
const RECEIPT = { status: 'stored', collection: 'manifests', document: 'counter', etag: REV, revision: REV };
const call = (seq = 1, change = {}) => ({ schema: SCHEMA, seq, action: 'call', method: 'PUT',
  collection: 'manifests', document: 'counter', source_file: 'input/a.bin', request_id: ID,
  if_match: null, if_none_match: null, ...change });
const close = seq => ({ schema: SCHEMA, seq, action: 'close' });
const recover = (seq, handle = 'h1') => ({ schema: SCHEMA, seq, action: 'recover', handle });

async function fixture(t) {
  const tls = await certificates(t), root = await scratch(t);
  await mkdir(join(root, 'input'));
  for (const [from, to] of [['ca.pem', 'ca.pem'], ['client.pem', 'client.pem'], ['client.key', 'client.key']])
    await copyFile(join(tls.root, from), join(root, to));
  await writeFile(join(root, 'read.token'), READ);
  await writeFile(join(root, 'write.token'), WRITE);
  await writeFile(join(root, 'input/a.bin'), SOURCE);
  await writeFile(join(root, 'input/patch.bin'), '{ "$inc" : { "n" : 1 } }\n');
  const seen = [];
  let handler = (_req, res) => { res.writeHead(409); res.end(); };
  const seeds = [];
  for (let node = 1; node <= 3; node++) {
    const server = https.createServer({ ca: tls.pem['ca.pem'], cert: tls.pem['server.pem'], key: tls.pem['server.key'],
      requestCert: true, rejectUnauthorized: true, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' }, async (req, res) => {
      const chunks = [];
      for await (const bytes of req) chunks.push(bytes);
      const entry = { method: req.method, path: req.url, headers: req.headers, body: Buffer.concat(chunks), node };
      seen.push(entry);
      if (req.url === '/v1/cluster/leader') json(res, { node, leader: node, term: 1, role: 'leader' });
      else handler(req, res, entry);
    });
    seeds.push({ ...await listen(t, server), node });
  }
  const config = { schema: 'yamora-http-replica-config/2', cluster_id: '01020304000000000000000000000000', voters: 3,
    seeds, tls: { ca_file: 'ca.pem', cert_file: 'client.pem', key_file: 'client.key' },
    tokens: { read_file: 'read.token', write_file: 'write.token' }, timeout_ms: 15000, attempt_timeout_ms: 3000 };
  await writeFile(join(root, 'config.json'), JSON.stringify(config));
  return { root, config, seen, mutations: () => seen.filter(entry => entry.method !== 'GET'),
    handler: fn => { handler = fn; } };
}
async function session(t, f, argv = ['--config', join(f.root, 'config.json'), '--root', f.root]) {
  const child = spawn(process.execPath, [adapter, ...argv], { env: { ...process.env, TMPDIR: process.env.TMPDIR }, stdio: ['pipe', 'pipe', 'pipe'] });
  const ended = new Promise((resolve, reject) => {
    child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal }));
  });
  let stdout = '', stderr = '', pending = '', wake;
  const lines = [];
  child.stdin.on('error', () => {});
  child.stderr.on('data', chunk => { stderr += chunk; });
  child.stdout.on('data', chunk => {
    stdout += chunk; pending += chunk;
    while (pending.includes('\n')) {
      const at = pending.indexOf('\n'); lines.push(JSON.parse(pending.slice(0, at))); pending = pending.slice(at + 1);
    }
    wake?.();
  });
  const outer = setTimeout(() => child.kill('SIGKILL'), 25000);
  t.after(async () => {
    clearTimeout(outer);
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await ended;
  });
  async function send(command) {
    await mkdir(join(f.root, `call-${String(command.seq).padStart(6, '0')}`), { recursive: true });
    const before = lines.length;
    child.stdin.write(JSON.stringify(command) + '\n');
    while (lines.length === before) {
      const next = new Promise(resolve => { wake = resolve; });
      const result = await Promise.race([next.then(() => null), ended]);
      if (result) throw new Error(`adapter exited: ${JSON.stringify(result)} ${stderr}`);
    }
    wake = undefined; return lines[before];
  }
  return { child, send, ended, text: () => ({ stdout, stderr, lines }) };
}
function api(extra = {}) {
  return { status: null, body_file: null, etag: null, revision: null, receipt: null, ...extra };
}
function assertObservation(value, seq, action) {
  assert.deepEqual(Object.keys(value).sort(), ['schema', 'seq', 'action', 'outcome', 'error_kind', 'elapsed_ns', 'api',
    'sdk_request_id', 'envelope', 'recovery_mode', 'recovery_handle'].sort());
  assert.equal(value.schema, 'yamora-http-replica-observation/2'); assert.equal(value.seq, seq); assert.equal(value.action, action);
  assert.ok(Number.isSafeInteger(value.elapsed_ns) && value.elapsed_ns >= 0);
  assert.ok(Buffer.byteLength(JSON.stringify(value) + '\n') <= 16384);
}
async function finish(s, seq) {
  const result = await s.send(close(seq));
  assertObservation(result, seq, 'close');
  assert.deepEqual(result, { schema: 'yamora-http-replica-observation/2', seq, action: 'close', outcome: 'closed',
    error_kind: null, elapsed_ns: 0, api: api(), sdk_request_id: null, envelope: null, recovery_mode: null, recovery_handle: null });
  assert.deepEqual(await s.ended, { code: 0, signal: null });
  assert.equal(s.text().stderr, '');
}

async function rejectsBeforeObservation(s, line) {
  const output = new Promise(resolve => s.child.stdout.once('data', () => resolve({ observation: s.text().lines[0] })));
  s.child.stdin.write(line);
  const first = await Promise.race([output, s.ended.then(({ code }) => ({ exit: code }))]);
  assert.deepEqual(first, { exit: 2 });
  assert.equal(s.text().stdout, '');
}

for (const variant of ['cr-frame', 'float-sequence', 'float-patch', 'config-limit', 'pem-limit'])
  test(`negative: committed validator boundary ${variant}`, async t => {
    const f = await fixture(t);
    await mkdir(join(f.root, 'call-000001'));
    let command = call();
    if (variant === 'float-patch') {
      await writeFile(join(f.root, 'input/patch.bin'), '{"$inc":{"n":1.0}}');
      command = call(1, { method: 'PATCH', source_file: 'input/patch.bin' });
    }
    if (variant === 'config-limit') {
      const config = JSON.stringify(f.config);
      await writeFile(join(f.root, 'config.json'), config + ' '.repeat(16385 - Buffer.byteLength(config)));
      command = close(1);
    }
    if (variant === 'pem-limit') {
      const pem = await readFile(join(f.root, 'ca.pem'));
      await writeFile(join(f.root, 'ca.pem'), Buffer.concat([pem, Buffer.alloc(16385 - pem.length, 32)]));
      command = close(1);
    }
    let line = JSON.stringify(command) + '\n';
    if (variant === 'cr-frame') line = line.slice(0, -1) + '\r\n';
    if (variant === 'float-sequence') line = line.replace('"seq":1', '"seq":1.0');
    const s = await session(t, f);
    await rejectsBeforeObservation(s, line);
    assert.equal(f.seen.length, 0);
  });

test('control: exact source bytes, supplied/generated ID, present/absent preconditions and definitive rejections', async t => {
  const f = await fixture(t), s = await session(t, f);
  const variations = [{ if_none_match: '*' }, { if_match: `"${REV}"` }, {}, { request_id: null },
    { method: 'PATCH', source_file: 'input/patch.bin', if_match: `"${REV}"` }, { method: 'DELETE', source_file: null }];
  for (let i = 0; i < variations.length; i++) {
    const result = await s.send(call(i + 1, variations[i]));
    assertObservation(result, i + 1, 'call');
    assert.equal(result.outcome, 'status'); assert.equal(result.error_kind, 'status');
    assert.deepEqual(result.api, api({ status: 409 }));
    assert.deepEqual([result.sdk_request_id, result.envelope, result.recovery_mode, result.recovery_handle], [null, null, null, null]);
  }
  const writes = f.mutations(); assert.equal(writes.length, variations.length);
  for (let i = 0; i < 4; i++) assert.deepEqual(writes[i].body, SOURCE);
  assert.equal(writes[0].headers['if-none-match'], '*'); assert.equal(writes[0].headers['if-match'], undefined);
  assert.equal(writes[1].headers['if-match'], `"${REV}"`); assert.equal(writes[1].headers['if-none-match'], undefined);
  assert.equal(writes[2].headers['if-match'], undefined); assert.equal(writes[2].headers['if-none-match'], undefined);
  assert.equal(writes[2].headers['x-yamora-request-id'], ID);
  assert.match(writes[3].headers['x-yamora-request-id'], /^(?!0{32}$)[0-9a-f]{32}$/);
  assert.deepEqual(writes[4].body, Buffer.from('{"$inc":{"n":1}}'));
  assert.equal(writes[5].body.length, 0);
  await finish(s, variations.length + 1);
});

test('control: nullable public success exposure and byte-exact GET output', async t => {
  const f = await fixture(t);
  f.handler((req, res) => {
    if (req.method === 'GET') { res.writeHead(200, { 'Content-Type': 'application/yaml', 'X-YamlDB-Revision': REV, ETag: `"${sourceTag(SOURCE)}"` }); res.end(SOURCE); }
    else if (req.method === 'DELETE') { res.writeHead(204, { 'X-YamlDB-Revision': REV }); res.end(); }
    else json(res, RECEIPT, REV, 201);
  });
  const s = await session(t, f);
  const put = await s.send(call(1, { request_id: null }));
  assert.equal(put.outcome, 'success'); assert.deepEqual(put.api, api({ etag: REV, revision: REV, receipt: RECEIPT }));
  assert.equal(put.sdk_request_id, null); assert.equal(put.recovery_handle, null);
  const get = await s.send(call(2, { method: 'GET', source_file: null, request_id: null }));
  assert.deepEqual(get.api, api({ body_file: 'call-000002/body.bin', etag: sourceTag(SOURCE), revision: REV }));
  assert.deepEqual(await readFile(join(f.root, get.api.body_file)), SOURCE);
  const del = await s.send(call(3, { method: 'DELETE', source_file: null }));
  assert.deepEqual(del.api, api({ revision: REV }));
  await finish(s, 4);
});

for (const generated of [false, true]) test(`control: retained actual uncertainty and immutable caller reissue (${generated ? 'generated' : 'supplied'} ID)`, async t => {
  const f = await fixture(t);
  // Invalid acknowledgement gives real SDK typed uncertainty without a timeout.
  f.handler((_req, res) => json(res, { invalid: true }));
  const s = await session(t, f);
  const first = await s.send(call(1, { request_id: generated ? null : ID, if_match: `"${REV}"` }));
  assert.equal(first.outcome, 'uncertain'); assert.equal(first.error_kind, 'protocol');
  assert.equal(first.recovery_handle, 'h1'); assert.equal(first.recovery_mode, 'caller-reissue'); assert.equal(first.envelope, null);
  const before = f.mutations()[0]; assert.equal(first.sdk_request_id, before.headers['x-yamora-request-id']);
  if (!generated) assert.equal(first.sdk_request_id, ID);
  await writeFile(join(f.root, 'input/a.bin'), '# changed after uncertainty\nn: 9\n');
  f.handler((_req, res) => json(res, RECEIPT));
  for (const seq of [2, 3]) {
    const result = await s.send(recover(seq));
    assert.equal(result.outcome, 'success'); assert.equal(result.recovery_handle, 'h1'); assert.equal(result.recovery_mode, 'caller-reissue');
    assert.equal(result.sdk_request_id, null); assert.equal(result.envelope, null); assert.deepEqual(result.api.receipt, RECEIPT);
    const after = f.mutations().at(-1);
    assert.equal(after.method, before.method); assert.equal(after.path, before.path); assert.deepEqual(after.body, SOURCE);
    assert.equal(after.headers['x-yamora-request-id'], first.sdk_request_id); assert.equal(after.headers['if-match'], `"${REV}"`);
  }
  await finish(s, 4);
});

test('control: handle retained across uncertain recovery; PATCH owns typed encoded primitive', async t => {
  const f = await fixture(t); f.handler((_req, res) => json(res, { invalid: true }));
  const s = await session(t, f);
  const first = await s.send(call(1, { method: 'PATCH', source_file: 'input/patch.bin', request_id: null }));
  const second = await s.send(recover(2));
  assert.equal(second.outcome, 'uncertain'); assert.equal(second.sdk_request_id, first.sdk_request_id); assert.equal(second.recovery_handle, 'h1');
  await writeFile(join(f.root, 'input/patch.bin'), '{"$inc":{"n":9007199254740993}}');
  f.handler((_req, res) => json(res, RECEIPT));
  assert.equal((await s.send(recover(3))).outcome, 'success');
  for (const write of f.mutations()) assert.deepEqual(write.body, Buffer.from('{"$inc":{"n":1}}'));
  await finish(s, 4);
});

test('control: SDK automatic retry retains actual exception ID and bytes before caller recovery', async t => {
  const f = await fixture(t);
  let count = 0;
  f.handler((req, res) => {
    if (++count === 1) req.socket.destroy();
    else { res.writeHead(409); res.end(); }
  });
  const s = await session(t, f);
  const result = await s.send(call(1, { request_id: null }));
  assert.equal(result.outcome, 'uncertain'); assert.equal(result.error_kind, 'status'); assert.equal(result.api.status, 409);
  assert.equal(f.mutations().length, 2);
  for (const item of f.mutations()) {
    assert.equal(item.headers['x-yamora-request-id'], result.sdk_request_id);
    assert.deepEqual(item.body, SOURCE);
  }
  await finish(s, 2);
});

test('negative: handled initial status errors never create a recovery handle', async t => {
  const f = await fixture(t), s = await session(t, f);
  for (let i = 0; i < 7; i++) {
    const status = [400, 401, 403, 409, 412, 413, 422][i];
    f.handler((_req, res) => { res.writeHead(status); res.end(); });
    const result = await s.send(call(i + 1));
    assert.equal(result.outcome, 'status'); assert.equal(result.api.status, status);
    assert.equal(result.recovery_handle, null); assert.equal(result.sdk_request_id, null);
  }
  s.child.stdin.write(JSON.stringify(recover(8)) + '\n');
  assert.deepEqual(await s.ended, { code: 2, signal: null });
  assert.equal(f.mutations().length, 7);
});

test('negative: malformed commands and unsafe sources reject before any dispatch', async t => {
  const f = await fixture(t);
  const nested = '{"a":'.repeat(13) + '0' + '}'.repeat(13);
  const invalid = [
    'not json\n', JSON.stringify(call()).replace('"seq":1', '"seq":1,"seq":1') + '\n',
    JSON.stringify(call()).replace('"seq":1', '"seq":1e999') + '\n', nested + '\n',
    JSON.stringify(call(2)) + '\n', JSON.stringify(call(1, { extra: true })) + '\n',
    ...[{ source_file: '../a.bin' }, { source_file: '/etc/passwd' }, { source_file: 'input/../a.bin' },
      { source_file: 'input/link.bin' }, { source_file: 'input/large.bin' }, { source_file: 'input/empty.bin' },
      { source_file: 'input/invalid.bin' }, { source_file: 'input/badpatch.bin', method: 'PATCH' },
      { source_file: 'input/bigint.bin', method: 'PATCH' }, { source_file: 'input/duplicate.bin', method: 'PATCH' },
      { request_id: '0'.repeat(32) }, { if_match: REV }, { if_match: `"${REV}"`, if_none_match: '*' },
      { method: 'PATCH', source_file: 'input/patch.bin', if_none_match: '*' }, { collection: 'yamldb-system' },
      { method: 'GET', source_file: null }, { method: 'DELETE' }].map(change => JSON.stringify(call(1, change)) + '\n'),
    ' '.repeat(16384) + '\n', Buffer.from([0xff, 10]), JSON.stringify(recover(1)) + '\n'
  ];
  await symlink(join(f.root, 'input/a.bin'), join(f.root, 'input/link.bin'));
  for (const [name, content] of [['large', Buffer.alloc(131073, 97)], ['empty', ''], ['invalid', Buffer.from([255])],
    ['badpatch', '{"$inc":{"n":2}}'], ['bigint', '{"$inc":{"n":9007199254740993}}'], ['duplicate', '{"$inc":{"n":1,"n":1}}']])
    await writeFile(join(f.root, `input/${name}.bin`), content);
  await mkdir(join(f.root, 'call-000001'));
  for (const line of invalid) {
    const s = await session(t, f); s.child.stdin.write(line);
    assert.deepEqual(await s.ended, { code: 2, signal: null });
    assert.equal(s.text().stdout, ''); assert.equal(s.text().stderr, 'Node HTTP replica adapter failed\n');
  }
  assert.equal(f.seen.length, 0);
});

test('negative: strict argv/config, symlink paths and missing output directory reject without network', async t => {
  const f = await fixture(t);
  const original = JSON.stringify(f.config);
  for (const mutate of [c => { c.seeds[0].host = 'localhost'; }, c => { c.seeds[1].node = 1; },
    c => { c.seeds[1].port = c.seeds[0].port; }, c => { c.seeds[0].port = 8000; },
    c => { c.cluster_id = '0'.repeat(32); }, c => { c.tls.key_file = '../client.key'; },
    c => { c.timeout_ms = 16000; }, c => { c.attempt_timeout_ms = 4000; }, c => { c.extra = true; }]) {
    const config = JSON.parse(original); mutate(config); await writeFile(join(f.root, 'config.json'), JSON.stringify(config));
    const s = await session(t, f); assert.equal((await s.ended).code, 2); assert.equal(s.text().stdout, '');
  }
  await writeFile(join(f.root, 'config.json'), original);
  const args = ['--config', join(f.root, 'input/a.bin'), '--root', f.root];
  assert.equal((await (await session(t, f, args)).ended).code, 2);
  const missing = await session(t, f); missing.child.stdin.write(JSON.stringify(call()) + '\n');
  assert.equal((await missing.ended).code, 2);
  await symlink(join(f.root, 'input'), join(f.root, 'call-000001'));
  const link = await session(t, f); link.child.stdin.write(JSON.stringify(call()) + '\n');
  assert.equal((await link.ended).code, 2);
  assert.equal(f.seen.length, 0); assert.deepEqual((await readdir(join(f.root, 'input'))).sort(), ['a.bin', 'patch.bin']);
});

test('control: exact line/file boundaries; 64-command limit and 16 retained handles', async t => {
  const f = await fixture(t);
  const s = await session(t, f);
  await writeFile(join(f.root, 'input/a.bin'), Buffer.alloc(131072, 97));
  for (let seq = 1; seq <= 64; seq++) {
    const result = await s.send(call(seq));
    assert.equal(result.outcome, 'status'); assert.equal(result.api.status, 409);
  }
  assert.equal(f.mutations().length, 64); assert.equal(f.mutations()[0].body.length, 131072);
  s.child.stdin.write(JSON.stringify(close(65)) + '\n');
  assert.equal((await s.ended).code, 2);
  const line = await session(t, f);
  const text = JSON.stringify(close(1));
  line.child.stdin.write(text + ' '.repeat(16383 - Buffer.byteLength(text)) + '\n');
  assert.equal((await line.ended).code, 0); assert.equal(line.text().lines[0].outcome, 'closed');
  f.handler((_req, res) => json(res, { invalid: true }));
  const handles = await session(t, f);
  for (let seq = 1; seq <= 16; seq++) {
    const result = await handles.send(call(seq));
    assert.equal(result.outcome, 'uncertain'); assert.equal(result.recovery_handle, `h${seq}`);
  }
  const again = await handles.send(recover(17, 'h16'));
  assert.equal(again.outcome, 'uncertain'); assert.equal(again.recovery_handle, 'h16');
  handles.child.stdin.write(JSON.stringify(recover(18, 'h17')) + '\n');
  assert.equal((await handles.ended).code, 2);
});

for (const method of ['PUT', 'PATCH', 'DELETE']) test(`negative: seventeenth ${method} rejects before dispatch at handle capacity`, async t => {
  const f = await fixture(t); f.handler((_req, res) => json(res, { invalid: true }));
  const s = await session(t, f);
  for (let seq = 1; seq <= 16; seq++) {
    const result = await s.send(call(seq));
    assert.equal(result.outcome, 'uncertain'); assert.equal(result.recovery_handle, `h${seq}`);
  }
  const before = f.mutations().length; assert.equal(before, 16);
  await mkdir(join(f.root, 'call-000017'));
  const source_file = method === 'PUT' ? 'input/a.bin' : method === 'PATCH' ? 'input/patch.bin' : null;
  s.child.stdin.write(JSON.stringify(call(17, { method, source_file })) + '\n');
  assert.deepEqual(await s.ended, { code: 2, signal: null });
  assert.equal(f.mutations().length, before, 'handle exhaustion must not dispatch a new mutation');
  assert.equal(s.text().lines.length, 16);
});

test('control: GET, recovery and close remain usable at full handle capacity', async t => {
  const f = await fixture(t); f.handler((_req, res) => json(res, { invalid: true }));
  const s = await session(t, f);
  for (let seq = 1; seq <= 16; seq++) {
    const result = await s.send(call(seq));
    assert.equal(result.outcome, 'uncertain'); assert.equal(result.recovery_handle, `h${seq}`);
  }
  f.handler((req, res) => {
    if (req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/yaml', 'X-YamlDB-Revision': REV, ETag: `"${sourceTag(SOURCE)}"` }); res.end(SOURCE);
    } else json(res, RECEIPT);
  });
  const fetched = await s.send(call(17, { method: 'GET', source_file: null, request_id: null }));
  assert.equal(fetched.outcome, 'success'); assert.equal(fetched.api.etag, sourceTag(SOURCE));
  assert.deepEqual(await readFile(join(f.root, fetched.api.body_file)), SOURCE);
  const result = await s.send(recover(18, 'h16'));
  assert.equal(result.outcome, 'success'); assert.equal(result.recovery_handle, 'h16'); assert.equal(result.recovery_mode, 'caller-reissue');
  assert.equal(f.mutations().length, 17);
  await finish(s, 19);
});

test('negative: output file symlinks cannot overwrite input; unexpected filesystem errors exit nonzero', async t => {
  const f = await fixture(t);
  f.handler((_req, res) => { res.writeHead(200, { 'Content-Type': 'application/yaml', 'X-YamlDB-Revision': REV, ETag: `"${sourceTag(SOURCE)}"` }); res.end(SOURCE); });
  await mkdir(join(f.root, 'call-000001'));
  await symlink(join(f.root, 'input/a.bin'), join(f.root, 'call-000001/body.bin'));
  const s = await session(t, f);
  s.child.stdin.write(JSON.stringify(call(1, { method: 'GET', source_file: null, request_id: null })) + '\n');
  assert.equal((await s.ended).code, 2); assert.equal(s.text().stdout, '');
  assert.deepEqual(await readFile(join(f.root, 'input/a.bin')), SOURCE);
});

test('negative: EOF, partial command, pipelining and interruption exit nonzero without leaking diagnostics', async t => {
  const f = await fixture(t);
  for (const text of ['', '{"schema":', JSON.stringify(close(1)) + '\n' + JSON.stringify(close(2)) + '\n']) {
    const s = await session(t, f); s.child.stdin.end(text);
    assert.equal((await s.ended).code, 2); assert.equal(s.text().stdout, '');
    assert.ok(Buffer.byteLength(s.text().stderr) <= 16384);
    assert.ok(!s.text().stderr.includes(READ) && !s.text().stderr.includes(WRITE));
  }
  f.handler(() => {});
  await mkdir(join(f.root, 'call-000001'));
  for (const interrupt of ['signal', 'eof']) {
    const before = f.mutations().length, s = await session(t, f);
    s.child.stdin.write(JSON.stringify(call()) + '\n');
    while (f.mutations().length === before) await new Promise(resolve => setTimeout(resolve, 5));
    if (interrupt === 'signal') s.child.kill('SIGTERM');
    else s.child.stdin.end();
    assert.deepEqual(await s.ended, { code: 2, signal: null });
    assert.equal(s.text().stdout, '');
  }
});
