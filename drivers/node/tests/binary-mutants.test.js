import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cp, readFile, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scratch } from './helpers.js';

function behavioralRed(result, marker) {
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
  return result.status === 1 && !result.signal && !result.error &&
    /^# fail 1$/m.test(output) && (output.match(/^not ok /gm) ?? []).length === 1 &&
    /code: 'ERR_ASSERTION'/.test(output) && output.includes(marker) &&
    !/Sanitizer|runtime error:|SIGABRT|SIGSEGV|SyntaxError|ERR_MODULE_NOT_FOUND|EADDRINUSE|ECONNREFUSED|spawn_error|hookFailed/.test(output);
}

test('binary behavioral red oracle rejects infrastructure, compiler, signal and sanitizer failures', () => {
  const good = { status: 1, signal: null, stdout: "not ok 1 - target\n  code: 'ERR_ASSERTION'\n  error: invariant\n# fail 1\n" };
  assert.equal(behavioralRed(good, 'invariant'), true);
  for (const result of [{ ...good, status: 0 }, { ...good, signal: 'SIGABRT' }, { ...good, error: new Error('spawn') },
    { ...good, stdout: good.stdout + 'AddressSanitizer: fatal' }, { ...good, stdout: good.stdout + 'runtime error: overflow' },
    { ...good, stdout: good.stdout + 'SyntaxError: broken compiler input' }, { ...good, stdout: good.stdout + 'ECONNREFUSED' },
    { ...good, stdout: good.stdout.replace('# fail 1', '# fail 2') }, { ...good, stdout: good.stdout.replace('ERR_ASSERTION', 'ERR_MODULE_NOT_FOUND') }]) assert.equal(behavioralRed(result, 'invariant'), false);
  const syntax = spawnSync(process.execPath, ['--eval', 'const ='], { encoding: 'utf8', timeout: 5000 });
  assert.equal(behavioralRed(syntax, 'invariant'), false);
  const abort = spawnSync(process.execPath, ['--eval', 'process.kill(process.pid, "SIGTERM")'], { encoding: 'utf8', timeout: 5000 });
  assert.equal(behavioralRed(abort, 'invariant'), false);
});

test('binary exact behavioral mutants fail only their named invariants; restored code passes', { timeout: 60000 }, async t => {
  const root = await scratch(t), source = dirname(dirname(fileURLToPath(import.meta.url)));
  const mutations = [
    ['request ID', 'binary-codec.js', "valid(fields.get(12)?.length === 16 && fields.get(12).toString('hex') === op.requestId);", '/* omit ID correlation */', 'ID correlation invariant'],
    ['acknowledgement bound', 'binary-codec.js', 'valid(length <= (success && op.method === 1 ? maximum : 4096));', 'valid(length <= maximum);', 'bounded acknowledgement invariant'],
    ['unique ascending TLVs', 'binary-codec.js', 'valid(id > previous && id <= (op.schema === 2 ? 13 : 12)', 'valid(id > 0 && id <= (op.schema === 2 ? 13 : 12)', 'ascending TLV invariant'],
    ['owned mutation envelope', 'binary-client.js', 'bytes = ownedBytes(source, this.#config.maxDocumentBytes);', 'bytes = source;', 'owned source invariant'],
    ['GET source fingerprint', 'binary-transport.js', 'isUtf8(bytes) && meta.etag === sourceTag(bytes, budget)', 'isUtf8(bytes)', 'GET source fingerprint invariant'],
    ['PUT source fingerprint', 'binary-transport.js', '  valid(meta.etag === sourceTag(op.source, budget));', '', 'PUT source fingerprint invariant'],
    ['create status', 'binary-codec.js', "      valid(op.conditions?.ifNoneMatch !== '*' || status === 201);", '', 'create status invariant'],
    ['match status', 'binary-codec.js', '      valid(op.conditions?.ifMatch === undefined || status === 200);', '', 'match status invariant'],
    ['source backing isolation', 'binary-codec.js', '  const copy = Buffer.alloc(length);\n  apply(nativeSet, copy, [new NativeBytes(backing, offset, length)]);', '  const copy = Buffer.allocUnsafe(length);\n  apply(nativeSet, copy, [new NativeBytes(backing, offset, length)]);', 'source backing isolation invariant'],
    ['trust backing isolation', 'binary-codec.js', '  const copy = Buffer.alloc(length);\n  apply(nativeSet, copy, [new NativeBytes(backing, offset, length)]);', '  const copy = Buffer.allocUnsafe(length);\n  apply(nativeSet, copy, [new NativeBytes(backing, offset, length)]);', 'trust backing isolation invariant'],
    ['identity backing isolation', 'binary-codec.js', '  const copy = Buffer.alloc(length);\n  apply(nativeSet, copy, [new NativeBytes(backing, offset, length)]);', '  const copy = Buffer.allocUnsafe(length);\n  apply(nativeSet, copy, [new NativeBytes(backing, offset, length)]);', 'identity backing isolation invariant'],
    ['envelope backing isolation', 'binary-client.js', 'function sourceReader(source) { return () => ownedBytes(source, LIMIT); }', 'function sourceReader(source) { return () => Buffer.from(source); }', 'envelope backing isolation invariant'],
    ['outbound backing isolation', 'binary-codec.js', 'parts.reduce((n, part) => n + part.length, 0), copy = Buffer.alloc(length)', 'parts.reduce((n, part) => n + part.length, 0), copy = Buffer.allocUnsafe(length)', 'outbound backing isolation invariant'],
    ['shadowed bound', 'binary-codec.js', 'length = apply(viewLength, value, []);', 'length = value.byteLength;', 'shadowed bound intrinsic bound invariant'],
    ['trust intrinsic bound', 'binary-codec.js', 'length = apply(viewLength, value, []);', 'length = value.byteLength;', 'trust intrinsic bound invariant'],
    ['subclass bound', 'binary-codec.js', 'length = apply(viewLength, value, []);', 'length = value.byteLength;', 'subclass bound intrinsic bound invariant'],
    ['proxied input', 'binary-codec.js', "} catch { throw new TypeError('yamora: nonshared Uint8Array bytes required'); }", '} catch { length = value.byteLength; offset = value.byteOffset; backing = value.buffer; }', 'proxied input intrinsic bound invariant'],
    ['shared shadow', 'binary-codec.js', '    apply(arrayLength, backing, []);', '    /* omit actual backing validation */', 'shared shadow intrinsic bound invariant'],
    ['conversion hooks ignored', 'binary-codec.js', '  apply(nativeSet, copy, [new NativeBytes(backing, offset, length)]);', '  return Buffer.from(value);', 'conversion hooks invariant'],
    ['subclass intrinsic copy', 'binary-codec.js', 'length = apply(viewLength, value, []);', 'length = value.length;', 'subclass intrinsic copy invariant'],
    ['envelope owner lifetime', 'binary-client.js', ['function envelope({ method, target, contentType, requestId, conditions, source }) {', 'get: sourceReader(source)'], ['function envelope(op) { const { method, target, contentType, requestId, conditions, source } = op;', 'get: () => ownedBytes(op.source, LIMIT)'], 'envelope credential owner lifetime invariant'],
    ['fingerprint budget', 'binary-codec.js', 'offset += 4096) {\n    budget.check();', 'offset += 4096) {', 'fingerprint budget invariant'],
    ['admission copy bound', 'binary-client.js', 'const waiting = this.#admit(budget);', 'if (method === 3) ownedBytes(source, this.#config.maxDocumentBytes); const waiting = this.#admit(budget);', 'admission copy bound invariant'],
  ];
  for (const [name, module, before, after, marker] of mutations) {
    const copy = join(root, name.replaceAll(' ', '-'));
    await cp(source, copy, { recursive: true });
    const path = join(copy, 'lib', module), original = await readFile(path, 'utf8');
    const edits = Array.isArray(before) ? before.map((value, index) => [value, after[index]]) : [[before, after]];
    let broken = original;
    for (const [find, replace] of edits) { assert.equal(broken.split(find).length, 2, 'exact mutant substitution'); broken = broken.replace(find, replace); }
    const environment = { ...process.env, TMPDIR: root };
    delete environment.NODE_TEST_CONTEXT;
    const run = () => spawnSync(process.execPath, ['--test', '--test-reporter=tap', `--test-name-pattern=^binary invariant: ${name}$`, join(copy, 'tests', 'binary-invariants.test.js')],
      { encoding: 'utf8', timeout: 15000, env: environment });
    const green = run(); assert.equal(green.status, 0, green.stdout + green.stderr);
    await writeFile(path, broken);
    const red = run(); assert.equal(behavioralRed(red, marker), true, `mutant must fail exact behavior: ${name}\n${red.stdout}\n${red.stderr}`);
    await writeFile(path, original);
    const restored = run(); assert.equal(restored.status, 0, restored.stdout + restored.stderr);
  }
});

test('binary native acceptance fails on missing executable instead of skipping', { timeout: 15000 }, async t => {
  const root = await scratch(t);
  const env = { ...process.env, TMPDIR: root, YAMORA_BINARY_NATIVE: join(root, 'absent-native-executable') };
  delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, ['--test', '--test-reporter=tap', '--test-name-pattern=^binary native ASan TLS', fileURLToPath(new URL('./binary-native.test.js', import.meta.url))], { encoding: 'utf8', timeout: 10000, env });
  assert.equal(result.status, 1);
  assert.match(result.stdout, /not ok 1 - binary native ASan TLS/);
  assert.match(result.stdout, /ENOENT/);
  assert.equal(behavioralRed(result, 'invariant'), false);
});


test('schema2 response schema and mandatory mode are behavioral guards', { timeout: 60000 }, async t => {
  const root = await scratch(t), source = dirname(dirname(fileURLToPath(import.meta.url)));
  for (const [name, before, after] of [
    ['schema', 'bytes.readUInt16BE(0) === (op.schema ?? 1)', '(bytes.readUInt16BE(0) === 1 || bytes.readUInt16BE(0) === 2)'],
    ['mode', 'const streaming = number(13, 1);', 'const streaming = fields.has(13) ? number(13, 1) : 0;']
  ]) {
    const copy = join(root, name); await cp(source, copy, { recursive: true });
    const path = join(copy, 'lib/binary-codec.js'), original = await readFile(path, 'utf8');
    assert.equal(original.split(before).length, 2);
    const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
    const run = () => spawnSync(process.execPath, ['--test', '--test-reporter=tap', '--test-name-pattern=^schema2 guards', join(copy, 'tests/binary-operations.test.js')], { env, encoding: 'utf8', timeout: 15000 });
    assert.equal(run().status, 0);
    await writeFile(path, original.replace(before, after));
    const red = run(); assert.equal(behavioralRed(red, 'schema and mode correlation invariant'), true, red.stdout + red.stderr);
    await writeFile(path, original); const green = run(); assert.equal(green.status, 0, green.stdout + green.stderr);
  }
});


test('schema2 callback cancellation retains the completed page cursor under mutation', { timeout: 30000 }, async t => {
  const root = await scratch(t), copy = join(root, 'callback'), source = dirname(dirname(fileURLToPath(import.meta.url)));
  await cp(source, copy, { recursive: true });
  const path = join(copy, 'lib/binary-transport.js'), original = await readFile(path, 'utf8');
  const anchor = 'const abort = () => { if (!publishing) fail(signal.reason); };';
  assert.equal(original.split(anchor).length, 2);
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const run = () => spawnSync(process.execPath, ['--test', '--test-reporter=tap', '--test-name-pattern=^schema2 cancellation inside', join(copy, 'tests/binary-operations.test.js')], { env, encoding: 'utf8', timeout: 10000 });
  assert.equal(run().status, 0);
  await writeFile(path, original.replace(anchor, 'const abort = () => fail(signal.reason);'));
  const red = run(); assert.equal(behavioralRed(red, 'completed callback cursor invariant'), true, red.stdout + red.stderr);
  await writeFile(path, original); const green = run(); assert.equal(green.status, 0, green.stdout + green.stderr);
});
