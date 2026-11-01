import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { copyFile, mkdir, readFile, readdir, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { binary, certificates, daemon, scratch } from './helpers.js';

const execute = promisify(execFile);
const sdk = fileURLToPath(new URL('..', import.meta.url));

test('local npm artifact installs offline and runs a public consumer', { timeout: 120000 }, async t => {
  const root = await scratch(t);
  const consumer = join(root, 'consumer');
  await mkdir(consumer);
  const environment = {
    ...process.env, HOME: root, TMPDIR: root,
    NODE_PATH: '', NODE_OPTIONS: '',
    npm_config_cache: join(root, 'npm-cache'),
    npm_config_userconfig: join(root, 'npm-user.conf'), npm_config_globalconfig: join(root, 'npm-global.conf'),
    npm_config_offline: 'true', npm_config_ignore_scripts: 'true',
    npm_config_audit: 'false', npm_config_fund: 'false',
  };
  await writeFile(environment.npm_config_userconfig, '');
  await writeFile(environment.npm_config_globalconfig, '');
  async function run(command, args, cwd = consumer, env = environment) {
    try {
      return (await execute(command, args, { cwd, env, timeout: 60000, maxBuffer: 1024 * 1024 })).stdout;
    } catch (error) {
      throw new Error(`${error.message}\n${error.stdout ?? ''}\n${error.stderr ?? ''}`, { cause: error });
    }
  }
  const [packed] = JSON.parse(await run('npm', ['pack', '--json', '--pack-destination', root], sdk));
  const manifest = JSON.parse(await readFile(join(sdk, 'package.json'), 'utf8'));
  const expected = ['package.json', 'index.js', 'index.d.ts', 'README.md', 'LICENSE', 'examples/crud.mjs',
    ...(await readdir(join(sdk, 'lib'))).map(name => `lib/${name}`)].sort();
  assert.deepEqual(packed.files.map(file => file.path).sort(), expected);
  await writeFile(join(consumer, 'package.json'), '{"private":true,"type":"module"}\n');
  await run('npm', ['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund',
    '--package-lock=false', join(root, packed.filename)]);
  const installed = join(consumer, 'node_modules/@yamora/node');
  const metadata = JSON.parse(await readFile(join(installed, 'package.json'), 'utf8'));
  assert.equal(metadata.version, manifest.version);
  assert.equal(metadata.private, true);
  assert.equal(metadata.license, 'MIT');
  assert.deepEqual(metadata.dependencies ?? {}, {});
  assert.deepEqual(await readFile(join(installed, 'LICENSE')), await readFile(join(sdk, 'LICENSE')));
  await writeFile(join(consumer, 'consumer.mjs'), `
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import * as sdk from '@yamora/node';
import * as bridge from './index.js';
const { Client, ClusterClient, YamoraError, UncertainWriteError,
  BinaryClient, BinaryUncertainWriteError } = sdk;
assert.equal(import.meta.resolve('@yamora/node'), pathToFileURL(process.argv[2]).href);
assert.deepEqual(Object.keys(sdk).sort(), ['BinaryClient', 'BinaryUncertainWriteError',
  'Client', 'ClusterClient', 'MAX_DOCUMENT_BYTES', 'MAX_REQUEST_BYTES', 'MAX_RESPONSE_BYTES',
  'UncertainWriteError', 'YamoraError'].sort());
for (const name of Object.keys(sdk)) assert.equal(bridge[name], sdk[name]);
for (const value of [Client, ClusterClient, YamoraError, UncertainWriteError,
  BinaryClient, BinaryUncertainWriteError]) assert.equal(typeof value, 'function');
assert.equal(typeof new Client({host: '127.0.0.1', port: 8765}).get, 'function');
console.log('installed package imports passed');
`);
  // Unchanged shared adapters can keep ../index.js while this consumer bridge
  // resolves only the installed artifact. No checkout SDK is copied here.
  await writeFile(join(consumer, 'index.js'), "export * from '@yamora/node';\n");
  const probe = ['consumer.mjs', join(installed, 'index.js')];
  assert.match(await run(process.execPath, probe), /installed package imports passed/);
  // Missing standalone HTTP, replica routing or binary transport must fail;
  // checkout sources and ambient module paths cannot conceal an incomplete pack.
  for (const name of ['transport.js', 'cluster.js', 'binary-transport.js']) {
    const path = join(installed, 'lib', name);
    await rename(path, `${path}.withheld`);
    try {
      await assert.rejects(run(process.execPath, probe), error =>
        error.cause?.code === 1 && error.message.includes('ERR_MODULE_NOT_FOUND') && error.message.includes(name));
    } finally {
      await rename(`${path}.withheld`, path);
    }
  }
  assert.match(await run(process.execPath, probe), /installed package imports passed/);
  const adapters = join(consumer, 'conformance');
  await mkdir(adapters);
  for (const [name, message] of [
    ['adapter.mjs', 'Node conformance adapter failed'],
    ['http_replica.mjs', 'Node HTTP replica adapter failed'],
  ]) {
    const adapter = join(adapters, name);
    await copyFile(join(sdk, 'conformance', name), adapter);
    // Empty/invalid input proves adapter import/linking only. Full profile
    // assertions remain the parent's binary-document-standalone/v2 gate.
    await assert.rejects(run(process.execPath, [adapter]), error =>
      error.cause?.code === 2 && error.cause.stderr.trim() === message);
  }
  // This consumer resolves declarations from the installed tarball, never ../index.js.
  await writeFile(join(consumer, 'consumer.ts'), `
import { Client, ClusterClient, BinaryClient } from '@yamora/node';
const client = new Client({host: '127.0.0.1', port: 8765});
const document: ReturnType<Client['get']> = client.get('examples', 'one');
type BinaryGet = BinaryClient['get'];
type ClusterGet = ClusterClient['get'];
const replica: ClusterGet = ClusterClient.prototype.get; void replica;
void document; const method: BinaryGet = BinaryClient.prototype.get; void method;
`);
  assert.ok(process.env.NODE_TYPE_ROOTS, 'supply the runner pinned NODE_TYPE_ROOTS for artifact declarations');
  const resolved = await run('tsc', ['--noEmit', '--strict', '--listFiles', '--target', 'ES2023', '--module', 'NodeNext',
    '--types', 'node', '--typeRoots', process.env.NODE_TYPE_ROOTS, 'consumer.ts']);
  assert.ok(resolved.split(/\r?\n/).includes(join(installed, 'index.d.ts')));
  assert.ok(!resolved.includes(join(sdk, 'index.d.ts')), 'checkout declarations entered artifact consumer');
  await t.test('installed example: native verified mTLS CRUD', { skip: !binary, timeout: 60000 }, async native => {
    const tls = await certificates(native);
    const { config } = await daemon(native, tls);
    const output = await run(process.execPath, [join(installed, 'examples/crud.mjs')], consumer, {
      ...environment, YAMORA_HOST: config.host, YAMORA_PORT: String(config.port),
      YAMORA_READ_TOKEN: config.readToken, YAMORA_WRITE_TOKEN: config.writeToken,
      YAMORA_CA_FILE: join(tls.root, 'ca.pem'),
      YAMORA_CERT_FILE: join(tls.root, 'client.pem'), YAMORA_KEY_FILE: join(tls.root, 'client.key'),
    });
    assert.match(output, /Yamora Node package CRUD passed/);
  });
});
