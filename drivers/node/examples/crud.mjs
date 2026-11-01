import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Client } from '@yamora/node';

// Run against a disposable database. Create-only protects an existing document;
// later writes use its ETag. On uncertainty, stop and reconcile; never retry here.
const client = new Client({
  host: process.env.YAMORA_HOST ?? '127.0.0.1',
  port: Number(process.env.YAMORA_PORT),
  readToken: process.env.YAMORA_READ_TOKEN,
  writeToken: process.env.YAMORA_WRITE_TOKEN,
  tls: {
    ca: await readFile(process.env.YAMORA_CA_FILE),
    ...(process.env.YAMORA_CERT_FILE ? {
      cert: await readFile(process.env.YAMORA_CERT_FILE),
      key: await readFile(process.env.YAMORA_KEY_FILE),
    } : {}),
  },
});
const collection = 'examples';
const document = 'node-package-crud';
const source = Buffer.from('# keep café\r\nname: Alpha\r\nn: 1 # keep inline\r\nwide: 9007199254740993\r\n');
const stored = await client.put(collection, document, source, { createOnly: true });
const original = await client.get(collection, document, { revision: stored.revision });
assert.deepEqual(original.source, source);
await client.patch(collection, document, { $inc: { n: 1 } }, { etag: original.etag });
const updated = await client.get(collection, document);
assert.deepEqual(updated.source, Buffer.from(source.toString().replace('n: 1 #', 'n: 2 #')));
await client.delete(collection, document, { etag: updated.etag });
await assert.rejects(client.get(collection, document), error => error.status === 404);
console.log('Yamora Node package CRUD passed: exact UTF-8, CRLF, comments and int64 source.');
