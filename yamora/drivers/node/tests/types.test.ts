import { Client, ClusterClient, YamoraError, UncertainWriteError, type Operation, type ClusterConfig } from '../index.js';

async function example(client: Client) {
  await client.requireReplicationSource();
  const saved = await client.put('people', 'alex', '# exact\ncount: 1\n', { createOnly: true });
  const doc = await client.get('people', 'alex', { revision: saved.revision });
  const bytes: Uint8Array = doc.source;
  await client.patch('people', 'alex', { $inc: { count: 1n } }, { etag: doc.etag });
  const query = await client.query<{ count: number | bigint }>('people', { filter: { count: 9223372036854775807n } });
  const n: number | bigint = query.documents[0]!.value.count;
  for await (const id of client.documents('people', { limit: 10 })) id.toUpperCase();
  const ops: Operation[] = [{ collection: 'people', document: 'alex', put: bytes }];
  await client.transaction(ops);
  return n;
}
void example;
const error = new YamoraError('test');
const uncertain: boolean = error.uncertain;
void uncertain;
// @ts-expect-error TLS verification cannot be disabled.
new Client({ tls: { rejectUnauthorized: false } });
// @ts-expect-error An operation selects exactly one mutation.
const invalid: Operation = { collection: 'people', document: 'alex', delete: true, put: 'x: 1' };
void invalid;
const config: ClusterConfig = { seeds: [{ host: '127.0.0.1', port: 8765 }], tls: {}, timeoutMs: 20000, retryTimeoutMs: 25000 };
const cluster: Client = new ClusterClient(config);
void example(cluster);
const recovery = new UncertainWriteError('1'.repeat(32), new YamoraError('transport'));
const requestId: string = recovery.requestId;
const cause: YamoraError | undefined = recovery.cause;
void cluster.patch('people', 'alex', { $inc: { count: 1n } }, { requestId });
void cause;
// @ts-expect-error Cluster TLS must be explicit.
new ClusterClient({ seeds: config.seeds });
// @ts-expect-error Standalone host cannot override seed routing.
new ClusterClient({ ...config, host: '127.0.0.1' });
// @ts-expect-error Redirect and proxy configuration is unavailable.
new ClusterClient({ ...config, proxy: 'http://127.0.0.1:1' });
// @ts-expect-error TLS verification cannot be disabled for clusters.
new ClusterClient({ ...config, tls: { rejectUnauthorized: false } });

async function binaryExample() {
  const { BinaryClient, BinaryUncertainWriteError } = await import('../index.js');
  const client = new BinaryClient({ host: '127.0.0.1', port: 7401, servername: 'database.internal', tls: { ca: 'PEM' }, maxConcurrentCalls: 2, maxFrameBytes: 4096 });
  const stored = await client.put('people', 'alex', '# exact\r\nn: 1\r\n', { token: 'credential', ifNoneMatch: '*', requestId: '1'.repeat(32) });
  const head: number = (await client.head('people', 'alex', { token: 'credential' })).representationLength;
  const operation = await client.operation('POST', '/v1/query/people', 'application/json', Buffer.from('{"limit":1}'), { token: 'read-credential' });
  const raw: Buffer | undefined = operation.body;
  void raw;
  await client.feed('/v1/changes/stream?after=v1.' + '0'.repeat(32) + '.' + '0'.repeat(16), (page, metadata) => {
    const bytes: Buffer = page;
    const resume: string | undefined = metadata.resumeAfter;
    void bytes; void resume;
  }, { token: 'read-credential' });
  // @ts-expect-error Source CRUD uses its unchanged schema-1 methods.
  await client.operation('DELETE', '/v1/collections/people/documents/alex', '', '');
  await client.delete('people', 'alex', { token: 'credential', ifMatch: `"${stored.etag}"` });
  try { await client.get('people', 'alex'); }
  catch (error) { if (error instanceof BinaryUncertainWriteError) { const bytes: Uint8Array = error.envelope.source; void bytes; } }
  // @ts-expect-error Binary TLS requires explicit trust bytes.
  new BinaryClient({ host: '127.0.0.1', port: 7401, servername: 'database.internal', tls: {} });
  // @ts-expect-error Opaque TLS callbacks are unsupported.
  new BinaryClient({ host: '127.0.0.1', port: 7401, servername: 'database.internal', tls: { ca: 'PEM', checkServerIdentity() {} } });
  // @ts-expect-error Binary driver has no cluster routing or implicit replay API.
  client.recover('1'.repeat(32));
  return head;
}
void binaryExample;
