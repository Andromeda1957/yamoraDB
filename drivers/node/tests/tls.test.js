import { test } from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { Client, YamoraError } from '../index.js';
import { certificates, listen, rawFixture, json } from './helpers.js';

test('real TLS: trust, IP identity, TLS 1.3 and mutual authentication', async t => {
  const { pem } = await certificates(t);
  let negotiated;
  const endpoint = await listen(t, https.createServer({ cert: pem['server.pem'], key: pem['server.key'], minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' }, (req, res) => {
    negotiated = req.socket.getProtocol(); json(res, { status: 'ok' });
  }));
  const tls = { ca: pem['ca.pem'] };
  assert.equal((await new Client({ ...endpoint, tls }).health()).status, 'ok');
  assert.equal(negotiated, 'TLSv1.3');
  await assert.rejects(new Client({ ...endpoint, tls: {} }).health(), error => error instanceof YamoraError && ['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'SELF_SIGNED_CERT_IN_CHAIN'].includes(error.code));
  const old = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  try {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    await assert.rejects(new Client({ ...endpoint, tls: {} }).health(), YamoraError);
  } finally { if (old === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED; else process.env.NODE_TLS_REJECT_UNAUTHORIZED = old; }
  const wrong = await listen(t, https.createServer({ cert: pem['wrong.pem'], key: pem['wrong.key'], minVersion: 'TLSv1.3' }, (_req, res) => json(res, { status: 'ok' })));
  await assert.rejects(new Client({ ...wrong, tls }).health(), error => error.code === 'ERR_TLS_CERT_ALTNAME_INVALID');
  const older = await listen(t, https.createServer({ cert: pem['server.pem'], key: pem['server.key'], maxVersion: 'TLSv1.2' }, (_req, res) => json(res, { status: 'ok' })));
  await assert.rejects(new Client({ ...older, tls }).health(), YamoraError);
  const mutual = await listen(t, https.createServer({ cert: pem['server.pem'], key: pem['server.key'], ca: pem['ca.pem'], minVersion: 'TLSv1.3', requestCert: true, rejectUnauthorized: true }, (_req, res) => json(res, { status: 'ok' })));
  await assert.rejects(new Client({ ...mutual, tls }).health(), YamoraError);
  assert.equal((await new Client({ ...mutual, tls: { ...tls, cert: pem['client.pem'], key: pem['client.key'] } }).health()).status, 'ok');
  // TLS material is owned; changing the caller's buffer cannot change trust.
  const ca = Buffer.from(pem['ca.pem']);
  const copied = new Client({ ...endpoint, tls: { ca } }); ca.fill(0);
  assert.equal((await copied.health()).status, 'ok');
});

test('absolute timeout and abort also bound a stalled TLS handshake', async t => {
  const { address } = await rawFixture(t, () => {});
  const client = new Client({ ...address, tls: {}, timeoutMs: 100 });
  await assert.rejects(client.health(), error => error.code === 'TIMEOUT');
  const controller = new AbortController();
  const pending = client.health({ signal: controller.signal });
  controller.abort();
  await assert.rejects(pending, error => error.code === 'ABORT_ERR');
});
