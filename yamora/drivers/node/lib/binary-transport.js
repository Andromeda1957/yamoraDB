import { connect, createSecureContext, checkServerIdentity } from 'node:tls';
import { isIP } from 'node:net';
import { isUtf8 } from 'node:buffer';
import { decode } from './codec.js';
import { operationReceipt, feedPage } from './binary-operations.js';
import { YamoraError } from './transport.js';
import { frame, header, hello, peerHello, requestMetadata, responseMetadata, sourceTag, valid, TYPES as T } from './binary-codec.js';

function receipt(op, meta, bytes, budget) {
  if (meta.status >= 400) {
    // Typed rejection still requires a complete bounded JSON body (HEAD suppresses it).
    if (op.method !== 2) { const value = decode(bytes); valid(value !== null && typeof value === 'object' && !Array.isArray(value)); }
    const error = new YamoraError(`binary status ${meta.status}`, { code: 'BINARY_STATUS', status: meta.status,
      uncertain: (op.mutation ?? op.method >= 3) && (meta.status >= 500 || meta.status === 408) });
    if (op.schema === 2) error.response = { ...meta, body: bytes };
    throw error;
  }
  if (op.schema === 2) {
    operationReceipt(op, meta, bytes);
    return { ...meta, body: bytes };
  }
  if (op.method === 1) { valid(isUtf8(bytes) && meta.etag === sourceTag(bytes, budget)); return { source: bytes, etag: meta.etag, revision: meta.revision, requestId: op.requestId }; }
  if (op.method === 2) return { representationLength: meta.representationLength, etag: meta.etag, revision: meta.revision, requestId: op.requestId };
  if (op.method === 4) return { revision: meta.revision, requestId: op.requestId };
  valid(meta.etag === sourceTag(op.source, budget));
  const value = decode(bytes);
  valid(value !== null && typeof value === 'object' && !Array.isArray(value) && value.status === 'stored' &&
    value.collection === op.collection && value.document === op.document && value.revision === meta.revision && value.etag === meta.etag);
  return { status: 'stored', collection: op.collection, document: op.document, etag: meta.etag, revision: meta.revision, requestId: op.requestId };
}

export async function execute(config, op, budget, uncertainty) {
  let socket, sender, closed, dispatched = false;
  let done = false, negotiated = false, maximum = config.maxFrameBytes, requestEnded = false;
  let pendingResult;
  let parts = [], pageBytes = 0, resumeAfter, terminal = false, publishing = false;
  let meta, body, received = 0, headerUsed = 0, payloadUsed = 0, current;
  const head = Buffer.alloc(16), payload = Buffer.alloc(maximum);
  let resolveHello, rejectHello, resolveResponse, rejectResponse;
  const helloReceived = new Promise((resolve, reject) => { resolveHello = resolve; rejectHello = reject; });
  // Install handlers before TCP begins: no rejected asynchronous work is detached.
  helloReceived.catch(() => {});
  const response = new Promise((resolve, reject) => { resolveResponse = resolve; rejectResponse = reject; });
  const signal = budget.controller.signal;
  const fail = error => {
    if (done) return;
    done = true;
    const safe = error instanceof YamoraError ? error : new YamoraError('invalid binary response', { code: 'PROTOCOL_ERROR' });
    if (op.schema === 2 && meta && safe.response === undefined) safe.response = { ...meta, resumeAfter };
    const failure = dispatched && (op.mutation ?? op.method >= 3) && (safe.code !== 'BINARY_STATUS' || safe.uncertain) ? uncertainty(safe) : safe;
    rejectHello(failure); rejectResponse(failure); socket?.destroy();
  };
  const abort = () => { if (!publishing) fail(signal.reason); };
  const receiveFrame = (type, bytes) => {
    budget.check();
    if (!negotiated) {
      valid(type === T.HELLO); maximum = peerHello(bytes, maximum, op.schema === 2 ? 2 : 1);
      if (op.schema === 2 && bytes.readUInt16BE(2) < 2) throw new YamoraError('binary operation protocol unavailable', { code: 'BINARY_UNSUPPORTED' });
      negotiated = true; resolveHello(); return;
    }
    // This single-call profile sends no probes and admits no unsolicited controls.
    if (type === T.ERROR) { valid(bytes.readUInt32BE() !== 0); throw new YamoraError('binary peer closed with ERROR', { code: 'BINARY_ERROR' }); }
    if (type === T.GOAWAY) throw new YamoraError('binary peer draining', { code: 'GOAWAY' });
    valid(requestEnded);
    if (type === T.RESPONSE) {
      valid(meta === undefined);
      meta = responseMetadata(bytes, op, config.maxDocumentBytes);
      budget.check();
      if (meta.streaming) resumeAfter = /[?&]after=([^&]+)/.exec(op.target)?.[1];
      else body = Buffer.alloc(meta.length);
      return;
    }
    if (type === T.DATA) {
      valid(meta !== undefined && !terminal);
      if (meta.streaming) {
        valid(received + bytes.length <= 16 * 1024 * 1024); received += bytes.length;
        let offset = 0;
        while (offset < bytes.length) {
          const end = bytes.indexOf(10, offset), next = end < 0 ? bytes.length : end + 1;
          const part = Buffer.from(bytes.subarray(offset, next)); parts.push(part); pageBytes += part.length;
          valid(pageBytes <= 16 * 1024 * 1024);
          if (end >= 0) {
            // Public pages own their entire backing store. Buffer.concat uses
            // Node's pool for small pages and would expose adjacent deliveries.
            const page = Buffer.alloc(pageBytes);
            let copied = 0;
            for (const part of parts) { part.copy(page, copied); copied += part.length; }
            parts = []; pageBytes = 0;
            const state = feedPage(page, resumeAfter); budget.check();
            try { publishing = true; op.onPage(page, { ...meta, resumeAfter: state.after }); }
            finally { publishing = false; }
            resumeAfter = state.after; terminal = state.terminal; budget.check();
            valid(!terminal || next === bytes.length);
          }
          offset = next;
        }
        return;
      }
      valid(received + bytes.length <= meta.length);
      bytes.copy(body, received); received += bytes.length; return;
    }
    valid(type === T.END && meta !== undefined && (meta.streaming ? pageBytes === 0 : received === meta.length));
    pendingResult = meta.streaming ? { ...meta, resumeAfter } : receipt(op, meta, body, budget); budget.check();
  };
  const onData = bytes => {
    try {
      let offset = 0;
      while (offset < bytes.length) {
        budget.check(); valid(!done && pendingResult === undefined);
        if (headerUsed < 16) {
          const count = Math.min(16 - headerUsed, bytes.length - offset);
          bytes.copy(head, headerUsed, offset, offset + count); headerUsed += count; offset += count;
          if (headerUsed < 16) continue;
          current = header(head, maximum); // Validate advertised length before copying payload.
        }
        const count = Math.min(current.length - payloadUsed, bytes.length - offset);
        bytes.copy(payload, payloadUsed, offset, offset + count); payloadUsed += count; offset += count;
        if (payloadUsed === current.length) {
          receiveFrame(current.type, payload.subarray(0, payloadUsed)); headerUsed = 0; payloadUsed = 0;
        }
      }
      if (pendingResult !== undefined) { budget.check(); done = true; resolveResponse(pendingResult); }
    } catch (error) { fail(error); }
  };
  const onError = error => fail(new YamoraError('binary TLS transport failed', { code: typeof error.code === 'string' ? error.code : 'TRANSPORT_ERROR' }));
  const onEnd = () => fail(new YamoraError('binary response ended before exact END', { code: 'TRUNCATED_RESPONSE' }));
  const write = bytes => new Promise((resolve, reject) => {
    try {
      budget.check();
      if (done) { reject(new YamoraError('binary call ended', { code: 'TRANSPORT_ERROR' })); return; }
      socket.write(bytes, error => { if (error) reject(error); else resolve(); });
    } catch (error) { reject(error); }
  });
  try {
    budget.check();
    // Reparse only our copied bytes for every connection. No shared SSL context,
    // agent, verification callback, DNS connection lookup or environment proxy.
    const secureContext = createSecureContext({ ...config.tls, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' });
    budget.check();
    socket = connect({ host: config.host, port: config.port, family: 4,
      servername: config.servername, secureContext, rejectUnauthorized: true,
      minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', ALPNProtocols: ['yamora-binary/1'],
      // An IP verification identity uses Node's built-in host verification. SNI
      // is omitted for IP literals, as required by RFC 6066 and Node.
      ...(isIP(config.servername) ? { servername: undefined, host: config.host } : {}) });
    // The built-in verifier also checks the explicit identity after handshake.
    closed = new Promise(resolve => socket.once('close', resolve));
    socket.on('data', onData); socket.on('error', onError); socket.on('end', onEnd);
    const onClose = () => { if (!done) onEnd(); };
    socket.on('close', onClose);
    signal.addEventListener('abort', abort, { once: true });
    sender = (async () => {
      await new Promise((resolve, reject) => {
        const secure = () => { cleanup(); resolve(); };
        const ended = () => { cleanup(); reject(new YamoraError('binary TLS handshake failed', { code: 'TLS_ERROR' })); };
        const cleanup = () => { socket.removeListener('secureConnect', secure); socket.removeListener('close', ended); };
        socket.once('secureConnect', secure); socket.once('close', ended);
      });
      budget.check();
      valid(socket.authorized && socket.getProtocol() === 'TLSv1.3' && socket.alpnProtocol === 'yamora-binary/1');
      // Built-in verifier is required even when a numeric connection endpoint and
      // the supplied certificate identity differ.
      if (checkServerIdentity(config.servername, socket.getPeerCertificate())) throw new YamoraError('binary TLS identity mismatch', { code: 'ERR_TLS_CERT_ALTNAME_INVALID' });
      await write(frame(T.HELLO, 0, hello(config.maxFrameBytes, op.schema === 2 ? 2 : 1)));
      await helloReceived;
      budget.check();
      const request = requestMetadata(op, budget.remaining());
      // Conservatively mark dispatch before the first REQUEST write: a write
      // callback or partial socket failure cannot establish remote non-execution.
      dispatched = true;
      await write(frame(T.REQUEST, 1, request));
      for (let offset = 0; offset < op.source.length; offset += maximum) {
        await write(frame(T.DATA, 1, op.source.subarray(offset, offset + maximum)));
      }
      requestEnded = true;
      await write(frame(T.END, 1));
    })().catch(fail);
    return await response;
  } catch (error) {
    fail(error);
    return await response;
  } finally {
    signal.removeEventListener('abort', abort);
    socket?.destroy();
    if (closed) await closed;
    if (sender) await sender;
    if (socket) { socket.removeAllListeners(); }
  }
}
