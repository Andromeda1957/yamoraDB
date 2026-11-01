/** Independent implementation of the committed YMBF/schema-1 network format. */
// Capture TypedArray intrinsics before accepting public views. Own properties,
// subclass accessors and conversion hooks never participate in bounds or copying.
const typed = Object.getPrototypeOf(Uint8Array.prototype);
const intrinsic = name => Object.getOwnPropertyDescriptor(typed, name).get;
const viewBuffer = intrinsic('buffer'), viewLength = intrinsic('byteLength'), viewOffset = intrinsic('byteOffset');
const viewTag = intrinsic(Symbol.toStringTag), arrayLength = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;
const nativeSet = Uint8Array.prototype.set, NativeBytes = Uint8Array, apply = Reflect.apply;

/** Bounded dedicated storage. Buffer.alloc never shares Node's caller-visible slab. */
export function ownedBytes(value, maximum, encoding = 'utf8') {
  if (typeof value === 'string') {
    const length = Buffer.byteLength(value, encoding);
    if (length > maximum) throw new TypeError('yamora: byte input exceeds limit');
    const copy = Buffer.alloc(length); copy.write(value, 0, length, encoding); return copy;
  }
  let length, offset, backing;
  try {
    if (apply(viewTag, value, []) !== 'Uint8Array') throw new TypeError();
    length = apply(viewLength, value, []); offset = apply(viewOffset, value, []); backing = apply(viewBuffer, value, []);
    apply(arrayLength, backing, []); // Reject actual SharedArrayBuffer, including shadowed .buffer.
  } catch { throw new TypeError('yamora: nonshared Uint8Array bytes required'); }
  if (length > maximum) throw new TypeError('yamora: byte input exceeds limit');
  const copy = Buffer.alloc(length);
  apply(nativeSet, copy, [new NativeBytes(backing, offset, length)]);
  return copy;
}
function joined(parts) {
  const length = parts.reduce((n, part) => n + part.length, 0), copy = Buffer.alloc(length);
  let offset = 0;
  for (const part of parts) { apply(nativeSet, copy, [part, offset]); offset += part.length; }
  return copy;
}

/** Native raw-source FNV: seed1469598103934665603, multiplier1099511628211,
 * modulo2^64. Two exact uint32 limbs avoid BigInt allocation per source byte. */
export function sourceTag(bytes, budget) {
  let high = 0x14650fb0, low = 0x739d0383;
  for (let offset = 0; offset < bytes.length; offset += 4096) {
    budget.check();
    for (let i = offset, end = Math.min(offset + 4096, bytes.length); i < end; i++) {
      low = (low ^ bytes[i]) >>> 0;
      const product = low * 435;
      high = (Math.imul(high, 435) + ((low << 8) >>> 0) + Math.floor(product / 4294967296)) >>> 0;
      low = product >>> 0;
    }
  }
  budget.check();
  return high.toString(16).padStart(8, '0') + low.toString(16).padStart(8, '0');
}

export const LIMIT = 16 * 1024 * 1024;
export const TYPES = Object.freeze({ HELLO: 1, REQUEST: 2, RESPONSE: 3, DATA: 4, END: 5, CANCEL: 6, ERROR: 7, PING: 8, PONG: 9, GOAWAY: 10 });
export function valid(ok) { if (!ok) throw new Error('invalid binary protocol'); }
export function uint(value, width) {
  const out = Buffer.alloc(width);
  if (width === 8) out.writeBigUInt64BE(BigInt(value));
  else out.writeUIntBE(value, 0, width);
  return out;
}
export function frame(type, stream, payload = Buffer.alloc(0)) {
  const header = ownedBytes('594d4246010000000000000000000000', 16, 'hex');
  header[5] = type; header.writeUInt32BE(stream, 8); header.writeUInt32BE(payload.length, 12);
  return joined([header, payload]);
}
export function header(bytes, maximum) {
  valid(bytes.length === 16 && bytes.readUInt32BE(0) === 0x594d4246 && bytes[4] === 1 && bytes.readUInt16BE(6) === 0);
  const type = bytes[5], stream = bytes.readUInt32BE(8), length = bytes.readUInt32BE(12);
  valid(type >= 1 && type <= 10 && length <= maximum);
  const control = [1, 8, 9, 10].includes(type);
  valid(control ? stream === 0 : stream === 1);
  valid(![2, 3].includes(type) || (length > 0 && length <= 2048));
  valid(type !== 1 || length === 12);
  valid(type !== 4 || length > 0);
  valid(![5, 6, 10].includes(type) || length === 0);
  valid(type !== 7 || length === 4);
  valid(![8, 9].includes(type) || length === 8);
  return { type, stream, length };
}
export function hello(maximum, protocol = 1) { return joined([uint(1, 2), uint(protocol, 2), uint(maximum, 4), uint(1, 4)]); }
export function peerHello(bytes, maximum, protocol = 1) {
  valid(bytes.length === 12);
  const low = bytes.readUInt16BE(0), high = bytes.readUInt16BE(2), cap = bytes.readUInt32BE(4), streams = bytes.readUInt32BE(8);
  valid(low > 0 && low <= protocol && high >= 1 && high >= low && cap >= 4096 && cap <= 1024 * 1024 && streams >= 1 && streams <= 128);
  return Math.min(maximum, cap);
}
export function metadata(fields, schema = 1) {
  const out = [uint(schema, 2), uint(fields.length, 2)];
  let previous = 0;
  for (const [id, value] of fields) {
    valid(id > previous); previous = id;
    out.push(uint(id, 2), uint(value.length, 2), value);
  }
  const bytes = joined(out); valid(bytes.length <= 2048); return bytes;
}
export function requestMetadata(op, remaining) {
  const fields = [[1, uint(op.method, 1)], [2, ownedBytes(op.target, 1024)], [3, ownedBytes(op.contentType ?? (op.method === 3 ? 'application/yaml' : ''), 95)], [4, uint(op.source.length, 8)]];
  if (op.token !== undefined) fields.push([5, ownedBytes(`Bearer ${op.token}`, 519)]);
  if (op.conditions.ifMatch !== undefined) fields.push([6, ownedBytes(op.conditions.ifMatch, 31)]);
  if (op.conditions.ifNoneMatch !== undefined) fields.push([7, ownedBytes(op.conditions.ifNoneMatch, 31)]);
  fields.push([8, ownedBytes(op.requestId, 16, 'hex')], [9, uint(remaining, 4)]);
  return metadata(fields, op.schema ?? 1);
}
function ascii(bytes, min, max, pattern = /^[\x20-\x7e]*$/) {
  valid(bytes.length >= min && bytes.length <= max && bytes.every(b => b >= 0x20 && b <= 0x7e));
  const text = bytes.toString('ascii'); valid(pattern.test(text)); return text;
}
export function responseMetadata(bytes, op, maximum) {
  valid(bytes.length >= 4 && bytes.length <= 2048 && bytes.readUInt16BE(0) === (op.schema ?? 1));
  const count = bytes.readUInt16BE(2), fields = new Map();
  valid(count >= 5 && count <= (op.schema === 2 ? 13 : 12));
  let offset = 4, previous = 0;
  for (let i = 0; i < count; i++) {
    valid(offset + 4 <= bytes.length);
    const id = bytes.readUInt16BE(offset), size = bytes.readUInt16BE(offset + 2); offset += 4;
    valid(id > previous && id <= (op.schema === 2 ? 13 : 12) && offset + size <= bytes.length);
    previous = id; fields.set(id, bytes.subarray(offset, offset + size)); offset += size;
  }
  valid(offset === bytes.length && [1, 2, 3, 4, 5].every(id => fields.has(id)));
  const number = (id, width) => {
    const field = fields.get(id); valid(field?.length === width);
    const n = width === 8 ? field.readBigUInt64BE() : BigInt(field.readUIntBE(0, width));
    valid(n <= BigInt(Number.MAX_SAFE_INTEGER)); return Number(n);
  };
  const status = number(1, 2), contentType = ascii(fields.get(2), 1, 95);
  const length = number(3, 8), representationLength = number(4, 8);
  valid(status >= 200 && status <= 599 && length <= LIMIT && representationLength <= LIMIT);
  valid(length === 0 || length === representationLength);
  valid(status !== 204 || (length === 0 && representationLength === 0));
  valid(status !== 304 || length === 0);
  const revision = ascii(fields.get(5), 16, 16, /^[0-9a-f]{16}$/);
  const etag = fields.has(6) ? ascii(fields.get(6), 18, 18, /^"[0-9a-f]{16}"$/).slice(1, -1) : undefined;
  for (const [id, name] of [[7, op.collection], [8, op.document]]) if (fields.has(id)) valid(ascii(fields.get(id), 1, 128, /^[a-z0-9-]+$/) === name);
  if (fields.has(9)) valid(number(9, 1) > 0 && number(9, 1) <= (op.schema === 2 ? 63 : 15));
  if (fields.has(10)) valid(number(10, 1) === 1);
  if (fields.has(11)) number(11, 4);
  // Every public call sends an ID, so a missing echo is also a correlation failure.
  valid(fields.get(12)?.length === 16 && fields.get(12).toString('hex') === op.requestId);
  if (op.schema === 2) {
    const streaming = number(13, 1); valid(streaming === 0 || streaming === 1);
    valid(length === representationLength);
    if (status >= 400) valid(!streaming && length <= 4096 && contentType.split(';')[0].toLowerCase() === 'application/json');
    else {
      valid(status === 200);
      valid(Boolean(streaming) === Boolean(op.onPage));
      valid(streaming ? length === 0 && contentType.split(';')[0].toLowerCase() === 'application/x-ndjson' : contentType.split(';')[0].toLowerCase() === 'application/json');
      if (op.mutation) valid(length > 0 && length <= 4096);
      if (op.method === 6) valid(etag !== undefined);
    }
    valid(!fields.has(9) || status === 405); valid(!fields.has(10) || status === 401);
    valid(!fields.has(11) || status === 429 || status === 503);
    return { status, length, representationLength, revision, etag, contentType, streaming: Boolean(streaming), requestId: op.requestId };
  }
  const success = status >= 200 && status < 300;
  if (success) {
    valid(({ 1: [200], 2: [200], 3: [200, 201], 4: [204] })[op.method].includes(status));
    if (op.method <= 2) valid(representationLength <= maximum && etag !== undefined && /^(application|text)\/yaml(?:;[\x20-\x7e]*)?$/i.test(contentType));
    if (op.method === 3) {
      valid(op.conditions?.ifNoneMatch !== '*' || status === 201);
      valid(op.conditions?.ifMatch === undefined || status === 200);
    }
    if (op.method === 3) valid(contentType.split(';')[0].toLowerCase() === 'application/json' && etag !== undefined);
  } else {
    valid(representationLength <= 4096 && status >= 400 && contentType.split(';')[0].toLowerCase() === 'application/json');
  }
  valid(op.method !== 2 || length === 0);
  valid(op.method === 2 || length === representationLength);
  valid(length <= (success && op.method === 1 ? maximum : 4096));
  return { status, length, representationLength, revision, etag, contentType };
}
