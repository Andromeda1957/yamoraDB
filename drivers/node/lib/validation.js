import { isUtf8 } from 'node:buffer';

export const MAX_DOCUMENT_BYTES = 16 * 1024 * 1024;
export const MAX_REQUEST_BYTES = 64 * 1024 * 1024;
export const MAX_RESPONSE_BYTES = 64 * 1024 * 1024;
export const IDENTIFIER = /^[a-z0-9-]{1,128}$/;
export const REVISION = /^[0-9a-f]{16}$/;
export const CHANGE_TOKEN = /^v1\.[0-9a-f]{32}\.[0-9a-f]{16}$/;

export function requireValue(condition, message = 'invalid arguments') {
  if (!condition) throw new TypeError(`yamora: ${message}`);
}
export function identifier(value) {
  requireValue(typeof value === 'string' && IDENTIFIER.test(value), 'invalid identifier');
  return value;
}
export function revision(value) {
  requireValue(typeof value === 'string' && REVISION.test(value), 'invalid revision or ETag');
  return value;
}
export function optionalRevision(value) { if (value !== undefined) revision(value); }
export function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}
export function keys(value, allowed) {
  requireValue(object(value) && Reflect.ownKeys(value).every(key => allowed.includes(key)), 'invalid options');
}
export function integer(value, min, max) {
  requireValue(Number.isSafeInteger(value) && value >= min && value <= max, 'integer outside limits');
}
export function changeToken(value) {
  requireValue(typeof value === 'string' && CHANGE_TOKEN.test(value), 'invalid change token');
  return value;
}
export function text(value) {
  requireValue(typeof value === 'string' && value.isWellFormed(), 'expected well-formed Unicode text');
}
export function sourceBytes(value, maximum = MAX_DOCUMENT_BYTES) {
  requireValue(typeof value === 'string' || Buffer.isBuffer(value) || value instanceof Uint8Array, 'expected YAML text or bytes');
  if (typeof value === 'string') text(value);
  requireValue((typeof value === 'string' ? Buffer.byteLength(value) : value.byteLength) <= maximum, 'document exceeds limit');
  const body = Buffer.from(value);
  requireValue(body.length > 0 && isUtf8(body), 'expected nonempty UTF-8 YAML');
  return body;
}
