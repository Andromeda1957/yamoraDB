import { isUtf8 } from 'node:buffer';
import { object, requireValue, text } from './validation.js';

function rejectSerializationHooks(value) {
  // JSON.stringify looks up toJSON on objects and bigint before its replacer.
  // Inspect descriptors without invoking accessors, including inherited hooks;
  // a noncallable own data field shadows any inherited hook and is ordinary data.
  let links = 0;
  for (let current = value; current !== null; current = Object.getPrototypeOf(current)) {
    requireValue(++links <= 64, 'prototype chain exceeds complexity limit');
    const descriptor = Object.getOwnPropertyDescriptor(current, 'toJSON');
    if (descriptor !== undefined) {
      requireValue(Object.hasOwn(descriptor, 'value') && typeof descriptor.value !== 'function', 'JSON serialization hooks are unsupported');
      return;
    }
  }
}

// Validate before JSON.stringify can call toJSON, getters or silently round an
// integer. Plain, dense JSON trees only; bigint is the signed-int64 extension.
export function encode(value, maximum) {
  let nodes = 0;
  let characters = 0;
  const visit = (item, depth) => {
    requireValue(++nodes <= 100000 && depth <= 64, 'structured input exceeds complexity limit');
    if (typeof item === 'string') {
      text(item);
      characters += item.length;
      requireValue(characters <= maximum, 'request exceeds limit');
    } else if (typeof item === 'number') {
      requireValue(Number.isFinite(item) && (!Number.isInteger(item) || Number.isSafeInteger(item)), 'use bigint for unsafe integers');
    } else if (typeof item === 'bigint') {
      rejectSerializationHooks(item);
      requireValue(item >= -(1n << 63n) && item < (1n << 63n), 'integer outside signed 64-bit range');
    } else if (item !== null && typeof item !== 'boolean') {
      requireValue(Array.isArray(item) || object(item), 'expected plain JSON values');
      rejectSerializationHooks(item);
      if (Array.isArray(item)) requireValue(item.length <= 100000, 'array exceeds complexity limit');
      const descriptors = Object.getOwnPropertyDescriptors(item);
      const names = Reflect.ownKeys(descriptors);
      if (Array.isArray(item)) {
        requireValue(names.length === item.length + 1 && names.every(name => name === 'length' ||
          (typeof name === 'string' && /^(0|[1-9][0-9]*)$/.test(name) && Number(name) < item.length)), 'expected dense JSON array');
      }
      for (const name of names) {
        if (Array.isArray(item) && name === 'length') continue;
        requireValue(typeof name === 'string', 'invalid JSON property');
        const descriptor = descriptors[name];
        requireValue(Object.hasOwn(descriptor, 'value') && descriptor.enumerable, 'accessors and hidden properties are unsupported');
        text(name);
        characters += name.length;
        requireValue(characters <= maximum, 'request exceeds limit');
        visit(descriptor.value, depth + 1);
      }
    }
  };
  visit(value, 0);
  const serialized = JSON.stringify(value, (_key, item) => typeof item === 'bigint' ? JSON.rawJSON(item.toString()) : item)
    .replace(/[\u0085\u2028\u2029]/g, ch => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`);
  requireValue(Buffer.byteLength(serialized) <= maximum, 'request exceeds limit');
  return Buffer.from(serialized);
}

// Node 22 exposes the original number token to a JSON reviver. Preserve unsafe
// integer tokens as bigint, including int64 max, without rounding through Number.
export function decode(body) {
  return decodeBounded(body, 64);
}
// Wire envelopes add containers around native values; ordinary JSON stays64.
export function decodeOperationResponse(body) {
  return decodeBounded(body, 80);
}
function decodeBounded(body, maxDepth) {
  if (!isUtf8(body)) throw new Error('invalid UTF-8');
  const string = body.toString('utf8');
  let depth = 0;
  let quoted = false;
  let escaped = false;
  for (const ch of string) {
    if (quoted) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '"') quoted = false;
    } else if (ch === '"') quoted = true;
    else if (ch === '{' || ch === '[') { if (++depth > maxDepth) throw new Error('JSON nesting limit'); }
    else if (ch === '}' || ch === ']') depth--;
  }
  let nodes = 0;
  const value = JSON.parse(string, (_key, item, context) => {
    if (++nodes > 100000) throw new Error('JSON node limit');
    if (typeof item === 'string' && !item.isWellFormed()) throw new Error('invalid Unicode');
    if (typeof item === 'number') {
      if (/^-?(?:0|[1-9][0-9]*)$/.test(context.source) && !Number.isSafeInteger(item)) return BigInt(context.source);
      if (!Number.isFinite(item)) throw new Error('non-finite number');
    }
    if (object(item) && Object.keys(item).some(key => !key.isWellFormed())) throw new Error('invalid Unicode key');
    return item;
  });
  if (!object(value)) throw new Error('expected JSON object');
  return value;
}
