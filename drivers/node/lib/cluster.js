import { randomBytes } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { setTimeout as pause } from 'node:timers/promises';
import { configuration, request, validateRequest, YamoraError } from './transport.js';
import { decode } from './codec.js';
import { keys, integer, requireValue } from './validation.js';

export class UncertainWriteError extends YamoraError {
  constructor(requestId, cause) {
    super('replica-set write outcome is uncertain; recover the same request ID and exact bytes',
      { code: 'UNCERTAIN_WRITE', status: cause?.status, uncertain: true });
    this.requestId = requestId;
    this.cause = cause;
  }
}

// A reply identifies only the seed which answered it. Node IDs are not array
// indexes, and neither advertised addresses nor follower hints are destinations.
function isLeader(response) {
  if ((response.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase() !== 'application/json') return false;
  const value = decode(response.body);
  return Object.keys(value).length === 4 && Number.isInteger(value.node) && value.node >= 1 && value.node <= 9 &&
    value.leader === value.node && (Number.isSafeInteger(value.term) || typeof value.term === 'bigint') &&
    value.term > 0 && value.term <= (1n << 64n) - 1n && value.role === 'leader';
}
function supportedWrite(method, path) {
  return (method === 'POST' && path === '/v1/transactions') || (method === 'PUT' && path === '/v1/indexes') ||
    (['PUT', 'PATCH', 'DELETE'].includes(method) && /^\/v1\/collections\/[a-z0-9-]+\/documents\/[a-z0-9-]+$/.test(path));
}
const aborted = () => new YamoraError('request aborted', { code: 'ABORT_ERR' });
const timedOut = () => new YamoraError('replica-set deadline exceeded', { code: 'TIMEOUT' });

export function clusterTransport(options) {
  keys(options, ['seeds', 'tls', 'readToken', 'writeToken', 'timeoutMs', 'retryTimeoutMs', 'maxDocumentBytes', 'maxRequestBytes', 'maxResponseBytes']);
  requireValue(Array.isArray(options.seeds) && options.seeds.length >= 1 && options.seeds.length <= 9, '1..9 distinct private HTTPS seeds required');
  requireValue(options.tls !== undefined, 'replica sets require verified TLS');
  const { seeds, retryTimeoutMs = 30000, ...common } = options;
  integer(retryTimeoutMs, 1, 30000);
  const seen = new Set();
  const clients = Object.freeze(Array.from(seeds, seed => {
    keys(seed, ['host', 'port']);
    requireValue(Object.hasOwn(seed, 'host') && Object.hasOwn(seed, 'port'), 'explicit seed host and port required');
    const config = configuration({ ...common, ...seed });
    const key = `${config.host}:${config.port}`;
    requireValue(!seen.has(key), 'duplicate replica-set seed'); seen.add(key);
    return config;
  }));
  // Async continuations update this synchronously. Compare route identity and
  // generation so a late failure/discovery cannot erase/replace newer routing.
  let cached = null;
  let generation = 0;
  let cursor = 0;
  const config = clients[0];
  const budgets = new AsyncLocalStorage();
  const newBudget = () => ({ deadline: performance.now() + Math.min(config.timeoutMs, retryTimeoutMs), attempts: 0 });

  async function send(method, path, body, headers, write, options, statuses, maximum, validate) {
    validateRequest(config, body, write, options);
    if (options.signal?.aborted) throw aborted();
    if (write && !supportedWrite(method, path)) throw new YamoraError('unsupported replica-set operation', { code: 'HTTP_ERROR', status: 405 });
    const budget = budgets.getStore() ?? newBudget();
    // Serialization has already happened once. Own the body, preconditions and
    // signal before the first await; callers can mutate their input afterwards.
    body = body === undefined ? undefined : Buffer.from(body);
    headers = { ...headers };
    options = { ...options };
    let id = options.requestId;
    if (write) {
      while (id === undefined || /^0+$/.test(id)) id = randomBytes(16).toString('hex');
      options.requestId = id;
    }
    let uncertain = false;
    let last = new YamoraError('replica set is unavailable', { code: 'HTTP_ERROR', status: 503 });
    let delay = 50;
    const remaining = () => budget.deadline - performance.now();
    const active = () => {
      if (options.signal?.aborted) throw aborted();
      if (remaining() <= 0) throw timedOut();
    };
    const recover = error => write && uncertain ? new UncertainWriteError(id, error) : error;
    const wait = async () => {
      active();
      try { await pause(Math.min(delay, remaining()), undefined, { signal: options.signal }); }
      catch { throw aborted(); }
      delay = Math.min(1000, delay * 2);
    };
    const discover = async () => {
      const start = cursor;
      const version = generation;
      for (let offset = 0; offset < clients.length && budget.attempts < 32; offset++) {
        active();
        const index = (start + offset) % clients.length;
        budget.attempts++;
        try {
          // Keep a share for dispatch as well as every remaining seed.
          const response = await request(clients[index], 'GET', '/v1/cluster/leader', undefined, {}, false,
            { signal: options.signal }, [200], Math.min(512, config.maxResponseBytes), remaining() / (clients.length - offset + 1));
          active();
          if (isLeader(response)) {
            const route = { index };
            if (generation === version) { cached = route; generation++; }
            return route;
          }
        } catch (error) {
          active();
          if (error.status === 401 || error.status === 403) throw error;
        }
      }
      return null;
    };
    try {
      while (budget.attempts < 32) {
        active();
        const route = cached ?? await discover();
        if (route === null) { await wait(); continue; }
        if (budget.attempts >= 32) break;
        active(); budget.attempts++;
        try {
          // A stalled cached leader cannot consume the complete caller budget.
          const response = await request(clients[route.index], method, path, body, headers, write, options, statuses, maximum,
            remaining() / (clients.length > 1 ? 2 : 1));
          // Receipt validators run here, before generated identity can be lost.
          const result = validate(response);
          active();
          return result;
        } catch (error) {
          // Validation/4xx conflicts are definitive only before any earlier
          // dispatch could have committed. Unexpected successes and 5xx aren't.
          const definitive = error.status >= 400 && error.status < 500 && error.status !== 408;
          if (write && !definitive) uncertain = true;
          last = error;
          active();
          const retry = error.status === 503 || (error instanceof YamoraError && error.status === undefined &&
            !['PROTOCOL_ERROR', 'RESPONSE_LIMIT', 'ABORT_ERR'].includes(error.code));
          if (!retry) throw error;
          if (cached === route) { cached = null; generation++; cursor = (route.index + 1) % clients.length; }
          await wait();
        }
      }
      throw last;
    } catch (error) { throw recover(error); }
  }
  // Each composite catalog call gets its own async context, so its read and
  // guarded write share one budget without leaking it to concurrent callers.
  return { config, send, withBudget: action => budgets.run(newBudget(), action) };
}
