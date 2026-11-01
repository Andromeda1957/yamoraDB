import type { Buffer } from 'node:buffer';

export const MAX_DOCUMENT_BYTES: number;
export const MAX_REQUEST_BYTES: number;
export const MAX_RESPONSE_BYTES: number;
export type JsonValue = null | boolean | number | bigint | string | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };
export type YamlSource = string | Uint8Array;
export interface TLSOptions { ca?: string | Buffer; cert?: string | Buffer; key?: string | Buffer }
export interface Config {
  host?: string;
  port?: number;
  readToken?: string;
  writeToken?: string;
  /** Absolute per-request deadline; default 5000, range 1..30000 milliseconds. */
  timeoutMs?: number;
  /** Omit for HTTP. Verification and TLS 1.3 are mandatory when provided. */
  tls?: TLSOptions;
  maxDocumentBytes?: number;
  maxRequestBytes?: number;
  maxResponseBytes?: number;
}
export interface Seed { host: string; port: number }
export interface ClusterConfig extends Omit<Config, 'host' | 'port' | 'tls'> {
  /** 1..9 distinct canonical numeric private IPv4 endpoints. Copied at construction. */
  seeds: readonly Seed[];
  /** Required verified TLS 1.3, optionally with a paired client identity. */
  tls: TLSOptions;
  /** Overall discovery/dispatch/backoff ceiling; min(timeoutMs, retryTimeoutMs). Default 30000. */
  retryTimeoutMs?: number;
}
export interface CallOptions { signal?: AbortSignal }
export interface RevisionOptions extends CallOptions { revision?: string }
export interface MutationOptions extends CallOptions {
  /** Nonzero 32-lowercase-hex identity. Cluster retries preserve it; standalone never replays. */
  requestId?: string;
}
export interface ETagOptions extends MutationOptions { etag?: string }
export interface PutOptions extends ETagOptions { createOnly?: boolean }
export interface CatalogOptions extends MutationOptions { revision?: string }
export interface Document { source: Buffer; etag: string; revision: string }
export interface Mutation { status: 'stored'; collection: string; document: string; etag: string; revision: string }
export interface DocumentPage {
  collection: string;
  documents: string[];
  next_after: string | null;
  revision: string;
}
export interface PageOptions extends RevisionOptions { limit?: number; after?: string }
export interface ScanOptions extends RevisionOptions { limit?: number }
export interface QuerySpec {
  filter?: JsonObject;
  /** Property enumeration order is compound sort priority. */
  sort?: Record<string, 'asc' | 'desc' | 'ascending' | 'descending' | 1 | -1>;
  projection?: string[];
  limit?: number;
  after?: string;
  revision?: string;
  count_only?: boolean;
  explain?: boolean;
  include_count?: boolean;
}
export interface Row<T = JsonValue> { id: string; value: T }
export interface QueryResult<T = JsonValue> {
  documents: Row<T>[];
  matched: number | bigint | null;
  next_after: string | null;
  revision: string;
  explain?: JsonObject;
}
export interface SearchSpec {
  index: string;
  text: string;
  mode?: 'all' | 'any';
  filter?: JsonObject;
  limit?: number;
  after?: string;
  revision?: string;
}
export interface SearchResult<T = JsonValue> {
  documents: (Row<T> & { score: number })[];
  next_after: string | null;
  revision: string;
  documents_examined: number | bigint;
  index_entries_examined: number | bigint;
}
export interface AggregateResult { documents: JsonObject[]; revision: string; documents_examined: number | bigint }
export interface IndexDefinition { collection: string; name: string; fields: string[]; unique?: boolean; type?: 'text' }
export interface IndexCatalog { indexes: IndexDefinition[]; revision: string }
export interface IndexBuild {
  id: string;
  status: 'idle' | 'running' | 'succeeded' | 'failed' | 'cancelled';
  phase: 'idle' | 'scanning' | 'catching_up' | 'publishing' | 'done';
  documents_scanned: number | bigint;
  transactions_replayed: number | bigint;
  /** Publication revision on success; may precede the current database head. */
  revision: string;
  error: string;
  cancel_requested: boolean;
}
interface OperationTarget { collection: string; document: string; etag?: string }
export type Operation = OperationTarget & (
  { put: YamlSource; create_only?: boolean; patch?: never; delete?: never } |
  { patch: JsonObject; create_only?: never; put?: never; delete?: never } |
  { delete: true; create_only?: never; put?: never; patch?: never }
);
export interface TransactionResult { status: 'committed'; revision: string; operations: number }
export type ChangeOperation = { collection: string } & (
  { document: string; put: string; delete?: never; create_collection?: never } |
  { document: string; delete: true; put?: never; create_collection?: never } |
  { create_collection: true; document?: never; put?: never; delete?: never }
);
export interface Change {
  token: string;
  previous_revision: string;
  revision: string;
  resnapshot_required: boolean;
  operations: ChangeOperation[];
}
export interface ChangePage {
  transactions: Change[];
  next_after: string;
  oldest_after: string;
  checkpoint: string;
  revision: string;
  has_more: boolean;
}
export class YamoraError extends Error {
  readonly name: 'YamoraError';
  readonly code: string;
  readonly status: number | undefined;
  /** A dispatched mutation may have committed; inspect state before resubmission. */
  readonly uncertain: boolean;
  constructor(message: string, options?: { code?: string; status?: number; uncertain?: boolean });
}
export class UncertainWriteError extends YamoraError {
  /** Persist this and the exact primitive request bytes and preconditions for recovery. */
  readonly requestId: string;
  readonly cause: YamoraError | undefined;
  constructor(requestId: string, cause?: YamoraError);
}
export class Client {
  constructor(config?: Config);
  health(options?: CallOptions): Promise<JsonObject>;
  ready(options?: CallOptions): Promise<JsonObject>;
  /** Advisory preflight; application-owned staging still requires native admission. */
  requireReplicationSource(options?: CallOptions): Promise<JsonObject>;
  stats(options?: CallOptions): Promise<JsonObject>;
  metrics(options?: CallOptions): Promise<string>;
  collections(options?: RevisionOptions): Promise<{ collections: string[]; revision: string }>;
  documentPage(collection: string, options?: PageOptions): Promise<DocumentPage>;
  documents(collection: string, options?: ScanOptions): AsyncGenerator<string, void, unknown>;
  get(collection: string, document: string, options?: RevisionOptions): Promise<Document>;
  put(collection: string, document: string, source: YamlSource, options?: PutOptions): Promise<Mutation>;
  patch(collection: string, document: string, operators: JsonObject, options?: ETagOptions): Promise<Mutation>;
  delete(collection: string, document: string, options?: ETagOptions): Promise<{ revision: string }>;
  query<T = JsonValue>(collection: string, spec?: QuerySpec, options?: CallOptions): Promise<QueryResult<T>>;
  count(collection: string, filter?: JsonObject, options?: RevisionOptions): Promise<number | bigint>;
  aggregate(collection: string, pipeline: JsonObject[], options?: RevisionOptions): Promise<AggregateResult>;
  search<T = JsonValue>(collection: string, spec: SearchSpec, options?: CallOptions): Promise<SearchResult<T>>;
  indexes(options?: CallOptions): Promise<IndexCatalog>;
  setIndexes(indexes: IndexDefinition[], options?: CatalogOptions): Promise<{ revision: string; [key: string]: JsonValue }>;
  createIndex(index: IndexDefinition, options?: CallOptions): Promise<{ revision: string; [key: string]: JsonValue }>;
  dropIndex(collection: string, name: string, options?: CallOptions): Promise<{ revision: string; [key: string]: JsonValue }>;
  startIndexBuild(indexes: IndexDefinition[], options?: RevisionOptions): Promise<IndexBuild>;
  indexBuild(id?: string, options?: CallOptions): Promise<IndexBuild>;
  cancelIndexBuild(id: string, options?: CallOptions): Promise<IndexBuild>;
  transaction(operations: Operation[], options?: CatalogOptions): Promise<TransactionResult>;
  changes(options?: CallOptions & { after?: string; limit?: number }): Promise<ChangePage>;
}
/** Same API with bounded leader discovery and exact-request retries over trusted HTTPS seeds. */
export class ClusterClient extends Client {
  constructor(config: ClusterConfig);
}

export interface BinaryConfig {
  /** Canonical numeric private IPv4 connection endpoint. No DNS/proxy routing. */
  host: string;
  port: number;
  /** Certificate verification identity; DNS name or IPv4. */
  servername: string;
  /** Explicit intrinsically bounded unpooled trust snapshot; optional paired static identity. */
  tls: TLSOptions & { ca: string | Buffer };
  timeoutMs?: number;
  /** 1..4; waiting calls do not copy source bytes until admitted. */
  maxConcurrentCalls?: number;
  /** 4096..65536. Document capacity is independent of frame size. */
  maxFrameBytes?: number;
  maxDocumentBytes?: number;
}
export interface BinaryCallOptions extends CallOptions {
  timeoutMs?: number;
  /** Per-request credential, sent inside verified TLS only. */
  token?: string;
  /** Nonzero 32 lowercase hex characters; generated when absent. No standalone deduplication. */
  requestId?: string;
  /** Opaque schema-1 preconditions, including empty values; server validates syntax.
   * Successful PUT: ifNoneMatch '*' requires 201; a present ifMatch requires 200. */
  ifMatch?: string;
  ifNoneMatch?: string;
}
export interface BinaryEnvelope {
  readonly method: 'GET' | 'HEAD' | 'PUT' | 'DELETE' | 'POST' | 'PATCH';
  readonly target: string;
  readonly contentType: string;
  readonly requestId: string;
  readonly conditions: Readonly<{ ifMatch?: string; ifNoneMatch?: string }>;
  readonly sourceLength: number;
  /** A fresh dedicated unpooled copy of the private source owner. Omitted from JSON/inspection. */
  readonly source: Buffer;
}
export class BinaryUncertainWriteError extends YamoraError {
  readonly requestId: string;
  readonly envelope: BinaryEnvelope;
  private constructor();
}
/** Raw owned schema-2 JSON. No decoded numeric-value API is implied. */
export interface BinaryOperationResponse {
  status: number;
  contentType: string;
  revision: string;
  etag?: string;
  requestId: string;
  representationLength: number;
  body?: Buffer;
  resumeAfter?: string;
}
/** Single-endpoint verified TLS 1.3 CRUD and explicit native operations. No automatic replay. */
export class BinaryClient {
  constructor(config: BinaryConfig);
  operation(method: 'GET' | 'POST' | 'PATCH', target: string, contentType: string, source: YamlSource, options?: BinaryCallOptions): Promise<BinaryOperationResponse>;
  /** Callback is synchronous; receives one owned validated raw page including LF. */
  feed(target: string, onPage: (page: Buffer, metadata: BinaryOperationResponse) => void, options?: BinaryCallOptions): Promise<BinaryOperationResponse>;
  get(collection: string, document: string, options?: BinaryCallOptions): Promise<Document & { requestId: string }>;
  head(collection: string, document: string, options?: BinaryCallOptions): Promise<{ representationLength: number; etag: string; revision: string; requestId: string }>;
  put(collection: string, document: string, source: YamlSource, options?: BinaryCallOptions): Promise<Mutation & { requestId: string }>;
  delete(collection: string, document: string, options?: BinaryCallOptions): Promise<{ revision: string; requestId: string }>;
}
