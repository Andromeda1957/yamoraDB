<?php
declare(strict_types=1);

namespace Yamora;

require_once __DIR__ . '/Transport.php';

final class Document
{
    public function __construct(
        public readonly string $source,
        public readonly string $etag,
        public readonly string $revision,
    ) {}
}

/** Dependency-free, synchronous HTTP foundation. Each primitive call is attempted once. */
final class Client
{
    public const MAX_DOCUMENT_BYTES = 16 * 1024 * 1024;
    public const MAX_REQUEST_BYTES = 64 * 1024 * 1024;
    public const MAX_RESPONSE_BYTES = 64 * 1024 * 1024;
    private readonly Transport $transport;
    private ?\Closure $executor = null;

    public function __construct(
        string $host = '127.0.0.1',
        int $port = 8765,
        #[\SensitiveParameter] string $readToken = '',
        #[\SensitiveParameter] string $writeToken = '',
        float $timeout = 5.0,
        ?TlsOptions $tls = null,
        int $maxResponseBytes = self::MAX_RESPONSE_BYTES,
    ) {
        if (PHP_INT_SIZE !== 8) {
            throw new \InvalidArgumentException('yamora: 64-bit PHP required for document integers');
        }
        $this->transport = new Transport($host, $port, $readToken, $writeToken, $timeout, $tls, $maxResponseBytes);
    }

    /** @internal Cluster adapter only; public standalone construction stays concrete. */
    public static function internalExecutor(\Closure $executor): self
    {
        $client = new self();
        $client->executor = $executor;
        return $client;
    }

    private function exchange(string $method, string $path, string $body, string $media,
        array $headers, bool $write, int $maximum, array $statuses): array
    {
        return $this->executor !== null
            ? ($this->executor)($method, $path, $body, $media, $headers, $write, $maximum, $statuses)
            : $this->transport->request($method, $path, $body, $media, $headers, $write, $maximum, $statuses);
    }

    private static function identifier(string $value): string
    {
        if (!preg_match('/\A[a-z0-9-]{1,128}\z/D', $value)) {
            throw new \InvalidArgumentException('yamora: invalid collection or document identifier');
        }
        return $value;
    }

    private static function revision(string $value): string
    {
        if (!preg_match('/\A[0-9a-f]{16}\z/D', $value)) {
            throw new \InvalidArgumentException('yamora: invalid revision or ETag');
        }
        return $value;
    }

    private static function path(string $collection, string $document): string
    {
        return '/v1/collections/' . self::identifier($collection) . '/documents/' . self::identifier($document);
    }

    private static function conditions(?string $etag, bool $createOnly = false, ?string $requestId = null): array
    {
        if ($etag !== null && $createOnly) {
            throw new \InvalidArgumentException('yamora: conflicting preconditions');
        }
        $headers = [];
        if ($etag !== null) {
            $headers['If-Match'] = '"' . self::revision($etag) . '"';
        } elseif ($createOnly) {
            $headers['If-None-Match'] = '*';
        }
        if ($requestId !== null) {
            if (!preg_match('/\A[0-9a-f]{32}\z/D', $requestId) || $requestId === str_repeat('0', 32)) {
                throw new \InvalidArgumentException('yamora: invalid request identity');
            }
            $headers['X-Yamora-Request-Id'] = $requestId;
        }
        return $headers;
    }

    private static function source(string $source): void
    {
        if ($source === '' || strlen($source) > self::MAX_DOCUMENT_BYTES || preg_match('//u', $source) !== 1) {
            throw new \InvalidArgumentException('yamora: nonempty bounded UTF-8 YAML required');
        }
    }

    /** Validate before encoding: no user-defined serializers, cycles or silently repaired UTF-8. */
    private static function validateJson(mixed $value, int $depth, int &$nodes, int &$bytes, int $maximum): void
    {
        if ($depth > 64 || --$nodes < 0) {
            throw new \InvalidArgumentException('yamora: JSON depth or node limit exceeded');
        }
        if (is_string($value)) {
            if (strlen($value) > $maximum || preg_match('//u', $value) !== 1) {
                throw new \InvalidArgumentException('yamora: invalid or oversized JSON string');
            }
            $bytes += 2;
            // Account for json_encode's actual escaping before allocating its output.
            for ($i = 0, $length = strlen($value); $i < $length; ++$i) {
                $byte = ord($value[$i]);
                if ($byte >= 0x80) {
                    $width = $byte < 0xe0 ? 2 : ($byte < 0xf0 ? 3 : 4);
                    $bytes += $width === 4 ? 12 : 6;
                    $i += $width - 1;
                } elseif ($byte < 0x20) {
                    $bytes += in_array($byte, [8, 9, 10, 12, 13], true) ? 2 : 6;
                } else {
                    $bytes += in_array($byte, [34, 47, 92], true) ? 2 : 1;
                }
                if ($bytes > $maximum) {
                    throw new \InvalidArgumentException('yamora: JSON request exceeds limit');
                }
            }
        } elseif (is_array($value) || (is_object($value) && get_class($value) === \stdClass::class)) {
            $bytes += 2;
            foreach ($value as $key => $child) {
                $bytes += 2;
                if (is_string($key)) {
                    self::validateJson($key, $depth + 1, $nodes, $bytes, $maximum);
                }
                self::validateJson($child, $depth + 1, $nodes, $bytes, $maximum);
            }
        } elseif (!(is_null($value) || is_bool($value) || is_int($value) || (is_float($value) && is_finite($value)))) {
            throw new \InvalidArgumentException('yamora: only standard JSON values accepted');
        }
    }

    private static function encode(array|\stdClass $value, int $maximum): string
    {
        $nodes = 100000;
        $bytes = 0;
        self::validateJson($value, 0, $nodes, $bytes, $maximum);
        try {
            // Keep Unicode escaped: literal NEL is a line break to the native YAML parser.
            $encoded = json_encode($value, JSON_THROW_ON_ERROR | JSON_PRESERVE_ZERO_FRACTION, 128);
        } catch (\JsonException) {
            throw new \InvalidArgumentException('yamora: invalid JSON request');
        }
        if (strlen($encoded) > $maximum) {
            throw new \InvalidArgumentException('yamora: request body exceeds limit');
        }
        return $encoded;
    }

    private static function responseRevision(array $headers, ?string $expected = null): string
    {
        $actual = $headers['x-yamldb-revision'] ?? '';
        if (!preg_match('/\A[0-9a-f]{16}\z/D', $actual) || ($expected !== null && $actual !== $expected)) {
            throw new ProtocolException('yamora: invalid or changed response revision');
        }
        return $actual;
    }

    private static function media(array $headers, array $allowed): void
    {
        $media = strtolower(trim(explode(';', $headers['content-type'] ?? '')[0]));
        if (!in_array($media, $allowed, true)) {
            throw new ProtocolException('yamora: unexpected response media type');
        }
    }

    private function json(string $method, string $path, array|\stdClass|null $value = null,
        array $headers = [], bool $write = false, array $statuses = [200],
        int $maximumRequest = 2 * 1024 * 1024, ?string $revision = null): \stdClass
    {
        $body = $value === null ? '' : self::encode($value, $maximumRequest);
        [$payload, $response] = $this->exchange($method, $path, $body,
            $value === null ? '' : 'application/json', $headers, $write, self::MAX_RESPONSE_BYTES, $statuses);
        self::media($response, ['application/json']);
        $actual = self::responseRevision($response, $revision);
        try {
            $result = json_decode($payload, false, 128, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
        } catch (\JsonException) {
            throw new ProtocolException('yamora: invalid JSON response');
        }
        if (!$result instanceof \stdClass || !self::finiteNumbers($result)) {
            throw new ProtocolException('yamora: expected JSON object');
        }
        if (property_exists($result, 'revision') && $result->revision !== $actual) {
            // Index jobs carry their own older publication revision instead.
            if (!str_starts_with($path, '/v1/index-builds')) {
                throw new ProtocolException('yamora: inconsistent body revision');
            }
        }
        if (!property_exists($result, 'revision')) {
            $result->revision = $actual;
        }
        return $result;
    }

    private static function finiteNumbers(mixed $value): bool
    {
        if (is_float($value)) { return is_finite($value); }
        if (is_array($value) || $value instanceof \stdClass) {
            foreach ($value as $item) {
                if (!self::finiteNumbers($item)) { return false; }
            }
        }
        return true;
    }

    public function health(): \stdClass { return $this->json('GET', '/healthz'); }
    public function ready(): \stdClass { return $this->json('GET', '/readyz'); }
    /** Advisory source preflight before application-owned stages; native admission remains authoritative. */
    public function requireReplicationSource(): \stdClass
    {
        $ready = $this->ready();
        if (property_exists($ready, 'replication_policy_free')) {
            if (!is_bool($ready->replication_policy_free)) {
                throw new ProtocolException('yamora: invalid replication source capability');
            }
            if (!$ready->replication_policy_free) {
                throw new SchemaPolicyReplicationException();
            }
        }
        return $ready;
    }
    public function stats(): \stdClass { return $this->json('GET', '/v1/stats'); }

    public function metrics(): string
    {
        [$body, $headers] = $this->exchange('GET', '/metrics', '', '', [], false, self::MAX_DOCUMENT_BYTES, [200]);
        self::responseRevision($headers);
        self::media($headers, ['text/plain']);
        if (preg_match('//u', $body) !== 1) {
            throw new ProtocolException('yamora: invalid metrics encoding');
        }
        return $body;
    }

    public function get(string $collection, string $document, ?string $revision = null): Document
    {
        if ($revision !== null) {
            self::revision($revision);
        }
        [$body, $headers] = $this->exchange('GET', self::path($collection, $document), '', '', [], false, self::MAX_DOCUMENT_BYTES, [200]);
        $actual = self::responseRevision($headers, $revision);
        self::media($headers, ['application/yaml', 'text/yaml']);
        $etag = $headers['etag'] ?? '';
        if (!preg_match('/\A"([0-9a-f]{16})"\z/D', $etag, $match)) {
            throw new ProtocolException('yamora: invalid document ETag');
        }
        return new Document($body, $match[1], $actual);
    }

    private static function mutation(\stdClass $result): \stdClass
    {
        if (($result->status ?? null) !== 'stored' || !is_string($result->etag ?? null) ||
            !preg_match('/\A[0-9a-f]{16}\z/D', $result->etag) || !is_string($result->revision ?? null)) {
            throw new ProtocolException('yamora: invalid mutation receipt');
        }
        return $result;
    }

    public function put(string $collection, string $document, string $source, ?string $etag = null,
        bool $createOnly = false, ?string $requestId = null): \stdClass
    {
        self::source($source);
        $headers = self::conditions($etag, $createOnly, $requestId);
        [$payload, $response] = $this->exchange('PUT', self::path($collection, $document),
            $source, 'application/yaml', $headers, true, self::MAX_DOCUMENT_BYTES, [200, 201]);
        self::media($response, ['application/json']);
        try {
            $result = json_decode($payload, false, 128, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new ProtocolException('yamora: invalid mutation receipt');
        }
        if (!$result instanceof \stdClass || !self::finiteNumbers($result)) {
            throw new ProtocolException('yamora: invalid mutation receipt');
        }
        if (!is_string($result->revision ?? null)) {
            throw new ProtocolException('yamora: missing mutation revision');
        }
        self::responseRevision($response, $result->revision);
        return self::mutation($result);
    }

    public function patch(string $collection, string $document, array|\stdClass $operations,
        ?string $etag = null, ?string $requestId = null): \stdClass
    {
        if (count((array) $operations) === 0) {
            throw new \InvalidArgumentException('yamora: empty patch');
        }
        return self::mutation($this->json('PATCH', self::path($collection, $document), (object) $operations,
            self::conditions($etag, false, $requestId), true, [200], self::MAX_REQUEST_BYTES));
    }

    public function delete(string $collection, string $document, ?string $etag = null, ?string $requestId = null): string
    {
        [, $headers] = $this->exchange('DELETE', self::path($collection, $document), '', '',
            self::conditions($etag, false, $requestId), true, 0, [204]);
        return self::responseRevision($headers);
    }

    private static function names(mixed $names, int $maximum, string $after = ''): void
    {
        if (!is_array($names) || count($names) > $maximum) {
            throw new ProtocolException('yamora: invalid name list');
        }
        foreach ($names as $name) {
            if (!is_string($name) || !preg_match('/\A[a-z0-9-]{1,128}\z/D', $name) || strcmp($name, $after) <= 0) {
                throw new ProtocolException('yamora: unordered or invalid name list');
            }
            $after = $name;
        }
    }

    public function collections(?string $revision = null): \stdClass
    {
        if ($revision !== null) { self::revision($revision); }
        $result = $this->json('GET', '/v1/collections', revision: $revision);
        self::names($result->collections ?? null, 65536);
        return $result;
    }

    public function documentPage(string $collection, int $limit = 1000, ?string $after = null, ?string $revision = null): \stdClass
    {
        self::identifier($collection);
        if ($limit < 1 || $limit > 1000 || ($after !== null && $revision === null)) {
            throw new \InvalidArgumentException('yamora: invalid page size or unpinned cursor');
        }
        if ($revision !== null) { self::revision($revision); }
        $path = '/v1/collections/' . $collection . '/documents?limit=' . $limit;
        if ($after !== null) { $path .= '&after=' . self::identifier($after); }
        $result = $this->json('GET', $path, revision: $revision);
        self::names($result->documents ?? null, $limit, $after ?? '');
        if (($result->collection ?? null) !== $collection || !property_exists($result, 'next_after') ||
            ($result->next_after !== null && ($result->documents === [] || $result->next_after !== end($result->documents)))) {
            throw new ProtocolException('yamora: invalid document page');
        }
        return $result;
    }

    /** Each yielded ID belongs to the first page's revision; any later change fails closed. */
    public function documents(string $collection, ?string $revision = null): \Generator
    {
        $after = null;
        do {
            $page = $this->documentPage($collection, after: $after, revision: $revision);
            $revision = $page->revision;
            foreach ($page->documents as $id) { yield $id; }
            $after = $page->next_after;
        } while ($after !== null);
    }

    private static function queryOptions(array $spec): void
    {
        if (isset($spec['revision'])) { self::revision($spec['revision']); }
        if (isset($spec['limit']) && (!is_int($spec['limit']) || $spec['limit'] < 1 || $spec['limit'] > 1000)) {
            throw new \InvalidArgumentException('yamora: invalid query limit');
        }
        if (isset($spec['after'])) {
            self::identifier($spec['after']);
            if (!isset($spec['revision']) || ($spec['count_only'] ?? false)) {
                throw new \InvalidArgumentException('yamora: query cursor requires revision');
            }
        }
    }

    public function query(string $collection, array $spec = []): \stdClass
    {
        self::queryOptions($spec);
        $result = $this->json('POST', '/v1/query/' . self::identifier($collection), (object) $spec,
            revision: $spec['revision'] ?? null);
        if (!is_array($result->documents ?? null) || count($result->documents) > ($spec['limit'] ?? 100) ||
            !property_exists($result, 'next_after') || !property_exists($result, 'matched') ||
            !is_string($result->revision ?? null)) {
            throw new ProtocolException('yamora: invalid query result');
        }
        if (($result->matched === null && (($spec['count_only'] ?? false) || ($spec['include_count'] ?? true))) ||
            ($result->matched !== null && (!is_int($result->matched) || $result->matched < count($result->documents))) ||
            ($result->next_after !== null && (!is_string($result->next_after) || !preg_match('/\A[a-z0-9-]{1,128}\z/D', $result->next_after)))) {
            throw new ProtocolException('yamora: invalid query count or cursor');
        }
        foreach ($result->documents as $row) {
            if (!$row instanceof \stdClass || !is_string($row->id ?? null) ||
                !preg_match('/\A[a-z0-9-]{1,128}\z/D', $row->id) || !property_exists($row, 'value')) {
                throw new ProtocolException('yamora: invalid query row');
            }
        }
        return $result;
    }

    public function count(string $collection, array|\stdClass $filter = new \stdClass(), ?string $revision = null): int
    {
        $spec = ['filter' => (object) $filter, 'count_only' => true];
        if ($revision !== null) { $spec['revision'] = $revision; }
        return $this->query($collection, $spec)->matched;
    }

    public function aggregate(string $collection, array $pipeline, ?string $revision = null): \stdClass
    {
        if (!array_is_list($pipeline) || count($pipeline) < 1 || count($pipeline) > 32) {
            throw new \InvalidArgumentException('yamora: invalid aggregation pipeline');
        }
        $spec = ['pipeline' => $pipeline];
        if ($revision !== null) { $spec['revision'] = self::revision($revision); }
        $result = $this->json('POST', '/v1/aggregate/' . self::identifier($collection), $spec, revision: $revision);
        if (!is_array($result->documents ?? null) || count($result->documents) > 65536 ||
            !is_int($result->documents_examined ?? null) || $result->documents_examined < 0) {
            throw new ProtocolException('yamora: invalid aggregation result');
        }
        foreach ($result->documents as $row) {
            if (!$row instanceof \stdClass) { throw new ProtocolException('yamora: invalid aggregation row'); }
        }
        return $result;
    }

    public function search(string $collection, string $index, string $text, array $options = []): \stdClass
    {
        self::queryOptions($options);
        self::identifier($index);
        if ($text === '' || strlen($text) > 8192 || !in_array($options['mode'] ?? 'all', ['all', 'any'], true) ||
            isset($options['index']) || isset($options['text'])) {
            throw new \InvalidArgumentException('yamora: invalid text search');
        }
        $result = $this->json('POST', '/v1/search/' . self::identifier($collection),
            ['index' => $index, 'text' => $text] + $options, revision: $options['revision'] ?? null);
        if (!is_array($result->documents ?? null) || count($result->documents) > ($options['limit'] ?? 100) ||
            !property_exists($result, 'next_after') || !is_int($result->documents_examined ?? null) ||
            !is_int($result->index_entries_examined ?? null) || $result->documents_examined < count($result->documents) ||
            $result->index_entries_examined < $result->documents_examined) {
            throw new ProtocolException('yamora: invalid search result');
        }
        $previous = $options['after'] ?? '';
        foreach ($result->documents as $row) {
            if (!$row instanceof \stdClass || !is_string($row->id ?? null) ||
                !preg_match('/\A[a-z0-9-]{1,128}\z/D', $row->id) || strcmp($row->id, $previous) <= 0 ||
                !is_int($row->score ?? null) || $row->score < 1 || $row->score > 32 || !property_exists($row, 'value')) {
                throw new ProtocolException('yamora: invalid search row');
            }
            $previous = $row->id;
        }
        if ($result->next_after !== null && ($result->documents === [] || $result->next_after !== $previous)) {
            throw new ProtocolException('yamora: invalid search cursor');
        }
        return $result;
    }

    public function indexes(): \stdClass
    {
        $result = $this->json('GET', '/v1/indexes');
        if (!is_array($result->indexes ?? null) || count($result->indexes) > 64) {
            throw new ProtocolException('yamora: invalid index catalog');
        }
        return $result;
    }

    private static function indexDefinitions(array $indexes): void
    {
        if (!array_is_list($indexes) || count($indexes) > 64) {
            throw new \InvalidArgumentException('yamora: invalid index catalog');
        }
        $seen = [];
        foreach ($indexes as $item) {
            if (!is_array($item)) { throw new \InvalidArgumentException('yamora: invalid index definition'); }
            $identity = self::path($item['collection'] ?? '', $item['name'] ?? '');
            $fields = $item['fields'] ?? null;
            if (isset($seen[$identity]) || !is_array($fields) || !array_is_list($fields) ||
                count($fields) < 1 || count($fields) > 8 || count(array_unique($fields, SORT_REGULAR)) !== count($fields) ||
                !is_bool($item['unique'] ?? false) || !in_array($item['type'] ?? '', ['', 'text'], true) ||
                (($item['type'] ?? '') === 'text' && ($item['unique'] ?? false))) {
                throw new \InvalidArgumentException('yamora: invalid index definition');
            }
            foreach ($fields as $field) {
                if (!is_string($field) || $field === '' || ($field === '$source' && (($item['type'] ?? '') !== 'text' || count($fields) !== 1))) {
                    throw new \InvalidArgumentException('yamora: invalid index field');
                }
            }
            $seen[$identity] = true;
        }
    }

    public function setIndexes(array $indexes, ?string $revision = null, ?string $requestId = null): \stdClass
    {
        self::indexDefinitions($indexes);
        $result = $this->json('PUT', '/v1/indexes', ['indexes' => $indexes], self::conditions($revision, false, $requestId), true);
        if (($result->status ?? null) !== 'committed' || ($result->operations ?? null) !== 1) {
            throw new ProtocolException('yamora: invalid index publication receipt');
        }
        return $result;
    }

    public function startIndexBuild(array $indexes, ?string $revision = null): \stdClass
    {
        self::indexDefinitions($indexes);
        return self::indexJob($this->json('POST', '/v1/index-builds', ['indexes' => $indexes], self::conditions($revision), true, [202]));
    }

    private static function jobId(string $id): string
    {
        if (!preg_match('/\A[0-9a-f]{32}\z/D', $id)) { throw new \InvalidArgumentException('yamora: invalid index job ID'); }
        return $id;
    }

    public function indexBuild(?string $id = null): \stdClass
    {
        return self::indexJob($this->json('GET', '/v1/index-builds' . ($id === null ? '' : '/' . self::jobId($id))), $id);
    }

    public function cancelIndexBuild(string $id): \stdClass
    {
        return self::indexJob($this->json('DELETE', '/v1/index-builds/' . self::jobId($id), write: true, statuses: [202]), $id);
    }

    private static function indexJob(\stdClass $job, ?string $id = null): \stdClass
    {
        $terminal = in_array($job->status ?? null, ['succeeded', 'failed', 'cancelled'], true);
        if (!is_string($job->id ?? null) || ($id !== null && $job->id !== $id) ||
            (!preg_match('/\A[0-9a-f]{32}\z/D', $job->id) && !(($job->status ?? null) === 'idle' && $job->id === '')) ||
            !in_array($job->status ?? null, ['idle', 'running', 'succeeded', 'failed', 'cancelled'], true) ||
            !in_array($job->phase ?? null, ['idle', 'scanning', 'catching_up', 'publishing', 'done'], true) ||
            !is_int($job->documents_scanned ?? null) || $job->documents_scanned < 0 ||
            !is_int($job->transactions_replayed ?? null) || $job->transactions_replayed < 0 ||
            !is_bool($job->cancel_requested ?? null) || !is_string($job->error ?? null) ||
            !is_string($job->revision ?? null) || ($terminal && $job->phase !== 'done') ||
            ($job->status === 'running' && in_array($job->phase, ['idle', 'done'], true)) ||
            ($job->status === 'succeeded' && (!preg_match('/\A[0-9a-f]{16}\z/D', $job->revision) || $job->error !== '')) ||
            ($job->status !== 'succeeded' && $job->revision !== '')) {
            throw new ProtocolException('yamora: invalid index job');
        }
        return $job;
    }

    public function transaction(array $operations, ?string $revision = null, ?string $requestId = null): \stdClass
    {
        if (!array_is_list($operations) || count($operations) < 1 || count($operations) > 128) {
            throw new \InvalidArgumentException('yamora: invalid transaction size');
        }
        $seen = [];
        foreach ($operations as $op) {
            if (!is_array($op)) { throw new \InvalidArgumentException('yamora: invalid operation'); }
            $path = self::path($op['collection'] ?? '', $op['document'] ?? '');
            $actions = (int) array_key_exists('put', $op) + (int) array_key_exists('patch', $op) + (int) array_key_exists('delete', $op);
            if (isset($seen[$path]) || $actions !== 1 || (isset($op['delete']) && $op['delete'] !== true) ||
                (isset($op['create_only']) && (!is_bool($op['create_only']) || ($op['create_only'] && !isset($op['put']))))) {
                throw new \InvalidArgumentException('yamora: conflicting transaction operation');
            }
            self::conditions($op['etag'] ?? null, $op['create_only'] ?? false);
            if (array_key_exists('put', $op)) { self::source($op['put']); }
            if (array_key_exists('patch', $op) && (!(is_array($op['patch']) || $op['patch'] instanceof \stdClass) || count((array) $op['patch']) === 0)) {
                throw new \InvalidArgumentException('yamora: invalid transaction patch');
            }
            $seen[$path] = true;
        }
        $body = ['operations' => $operations];
        if ($revision !== null) { $body['revision'] = self::revision($revision); }
        $result = $this->json('POST', '/v1/transactions', $body, self::conditions(null, false, $requestId), true,
            [200], self::MAX_REQUEST_BYTES);
        if (($result->status ?? null) !== 'committed' || ($result->operations ?? null) !== count($operations) ||
            !is_string($result->revision ?? null)) {
            throw new ProtocolException('yamora: invalid transaction receipt');
        }
        return $result;
    }

    public function changes(?string $after = null, int $limit = 100): \stdClass
    {
        if ($limit < 1 || $limit > 100 || ($after !== null && !preg_match('/\Av1\.[0-9a-f]{32}\.[0-9a-f]{16}\z/D', $after))) {
            throw new \InvalidArgumentException('yamora: invalid change cursor or limit');
        }
        $path = '/v1/changes' . ($after === null ? '' : '?after=' . $after . '&limit=' . $limit);
        $result = $this->json('GET', $path);
        if (!is_array($result->transactions ?? null) || count($result->transactions) > $limit || !is_bool($result->has_more ?? null)) {
            throw new ProtocolException('yamora: invalid change page');
        }
        foreach (['next_after', 'oldest_after', 'checkpoint'] as $key) {
            if (!is_string($result->$key ?? null) || !preg_match('/\Av1\.[0-9a-f]{32}\.[0-9a-f]{16}\z/D', $result->$key)) {
                throw new ProtocolException('yamora: invalid returned change cursor');
            }
        }
        return $result;
    }
}
