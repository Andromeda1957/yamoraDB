<?php
declare(strict_types=1);
namespace Yamora;
require_once __DIR__ . '/Client.php';
require_once __DIR__ . '/StrictJson.php';

/** Immutable recovery inputs, with no transport, credentials or caller-owned objects. */
final class PreparedMutation
{
    private function __construct(
        public readonly string $clusterId,
        public readonly string $method,
        public readonly string $path,
        public readonly string $body,
        public readonly string $media,
        public readonly array $headers,
        public readonly int $maximum,
        public readonly array $statuses,
        public readonly string $requestId,
        public readonly int $operations,
    ) {}
    /** @internal Receives an already validated, once-encoded Client request. */
    public static function capture(string $clusterId, string $method, string $path, string $body,
        string $media, array $headers, int $maximum, array $statuses, OperationControl $control): self
    {
        $document = preg_match('~\A/v1/collections/([a-z0-9-]{1,128})/documents/([a-z0-9-]{1,128})\z~D', $path, $parts);
        if (!(($document && in_array($method, ['PUT', 'PATCH', 'DELETE'], true)) ||
            ($method === 'POST' && $path === '/v1/transactions') || ($method === 'PUT' && $path === '/v1/indexes'))) {
            throw new HttpException(405);
        }
        if ($document && $parts[1] === 'yamldb-system') { throw new \InvalidArgumentException('yamora: reserved collection'); }
        $id = $headers['X-Yamora-Request-Id'] ?? null;
        if ($id === null) { do { $id = bin2hex(random_bytes(16)); } while ($id === str_repeat('0', 32)); }
        if (!is_string($id) || !preg_match('/\A[0-9a-f]{32}\z/D', $id) || $id === str_repeat('0', 32)) {
            throw new \InvalidArgumentException('yamora: invalid request identity');
        }
        $headers['X-Yamora-Request-Id'] = $id;
        $count = $path === '/v1/transactions' ? count(StrictJson::decode($body, $control)->operations) : 1;
        return new self($clusterId, $method, $path, $body, $media, $headers, $maximum, $statuses, $id, $count);
    }
    public function __debugInfo(): array { return ['requestId' => $this->requestId]; }
}
final class UncertainWriteException extends DriverException
{
    public readonly string $requestId;
    public readonly string $reason;
    public readonly ?int $status;
    public function __construct(public readonly PreparedMutation $mutation, DriverException $failure)
    {
        $this->requestId = $mutation->requestId;
        $this->reason = $failure::class;
        $this->status = $failure instanceof HttpException ? $failure->status : null;
        parent::__construct('yamora: write outcome uncertain; execute the original immutable mutation to recover');
    }
    public function __debugInfo(): array { return ['requestId' => $this->requestId, 'reason' => $this->reason, 'status' => $this->status]; }
}
/** @internal Carries a prepared operation out of the concrete Client's encoding seam. */
final class MutationCaptured extends \RuntimeException
{
    public function __construct(public readonly PreparedMutation $mutation) { parent::__construct('yamora: prepared'); }
}

/** Additive synchronous replica-set client. Only configured seeds receive credentials. */
final class ClusterClient
{
    private const METHODS = ['health', 'ready', 'stats', 'metrics', 'get', 'put', 'patch', 'delete',
        'collections', 'documentPage', 'query', 'count', 'aggregate', 'search', 'indexes', 'setIndexes', 'transaction', 'changes'];
    private array $seeds = [];
    private ?int $route = null;
    private int $cursor = 0;
    private bool $busy = false;

    public function __construct(array $seeds, private readonly string $clusterId, private readonly int $voters,
        TlsOptions $tls, #[\SensitiveParameter] string $readToken = '', #[\SensitiveParameter] string $writeToken = '',
        private readonly float $timeout = 5, private readonly float $attemptTimeout = 1,
        int $maxResponseBytes = Client::MAX_RESPONSE_BYTES)
    {
        if (!preg_match('/\A[0-9a-f]{32}\z/D', $clusterId) || $clusterId === str_repeat('0', 32) ||
            !in_array($voters, [3, 5, 7, 9], true) || !array_is_list($seeds) || count($seeds) < 1 || count($seeds) > 9) {
            throw new \InvalidArgumentException('yamora: invalid cluster binding');
        }
        self::duration($timeout); self::duration($attemptTimeout);
        $addresses = []; $nodes = [];
        foreach ($seeds as $seed) {
            if (!is_array($seed) || count($seed) !== 3 || !is_string($seed['host'] ?? null) ||
                !is_int($seed['port'] ?? null) || !is_int($seed['node'] ?? null) || $seed['node'] < 1 || $seed['node'] > $voters) {
                throw new \InvalidArgumentException('yamora: explicit private IPv4, port and node required');
            }
            $address = $seed['host'] . ':' . $seed['port'];
            if (isset($addresses[$address]) || isset($nodes[$seed['node']])) { throw new \InvalidArgumentException('yamora: duplicate seed binding'); }
            $transport = new Transport($seed['host'], $seed['port'], $readToken, $writeToken, $attemptTimeout, $tls, $maxResponseBytes);
            $this->seeds[] = [$transport, $seed['node']];
            $addresses[$address] = true; $nodes[$seed['node']] = true;
        }
    }
    public function __debugInfo(): array { return ['clusterId' => $this->clusterId, 'voters' => $this->voters]; }
    private static function duration(float $v): void
    {
        if (!is_finite($v) || $v <= 0 || $v > 30) { throw new \InvalidArgumentException('yamora: timeout must be in (0,30] seconds'); }
    }
    private function operation(\Closure $action, ?float $timeout, ?CancellationToken $cancellation): mixed
    {
        // No mutable operation context crosses a scheduler or reentrant callback.
        if (\Fiber::getCurrent() !== null || $this->busy) { throw new \LogicException('yamora: concurrent/reentrant fiber use unsupported'); }
        $timeout ??= $this->timeout; self::duration($timeout);
        $control = new OperationControl(hrtime(true) / 1e9 + min($timeout, $this->timeout), $cancellation);
        $mutation = null; $uncertain = false;
        $this->busy = true;
        try {
            $control->check();
            $result = $action($control, $mutation, $uncertain);
            $control->check();
            return $result;
        } catch (DriverException $failure) {
            if ($mutation !== null && $uncertain) { throw new UncertainWriteException($mutation, $failure); }
            throw $failure;
        } finally { $this->busy = false; }
    }
    /** Existing Client APIs plus named timeout/cancellation per call. */
    public function __call(string $method, array $arguments): mixed
    {
        if (in_array($method, ['startIndexBuild', 'indexBuild', 'cancelIndexBuild', 'replication', 'followReplication', 'continuousChanges'], true)) {
            throw new HttpException(405);
        }
        if (!in_array($method, self::METHODS, true)) { throw new \BadMethodCallException('yamora: unknown operation'); }
        $timeout = $arguments['timeout'] ?? null; $cancellation = $arguments['cancellation'] ?? null;
        unset($arguments['timeout'], $arguments['cancellation']);
        return $this->operation(function ($control, &$mutation, &$uncertain) use ($method, $arguments) {
            $adapter = Client::internalExecutor(function ($verb, $path, $body, $media, $headers, $write, $maximum, $statuses)
                use ($control, &$mutation, &$uncertain) {
                if ($write) {
                    $mutation = PreparedMutation::capture($this->clusterId, $verb, $path, $body, $media, $headers, $maximum, $statuses, $control);
                    $headers = $mutation->headers;
                }
                $response = $this->exchange($verb, $path, $body, $media, $headers, $write, $maximum, $statuses, $control, $mutation, $uncertain);
                // Validate every JSON read while the operation control is active,
                // before the standalone decoder can overwrite duplicate keys or
                // accept a larger depth/value budget. YAML/metrics stay raw.
                if (!$write && strtolower(trim(explode(';', $response[1]['content-type'] ?? '')[0])) === 'application/json') {
                    self::json($response, $control);
                }
                return $response;
            });
            return $adapter->$method(...$arguments);
        }, $timeout, $cancellation);
    }
    /** Prepare through the same concrete input validators/encoder, without I/O. */
    public function prepareMutation(string $method, array $arguments): PreparedMutation
    {
        if (!in_array($method, ['put', 'patch', 'delete', 'transaction', 'setIndexes'], true)) { throw new HttpException(405); }
        return $this->operation(function ($control) use ($method, $arguments) {
            $adapter = Client::internalExecutor(function ($verb, $path, $body, $media, $headers, $write, $maximum, $statuses) use ($control) {
                throw new MutationCaptured(PreparedMutation::capture($this->clusterId, $verb, $path, $body, $media, $headers, $maximum, $statuses, $control));
            });
            try { $adapter->$method(...$arguments); } catch (MutationCaptured $captured) { return $captured->mutation; }
            throw new \LogicException('yamora: mutation preparation failed');
        }, null, null);
    }
    /** Recovery retains a previous uncertain dispatch even if replay rejects. */
    public function recover(UncertainWriteException $failure, ?float $timeout = null, ?CancellationToken $cancellation = null): \stdClass|string
    {
        try { return $this->executePrepared($failure->mutation, $timeout, $cancellation, true); }
        catch (UncertainWriteException $uncertain) { throw $uncertain; }
        catch (DriverException $later) { throw new UncertainWriteException($failure->mutation, $later); }
    }
    public function execute(PreparedMutation $prepared, ?float $timeout = null, ?CancellationToken $cancellation = null): \stdClass|string
    {
        return $this->executePrepared($prepared, $timeout, $cancellation, false);
    }
    private function executePrepared(PreparedMutation $prepared, ?float $timeout, ?CancellationToken $cancellation, bool $priorUncertainty): \stdClass|string
    {
        if ($prepared->clusterId !== $this->clusterId) { throw new \InvalidArgumentException('yamora: recovery cluster binding differs'); }
        return $this->operation(function ($control, &$mutation, &$uncertain) use ($prepared, $priorUncertainty) {
            $mutation = $prepared;
            $uncertain = $priorUncertainty;
            $response = $this->exchange($prepared->method, $prepared->path, $prepared->body, $prepared->media,
                $prepared->headers, true, $prepared->maximum, $prepared->statuses, $control, $mutation, $uncertain);
            return self::receipt($prepared, $response, $control);
        }, $timeout, $cancellation);
    }
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
    private static function valid(bool $condition): void
    {
        if (!$condition) { throw new ProtocolException('yamora: invalid cluster identity or receipt'); }
    }
    private static function json(array $response, OperationControl $control): \stdClass
    {
        [$body, $headers] = $response;
        self::valid(strtolower(trim(explode(';', $headers['content-type'] ?? '')[0])) === 'application/json');
        self::valid(preg_match('/\A[0-9a-f]{16}\z/D', $headers['x-yamldb-revision'] ?? '') === 1);
        $v = StrictJson::decode($body, $control);
        self::valid(!property_exists($v, 'revision') || $v->revision === $headers['x-yamldb-revision']);
        return $v;
    }
    private function discover(OperationControl $control, int &$attempts): ?int
    {
        $start = $this->route ?? $this->cursor;
        $count = count($this->seeds);
        for ($offset = 0; $offset < $count && $attempts < 32; ++$offset) {
            $control->check(); $index = ($start + $offset) % $count;
            [$transport, $node] = $this->seeds[$index];
            try {
                ++$attempts;
                $v = self::json($transport->request('GET', '/v1/cluster/status', '', '', [], false, 4096, [200],
                    $control->budget($this->attemptTimeout, $count - $offset + 2)), $control);
                self::valid(($v->node ?? null) === $node && ($v->leader ?? null) === $node && ($v->voters ?? null) === $this->voters &&
                    ($v->role ?? null) === 'leader' && is_int($v->term ?? null) && $v->term > 0 && ($v->failed ?? null) === false);
                foreach (['applied', 'committed', 'last'] as $key) { self::valid(is_int($v->$key ?? null) && $v->$key >= 0); }
                self::valid($v->applied <= $v->committed && $v->committed <= $v->last);
                if ($attempts >= 32) { break; }
                ++$attempts;
                $feed = self::json($transport->request('GET', '/v1/changes', '', '', [], false, 4096, [200],
                    $control->budget($this->attemptTimeout, $count - $offset + 1)), $control);
                foreach (['checkpoint', 'next_after', 'oldest_after'] as $key) {
                    self::valid(is_string($feed->$key ?? null) && preg_match('/\Av1\.([0-9a-f]{32})\.[0-9a-f]{16}\z/D', $feed->$key, $match) === 1 && $match[1] === $this->clusterId);
                }
                self::valid(($feed->transactions ?? null) === [] && ($feed->has_more ?? null) === false && $feed->next_after === $feed->checkpoint);
                $control->check(); $this->route = $index;
                return $index;
            } catch (DriverException $failure) {
                if ($failure instanceof CancelledException || ($failure instanceof HttpException && in_array($failure->status, [401, 403], true))) { throw $failure; }
                $control->check();
            }
        }
        $this->route = null; $this->cursor = ($start + 1) % $count;
        return null;
    }
    private function exchange(string $method, string $path, string $body, string $media, array $headers,
        bool $write, int $maximum, array $statuses, OperationControl $control, ?PreparedMutation $mutation, bool &$uncertain): array
    {
        $attempts = 0; $delay = 0.025; $last = new HttpException(503);
        while ($attempts < 32) {
            $control->check();
            $index = $this->discover($control, $attempts);
            if ($index !== null && $attempts < 32) {
                ++$attempts; $dispatched = false; $prior = $uncertain;
                try {
                    $response = $this->seeds[$index][0]->request($method, $path, $body, $media, $headers, $write, $maximum, $statuses,
                        $control->budget($this->attemptTimeout, count($this->seeds) > 1 ? 2 : 1),
                        static function () use (&$dispatched, &$uncertain, $write) { $dispatched = true; if ($write) { $uncertain = true; } });
                    if ($mutation !== null) { self::receipt($mutation, $response, $control); }
                    $control->check();
                    return $response;
                } catch (DriverException $failure) {
                    // A definitive first rejection is certain. It cannot erase an
                    // earlier dispatch whose result was lost or malformed.
                    if (!$dispatched || ($failure instanceof HttpException && $failure->status >= 400 && $failure->status < 500 && $failure->status !== 408)) { $uncertain = $prior; }
                    $last = $failure; $control->check();
                    if (!($failure instanceof TransportException || $failure instanceof DeadlineException || ($failure instanceof HttpException && $failure->status === 503))) { throw $failure; }
                    $this->route = null; $this->cursor = ($index + 1) % count($this->seeds);
                }
            }
            $control->backoff($delay); $delay = min(0.5, $delay * 2);
        }
        $control->check(); throw $last;
    }
    private static function receipt(PreparedMutation $mutation, array $response, OperationControl $control): \stdClass|string
    {
        [$body, $headers, $status] = $response;
        $revision = $headers['x-yamldb-revision'] ?? '';
        self::valid(preg_match('/\A[0-9a-f]{16}\z/D', $revision) === 1);
        if ($mutation->method === 'DELETE') {
            self::valid($status === 204 && $body === '' && (!isset($headers['etag']) || $headers['etag'] === '"' . $revision . '"'));
            return $revision;
        }
        $v = self::json($response, $control);
        self::valid(($v->revision ?? null) === $revision);
        if (str_starts_with($mutation->path, '/v1/collections/')) {
            $parts = explode('/', $mutation->path);
            $statuses = $mutation->method !== 'PUT' || isset($mutation->headers['If-Match']) ? [200] :
                (isset($mutation->headers['If-None-Match']) ? [201] : [200, 201]);
            self::valid(in_array($status, $statuses, true) && ($v->status ?? null) === 'stored' && ($v->collection ?? null) === $parts[3] &&
                ($v->document ?? null) === $parts[5] && is_string($v->etag ?? null) && preg_match('/\A[0-9a-f]{16}\z/D', $v->etag) === 1 &&
                ($headers['etag'] ?? null) === '"' . $v->etag . '"');
        } else {
            self::valid($status === 200 && ($v->status ?? null) === 'committed' && is_int($v->operations ?? null) && $v->operations === $mutation->operations &&
                (!isset($headers['etag']) || $headers['etag'] === '"' . $revision . '"'));
        }
        $control->check(); return $v;
    }
}
