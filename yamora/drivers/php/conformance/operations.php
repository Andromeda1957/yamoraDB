<?php
declare(strict_types=1);

// The runner owns fixtures and assertions. Only public SDK types are used here.
require_once __DIR__ . '/../src/BinaryOperationClient.php';

function demand(bool $value): void
{
    if (!$value) { throw new RuntimeException('adapter input or infrastructure'); }
}

function arguments(array $argv): array
{
    $required = ['host', 'port', 'server-name', 'ca-file', 'cert-file', 'key-file', 'method',
        'target', 'content-type', 'feed', 'source-file', 'request-id', 'timeout-ms', 'max-frame-bytes',
        'cancel-mode', 'output-dir'];
    $allowed = [...$required, 'token-file', 'if-match', 'if-none-match'];
    demand(count($argv) % 2 === 1);
    $args = [];
    for ($i = 1; $i < count($argv); $i += 2) {
        demand(str_starts_with($argv[$i], '--'));
        $name = substr($argv[$i], 2);
        demand(in_array($name, $allowed, true) && !array_key_exists($name, $args) && strlen($argv[$i + 1]) <= 4096);
        $args[$name] = $argv[$i + 1];
    }
    foreach ($required as $name) { demand(array_key_exists($name, $args)); }
    return $args;
}

function number(string $value, int $maximum): int
{
    demand(preg_match('/\A[0-9]{1,5}\z/D', $value) === 1);
    $n = (int)$value;
    demand($n >= 1 && $n <= $maximum);
    return $n;
}

function readBounded(string $path, int $cap): string
{
    demand(str_starts_with($path, '/') && is_file($path));
    $handle = fopen($path, 'rb');
    demand($handle !== false);
    try { $bytes = stream_get_contents($handle, $cap + 1); }
    finally { fclose($handle); }
    demand($bytes !== false && strlen($bytes) <= $cap);
    return $bytes;
}

function writeOwned(string $root, string $name, string $bytes): void
{
    $handle = fopen($root . '/' . $name, 'xb');
    demand($handle !== false);
    try {
        demand(chmod($root . '/' . $name, 0600));
        for ($offset = 0; $offset < strlen($bytes);) {
            $n = fwrite($handle, substr($bytes, $offset, 65536));
            demand($n !== false && $n > 0);
            $offset += $n;
        }
    } finally { fclose($handle); }
}

function kind(string $class): string
{
    // BinaryUncertainException exposes the original exception class as reason.
    return match ($class) {
        Yamora\BinaryStatusException::class => 'status',
        Yamora\DeadlineException::class => 'deadline',
        Yamora\CancelledException::class => 'cancelled',
        Yamora\ProtocolException::class => 'protocol',
        Yamora\TransportException::class => 'transport',
        default => throw new RuntimeException('unexpected SDK error type'),
    };
}

function observe(array $argv): array
{
    $args = arguments($argv);
    $port = number($args['port'], 65535);
    $timeout = number($args['timeout-ms'], 30000) / 1000;
    demand($args['host'] === '127.0.0.1' && $args['server-name'] === 'localhost' && $port !== 8000 && $args['max-frame-bytes'] === '4096');
    demand(in_array($args['cancel-mode'], ['none', 'pre', 'external'], true));
    demand(in_array($args['method'], ['GET', 'POST', 'PATCH'], true));
    $root = $args['output-dir'];
    demand(str_starts_with($root, '/') && realpath($root) === $root && is_dir($root));
    $source = readBounded($args['source-file'], 16777216);
    demand(in_array($args['feed'], ['true', 'false'], true));
    demand($args['method'] !== 'GET' || ($source === '' && $args['content-type'] === ''));
    demand($args['feed'] !== 'true' || ($args['method'] === 'GET' && str_starts_with($args['target'], '/v1/changes/stream?')));
    $bearer = isset($args['token-file']) ? readBounded($args['token-file'], 512) : null;
    demand(extension_loaded('openssl') && function_exists('posix_geteuid'));
    if ($args['cancel-mode'] === 'external') {
        demand(function_exists('pcntl_async_signals') && function_exists('pcntl_signal'));
    }
    // PHP's synchronous client has exactly one admission slot. The SDK owns
    // any temporary TLS files under this already-owned credential parent.
    $client = new Yamora\BinaryOperationClient(new Yamora\BinaryConfig(
        host: $args['host'], port: $port, serverName: $args['server-name'],
        caPem: readBounded($args['ca-file'], 1048576), privateDirectory: dirname($args['key-file']),
        clientCertPem: readBounded($args['cert-file'], 1048576), clientKeyPem: readBounded($args['key-file'], 1048576),
        timeout: $timeout, maxFrame: 4096));
    $cancel = new Yamora\CancellationToken();
    if ($args['cancel-mode'] === 'pre') { $cancel->cancel(); }
    $oldHandler = null;
    $oldAsync = false;
    if ($args['cancel-mode'] === 'external') {
        $oldHandler = pcntl_signal_get_handler(SIGUSR1);
        $oldAsync = pcntl_async_signals();
        pcntl_async_signals(true);
        demand(pcntl_signal(SIGUSR1, static function () use ($cancel): void { $cancel->cancel(); }));
    }
    $observation = ['schema' => 'yamora-operation-observation/3', 'outcome' => 'success', 'error_kind' => null,
        'elapsed_ns' => 0, 'api' => array_fill_keys(['status', 'body_file', 'etag', 'revision',
            'representation_length', 'request_id', 'receipt'], null), 'envelope' => null];
    $response = null; $error = null; $feedResult = null; $handle = null; $delivered = false;
    try {
        $started = hrtime(true);
        try {
            if ($args['feed'] === 'true') {
                $feedResult = $client->feed($args['target'], static function (Yamora\BinaryChangePage $page) use ($root, &$handle, &$delivered): bool {
                    if ($handle === null) { $handle = fopen($root . '/body.bin', 'xb'); demand($handle !== false); demand(chmod($root . '/body.bin', 0600)); }
                    for ($at = 0; $at < strlen($page->bytes);) {
                        $n = fwrite($handle, substr($page->bytes, $at, 65536)); demand($n !== false && $n > 0); $at += $n;
                    }
                    $delivered = true;
                    return true;
                }, token: $bearer, ifMatch: $args['if-match'] ?? null, ifNoneMatch: $args['if-none-match'] ?? null,
                    requestId: $args['request-id'], cancellation: $cancel);
            } else {
                $response = $client->operation($args['method'], $args['target'], $source, $args['content-type'],
                    token: $bearer, ifMatch: $args['if-match'] ?? null, ifNoneMatch: $args['if-none-match'] ?? null,
                    requestId: $args['request-id'], cancellation: $cancel);
            }
            $observation['elapsed_ns'] = hrtime(true) - $started;
        } catch (Yamora\BinaryOperationException $caught) {
            $observation['elapsed_ns'] = hrtime(true) - $started; $error = $caught;
        }
    } finally {
        if ($handle !== null) { demand(fclose($handle)); }
        if ($args['cancel-mode'] === 'external') {
            demand(pcntl_signal(SIGUSR1, $oldHandler)); pcntl_async_signals($oldAsync);
        }
        $client->close();
    }
    $meta = $response?->metadata ?? $feedResult?->metadata ?? $error?->metadata;
    if ($error?->response !== null) { $response = $error->response; }
    if ($response !== null) { writeOwned($root, 'body.bin', $response->body); $delivered = true; }
    if ($meta !== null) {
        $observation['api'] = ['status' => $meta['status'], 'body_file' => $delivered ? 'body.bin' : null,
            'etag' => $meta['etag'] ?? null, 'revision' => $meta['revision'],
            'representation_length' => $meta['representationLength'], 'request_id' => $meta['requestId'] ?? null, 'receipt' => null];
    } elseif ($delivered) { $observation['api']['body_file'] = 'body.bin'; }
    if ($error !== null) {
        $observation['outcome'] = $observation['error_kind'] = kind($error->reason);
        if ($error->status !== null) { $observation['api']['status'] = $error->status; }
        if ($error instanceof Yamora\BinaryOperationUncertainException) {
            $observation['outcome'] = 'uncertain'; $original = $error->envelope;
            writeOwned($root, 'envelope.bin', $original->source);
            $observation['envelope'] = ['method' => $original->method, 'target' => $original->target,
                'content_type' => $original->contentType, 'if_match' => $original->ifMatch,
                'if_none_match' => $original->ifNoneMatch, 'request_id' => $original->requestId, 'source_file' => 'envelope.bin'];
        }
    }
    return $observation;
}

// Never render exception messages, PHP warnings, arguments or stack traces.
set_error_handler(static function (): never { throw new RuntimeException('adapter infrastructure'); });
try {
    $json = json_encode(observe($argv), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    demand(strlen($json) + 1 <= 16384);
    demand(fwrite(STDOUT, $json . "\n") === strlen($json) + 1);
} catch (Throwable) {
    fwrite(STDERR, "PHP conformance adapter failed\n");
    exit(2);
}
