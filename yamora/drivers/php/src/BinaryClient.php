<?php
declare(strict_types=1);
namespace Yamora;

require_once __DIR__ . '/BinaryCodec.php';
require_once __DIR__ . '/BinaryTls.php';

/** Additive TLS binary CRUD. Synchronous owners never share a socket or replay. */
final class BinaryClient
{
    private bool $busy = false;
    private bool $closed = false;
    public function __construct(private readonly BinaryConfig $config) {}

    public function get(mixed $collection, mixed $document, #[\SensitiveParameter] mixed $token = null,
        mixed $ifMatch = null, mixed $ifNoneMatch = null, mixed $requestId = null,
        mixed $timeout = null, mixed $cancellation = null): BinaryResponse
    {
        return $this->request('GET', $collection, $document, token: $token, ifMatch: $ifMatch,
            ifNoneMatch: $ifNoneMatch, requestId: $requestId, timeout: $timeout, cancellation: $cancellation);
    }
    public function head(mixed $collection, mixed $document, #[\SensitiveParameter] mixed $token = null,
        mixed $ifMatch = null, mixed $ifNoneMatch = null, mixed $requestId = null,
        mixed $timeout = null, mixed $cancellation = null): BinaryResponse
    {
        return $this->request('HEAD', $collection, $document, token: $token, ifMatch: $ifMatch,
            ifNoneMatch: $ifNoneMatch, requestId: $requestId, timeout: $timeout, cancellation: $cancellation);
    }
    public function put(mixed $collection, mixed $document, #[\SensitiveParameter] mixed $source,
        #[\SensitiveParameter] mixed $token = null, mixed $ifMatch = null, mixed $ifNoneMatch = null,
        mixed $requestId = null, mixed $timeout = null, mixed $cancellation = null): BinaryResponse
    {
        return $this->request('PUT', $collection, $document, $source, $token, $ifMatch, $ifNoneMatch,
            $requestId, $timeout, $cancellation);
    }
    public function delete(mixed $collection, mixed $document, #[\SensitiveParameter] mixed $token = null,
        mixed $ifMatch = null, mixed $ifNoneMatch = null, mixed $requestId = null,
        mixed $timeout = null, mixed $cancellation = null): BinaryResponse
    {
        return $this->request('DELETE', $collection, $document, token: $token, ifMatch: $ifMatch,
            ifNoneMatch: $ifNoneMatch, requestId: $requestId, timeout: $timeout, cancellation: $cancellation);
    }
    public function request(mixed $method, mixed $collection, mixed $document,
        #[\SensitiveParameter] mixed $source = '', #[\SensitiveParameter] mixed $token = null,
        mixed $ifMatch = null, mixed $ifNoneMatch = null, mixed $requestId = null,
        mixed $timeout = null, mixed $cancellation = null): BinaryResponse
    {
        return $this->run(null, false, $method, $collection, $document, $source, $token,
            $ifMatch, $ifNoneMatch, $requestId, $timeout, $cancellation);
    }

    /** Explicit application repetition only. Standalone does not deduplicate. */
    public function execute(BinaryEnvelope $envelope, #[\SensitiveParameter] mixed $token = null,
        mixed $timeout = null, mixed $cancellation = null): BinaryResponse
    {
        return $this->run($envelope, false, null, null, null, '', $token, null, null, null, $timeout, $cancellation);
    }
    /** Preserve prior uncertainty even if this explicit recovery never dispatches. */
    public function recover(BinaryUncertainException $uncertain, #[\SensitiveParameter] mixed $token = null,
        mixed $timeout = null, mixed $cancellation = null): BinaryResponse
    {
        return $this->run($uncertain->envelope, true, null, null, null, '', $token, null, null, null, $timeout, $cancellation);
    }

    private function run(?BinaryEnvelope $envelope, bool $previouslyUncertain, mixed $method,
        mixed $collection, mixed $document, #[\SensitiveParameter] mixed $source,
        #[\SensitiveParameter] mixed $token, mixed $ifMatch, mixed $ifNoneMatch, mixed $requestId,
        mixed $timeout, mixed $cancellation): BinaryResponse
    {
        $started = hrtime(true) / 1e9;
        $admitted = false; $dispatched = false;
        try {
            // No fibers/threads/callback scheduler supported. Reject reentrancy before
            // freezing input; no waiter retains a second source or can deadlock its owner.
            if (\Fiber::getCurrent() !== null || $this->busy || $this->closed) {
                throw new \LogicException('yamora: binary client requires an open nonreentrant synchronous owner');
            }
            $duration = $timeout ?? $this->config->timeout;
            if ((!is_int($duration) && !is_float($duration)) || !is_finite((float)$duration) || $duration <= 0 || $duration > 30 ||
                ($cancellation !== null && !$cancellation instanceof CancellationToken)) {
                throw new \InvalidArgumentException('yamora: invalid binary call control');
            }
            $control = new OperationControl($started + $duration, $cancellation);
            $control->check();
            $this->busy = true; $admitted = true;
            $envelope ??= new BinaryEnvelope($method, $collection, $document, $source, $ifMatch, $ifNoneMatch, $requestId);
            if ($token !== null && (!is_string($token) || !preg_match('/\A[!-~]{1,512}\z/D', $token))) {
                throw new \InvalidArgumentException('yamora: invalid per-call bearer');
            }
            BinaryCodec::utf8($envelope->source, $control);
            $material = $this->config->material($control);
            $socket = null;
            try {
                $channel = new BinaryChannel($this->config, $material, $control);
                $socket = $channel;
                $channel->hello();
                $control->check();
                $ms = max(1, min(30000, (int)(($control->deadline - hrtime(true) / 1e9) * 1000)));
                $metadata = BinaryCodec::request($envelope, $token, $ms);
                $control->check();
                $dispatched = true; // First REQUEST may have been partially sent.
                $channel->send(2, 1, $metadata);
                for ($offset = 0, $length = strlen($envelope->source); $offset < $length; $offset += $channel->maxFrame) {
                    $channel->send(4, 1, substr($envelope->source, $offset, $channel->maxFrame));
                }
                $channel->send(5, 1, '');
                $response = $channel->response($envelope);
                BinaryCodec::body($response->metadata, $response->body, $envelope, $control);
                $control->check();
                $status = $response->metadata['status'];
                if ($status >= 400) { throw new BinaryStatusException($status); }
            } finally {
                $socket?->close();
                $material->close();
            }
            $control->check(); // Includes decode, hash, TLS file disposal and socket close.
            return $response;
        } catch (\Throwable $error) {
            $mutation = $envelope !== null && in_array($envelope->method, ['PUT', 'DELETE'], true);
            $certainRejection = $error instanceof BinaryStatusException && $error->status < 500 && $error->status !== 408;
            if ($mutation && ($previouslyUncertain || ($dispatched && !$certainRejection))) {
                throw new BinaryUncertainException($envelope, $error instanceof DriverException ? $error::class : 'local',
                    $error instanceof BinaryStatusException ? $error->status : null);
            }
            if ($error instanceof DriverException || $error instanceof \InvalidArgumentException || $error instanceof \LogicException) { throw $error; }
            throw new TransportException('yamora: binary call failed');
        } finally { if ($admitted) { $this->busy = false; } }
    }

    public function close(): void
    {
        if ($this->busy) { throw new \LogicException('yamora: cancel the synchronous owner before closing'); }
        $this->closed = true;
    }
    public function __debugInfo(): array { return ['busy' => $this->busy, 'closed' => $this->closed]; }
    public function __serialize(): array { throw new \LogicException('yamora: binary client cannot be serialized'); }
}

/** @internal One operation's socket; all waits share the admission deadline. */
final class BinaryChannel
{
    private mixed $socket = null;
    public int $maxFrame;

    public function __construct(BinaryConfig $config, BinaryTls $material, private readonly OperationControl $control)
    {
        $this->maxFrame = $config->maxFrame;
        $control->check();
        $context = $material->context($config->serverName);
        $this->socket = BinaryTls::quiet(static fn() => stream_socket_client('tcp://' . $config->host . ':' . $config->port,
            $code, $message, max(0.001, $control->deadline - hrtime(true) / 1e9), STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT, $context));
        if ($this->socket === false) { $this->socket = null; throw new TransportException('yamora: binary connect failed'); }
        try {
            stream_set_blocking($this->socket, false);
            $this->wait(true);
            do {
                $control->check();
                $secure = BinaryTls::quiet(fn() => stream_socket_enable_crypto($this->socket, true, STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT));
                if ($secure === false) { throw new TransportException('yamora: verified binary TLS handshake failed'); }
                if ($secure === 0) { $this->wait(false); }
            } while ($secure !== true);
            $control->check();
            $crypto = stream_get_meta_data($this->socket)['crypto'] ?? [];
            $leaf = stream_context_get_options($this->socket)['ssl']['peer_certificate'] ?? null;
            if (($crypto['protocol'] ?? null) !== 'TLSv1.3' || ($crypto['alpn_protocol'] ?? null) !== BinaryCodec::ALPN ||
                !$leaf instanceof \OpenSSLCertificate ||
                !(CertificateIdentity::hasIPv4San($leaf, $config->serverName) || CertificateIdentity::hasDnsSan($leaf, $config->serverName))) {
                throw new TransportException('yamora: binary TLS identity or ALPN rejected');
            }
            $control->check();
        } catch (\Throwable $error) { $this->close(); throw $error; }
    }

    private function wait(bool $write): void
    {
        do {
            $this->control->check();
            $left = max(1, (int)(min(0.01, $this->control->deadline - hrtime(true) / 1e9) * 1e6));
            $read = $write ? [] : [$this->socket]; $writers = $write ? [$this->socket] : []; $except = [$this->socket];
            $interrupted = false;
            set_error_handler(static function (int $level, string $message) use (&$interrupted): bool {
                $interrupted = str_contains($message, 'Interrupted system call');
                return true;
            });
            try { $result = stream_select($read, $writers, $except, 0, $left); } finally { restore_error_handler(); }
            $this->control->check();
            if ($result === false && $interrupted) { $result = 0; continue; }
            if ($result === false || $except !== []) { throw new TransportException('yamora: binary socket wait failed'); }
        } while ($result === 0);
    }

    public function send(int $kind, int $stream, #[\SensitiveParameter] string $payload): void
    {
        foreach ([pack('a4CCnNN', 'YMBF', 1, $kind, 0, $stream, strlen($payload)), $payload] as $part) {
            for ($offset = 0, $length = strlen($part); $offset < $length;) {
                $this->control->check();
                $tail = substr($part, $offset);
                $n = BinaryTls::quiet(fn() => fwrite($this->socket, $tail));
                if ($n === false) { throw new TransportException('yamora: binary send failed'); }
                if ($n === 0) { $this->wait(true); } else { $offset += $n; }
            }
        }
        $this->control->check();
    }

    private function exact(int $size): string
    {
        $out = '';
        while (strlen($out) < $size) {
            $this->control->check();
            $warned = false;
            set_error_handler(static function () use (&$warned): bool { $warned = true; return true; });
            try { $part = fread($this->socket, $size - strlen($out)); } finally { restore_error_handler(); }
            if ($warned || $part === false || ($part === '' && feof($this->socket))) { throw new TransportException('yamora: binary response incomplete'); }
            if ($part === '') { $this->wait(false); } else { $out .= $part; }
        }
        return $out;
    }
    public function receive(int $remaining = 0): array
    {
        [$kind, $size] = BinaryCodec::header($this->exact(16), $this->maxFrame);
        if ($kind === 4 && $size > $remaining) { BinaryCodec::fail(); }
        return [$kind, $this->exact($size)];
    }

    public function hello(int $protocol = 1): void
    {
        $this->send(1, 0, pack('nnNN', 1, $protocol, $this->maxFrame, 1));
        [$kind, $payload] = $this->receive();
        if ($kind !== 1) { BinaryCodec::fail(); }
        $h = unpack('nlow/nhigh/Nframe/Nstreams', $payload);
        if (!in_array($protocol, [1, 2], true) || $h['low'] < 1 || $h['low'] > $protocol || $h['high'] < $protocol || $h['high'] < $h['low'] || $h['frame'] < 4096 || $h['frame'] > 1048576 || $h['streams'] < 1 || $h['streams'] > 128) { BinaryCodec::fail(); }
        $this->maxFrame = min($this->maxFrame, $h['frame']);
    }

    public function response(BinaryEnvelope $e): BinaryResponse
    {
        $metadata = null; $body = ''; $controls = 0; $goaway = false;
        while (true) {
            [$kind, $payload] = $this->receive($metadata === null ? 0 : $metadata['bodyLength'] - strlen($body));
            if ($kind === 8) {
                if (++$controls > 16) { BinaryCodec::fail(); }
                $this->send(9, 0, $payload); continue;
            }
            if ($kind === 10) {
                if ($goaway || ++$controls > 16) { BinaryCodec::fail(); }
                $goaway = true; continue; // Drain current response; GOAWAY grants no replay promise.
            }
            if ($kind === 3) {
                if ($metadata !== null) { BinaryCodec::fail(); }
                $metadata = BinaryCodec::metadata($payload, $e);
            } elseif ($kind === 4) {
                if ($metadata === null || strlen($payload) > $metadata['bodyLength'] - strlen($body)) { BinaryCodec::fail(); }
                $body .= $payload;
            } elseif ($kind === 5) {
                if ($metadata === null || strlen($body) !== $metadata['bodyLength']) { BinaryCodec::fail(); }
                $this->control->check();
                return new BinaryResponse($metadata, $body);
            } elseif ($kind === 7) {
                if ($payload === str_repeat("\0", 4)) { BinaryCodec::fail(); }
                throw new TransportException('yamora: binary session ERROR; outcome unavailable');
            } else { BinaryCodec::fail(); }
        }
    }
    public function close(): void
    {
        if (is_resource($this->socket)) { BinaryTls::quiet(fn() => fclose($this->socket)); }
        $this->socket = null;
    }
    public function __destruct() { $this->close(); }
}
