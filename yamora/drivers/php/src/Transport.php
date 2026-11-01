<?php
declare(strict_types=1);

namespace Yamora;

require_once __DIR__ . '/CertificateIdentity.php';

class DriverException extends \RuntimeException {}
final class ProtocolException extends DriverException {}
final class SchemaPolicyReplicationException extends DriverException
{
    public readonly int $status;
    public function __construct()
    {
        $this->status = 409;
        parent::__construct('yamora: schema_policy_replication_unsupported');
    }
}
final class TransportException extends DriverException {}
final class DeadlineException extends DriverException {}

require_once __DIR__ . '/OperationControl.php';

/** Remote bodies and credentials are deliberately excluded from diagnostics. */
final class HttpException extends DriverException
{
    public function __construct(public readonly int $status)
    {
        parent::__construct('yamora: HTTP ' . $status);
    }
}

/** Only verified TLS 1.3 is configurable; no arbitrary stream context overrides. */
final class TlsOptions
{
    public function __construct(
        public readonly ?string $caFile = null,
        public readonly ?string $certificateFile = null,
        public readonly ?string $privateKeyFile = null,
    ) {
        if (!extension_loaded('openssl') || !defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT')) {
            throw new \InvalidArgumentException('yamora: TLS 1.3 support required');
        }
        if (($certificateFile === null) !== ($privateKeyFile === null)) {
            throw new \InvalidArgumentException('yamora: both client certificate and key required');
        }
        foreach ([$caFile, $certificateFile, $privateKeyFile] as $file) {
            if ($file !== null && (str_contains($file, "\0") || !is_file($file) || !is_readable($file))) {
                throw new \InvalidArgumentException('yamora: TLS file unavailable');
            }
        }
    }

    /** @internal */
    public function context(string $host): array
    {
        $options = [
            'verify_peer' => true, 'verify_peer_name' => true,
            'allow_self_signed' => false, 'peer_name' => $host,
            'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT,
            'disable_compression' => true, 'alpn_protocols' => 'http/1.1',
            'capture_peer_cert' => true,
        ];
        if ($this->caFile !== null) {
            $options['cafile'] = $this->caFile;
        }
        if ($this->certificateFile !== null) {
            $options['local_cert'] = $this->certificateFile;
            $options['local_pk'] = $this->privateKeyFile;
            // Install PHP's noninteractive password callback even for an empty password.
            // Otherwise OpenSSL can prompt on /dev/tty while loading an encrypted key.
            $options['passphrase'] = '';
        }
        return ['ssl' => $options];
    }
}

/** @internal One socket per call, no HTTP wrappers, proxies, redirects or retries. */
final class Transport
{
    public function __construct(
        private readonly string $host,
        private readonly int $port,
        #[\SensitiveParameter] private readonly string $readToken,
        #[\SensitiveParameter] private readonly string $writeToken,
        private readonly float $timeout,
        private readonly ?TlsOptions $tls,
        private readonly int $maxResponseBytes,
    ) {
        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            throw new \InvalidArgumentException('yamora: numeric private IPv4 required');
        }
        $octets = array_map('intval', explode('.', $host));
        if (!($octets[0] === 127 || $octets[0] === 10 ||
            ($octets[0] === 172 && $octets[1] >= 16 && $octets[1] <= 31) ||
            ($octets[0] === 192 && $octets[1] === 168))) {
            throw new \InvalidArgumentException('yamora: loopback or RFC1918 IPv4 required');
        }
        if ($port < 1 || $port > 65535 || !is_finite($timeout) || $timeout <= 0 || $timeout > 30 ||
            $maxResponseBytes < 1 || $maxResponseBytes > Client::MAX_RESPONSE_BYTES) {
            throw new \InvalidArgumentException('yamora: invalid port, timeout or response limit');
        }
        foreach ([$readToken, $writeToken] as $token) {
            if ($token !== '' && !preg_match('/\A[!-~]{32,512}\z/D', $token)) {
                throw new \InvalidArgumentException('yamora: invalid credential');
            }
        }
    }

    private static function remaining(float $deadline, ?OperationControl $control = null): float
    {
        $control?->check();
        $left = $deadline - hrtime(true) / 1e9;
        if ($left <= 0) {
            throw new DeadlineException('yamora: whole request deadline exceeded');
        }
        return $left;
    }

    private static function wait($socket, bool $write, float $deadline, ?OperationControl $control = null): void
    {
        do {
            $left = self::remaining($deadline, $control);
            if ($control !== null) { $left = min($left, 0.01); }
            $seconds = (int) $left;
            $microseconds = (int) (($left - $seconds) * 1e6);
            $read = $write ? [] : [$socket];
            $writers = $write ? [$socket] : [];
            $except = [$socket];
            $result = @stream_select($read, $writers, $except, $seconds, $microseconds);
            self::remaining($deadline, $control);
            if ($result === false || $except !== []) {
                throw new TransportException('yamora: socket I/O failed');
            }
        } while ($result === 0);
    }

    private static function read($socket, int $maximum, float $deadline, ?OperationControl $control = null): string
    {
        while (true) {
            self::remaining($deadline, $control);
            // Read before selecting: OpenSSL can already have decrypted bytes buffered.
            // A fatal TLS record error can return an empty string with feof()
            // set. Preserve that distinction without exposing OpenSSL details
            // or replacing the application's error handler beyond this read.
            $readWarning = false;
            set_error_handler(static function (int $severity, string $message) use (&$readWarning): bool {
                $readWarning = true;
                return true;
            }, E_WARNING);
            try {
                $bytes = fread($socket, $maximum);
            } finally {
                restore_error_handler();
            }
            if ($readWarning || $bytes === false) {
                throw new TransportException('yamora: response read failed');
            }
            if ($bytes !== '' || feof($socket)) {
                return $bytes;
            }
            self::wait($socket, false, $deadline, $control);
        }
    }

    public function request(string $method, string $path, string $body, string $media,
        array $headers, bool $write, int $maximum, array $statuses,
        ?OperationControl $control = null, ?\Closure $onDispatch = null): array
    {
        if (!in_array($method, ['GET', 'PUT', 'PATCH', 'DELETE', 'POST'], true) ||
            strlen($path) > 1024 || !preg_match('/\A\/[a-z0-9\/?&=.\-]+\z/D', $path) ||
            strlen($body) > Client::MAX_REQUEST_BYTES ||
            !in_array($media, ['', 'application/json', 'application/yaml'], true) || count($headers) > 3) {
            throw new \InvalidArgumentException('yamora: invalid bounded request');
        }
        foreach ($headers as $name => $value) {
            if (!in_array($name, ['If-Match', 'If-None-Match', 'X-Yamora-Request-Id'], true) ||
                !is_string($value) || !preg_match('/\A[\x20-\x7e]{1,512}\z/D', $value)) {
                throw new \InvalidArgumentException('yamora: invalid request precondition header');
            }
        }
        $deadline = min(hrtime(true) / 1e9 + $this->timeout, $control?->deadline ?? INF);
        $context = stream_context_create($this->tls?->context($this->host) ?? []);
        $socket = @stream_socket_client('tcp://' . $this->host . ':' . $this->port,
            $errorCode, $errorMessage, self::remaining($deadline, $control), STREAM_CLIENT_CONNECT | ($control === null ? 0 : STREAM_CLIENT_ASYNC_CONNECT), $context);
        if ($socket === false) {
            self::remaining($deadline, $control);
            throw new TransportException('yamora: connection failed');
        }
        try {
            stream_set_blocking($socket, false);
            if ($control !== null) { self::wait($socket, true, $deadline, $control); }
            self::remaining($deadline, $control);
            if ($this->tls !== null) {
                do {
                    self::remaining($deadline, $control);
                    $secure = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT);
                    if ($secure === false) {
                        throw new TransportException('yamora: verified TLS 1.3 handshake failed');
                    }
                    if ($secure === 0) {
                        self::wait($socket, false, $deadline, $control);
                    }
                } while ($secure !== true);
                $crypto = stream_get_meta_data($socket)['crypto'] ?? [];
                if (($crypto['protocol'] ?? '') !== 'TLSv1.3' ||
                    (isset($crypto['alpn_protocol']) && $crypto['alpn_protocol'] !== 'http/1.1')) {
                    throw new TransportException('yamora: unexpected TLS negotiation');
                }
                $leaf = stream_context_get_options($socket)['ssl']['peer_certificate'] ?? null;
                if (!$leaf instanceof \OpenSSLCertificate || !CertificateIdentity::hasIPv4San($leaf, $this->host)) {
                    throw new TransportException('yamora: exact IPv4 subjectAltName required');
                }
            }
            $head = $method . ' ' . $path . " HTTP/1.1\r\nHost: " . $this->host . ':' . $this->port .
                "\r\nConnection: close\r\nAccept: application/json, application/yaml\r\nAccept-Encoding: identity\r\n";
            $token = $write ? $this->writeToken : $this->readToken;
            if ($token !== '') {
                $head .= 'Authorization: Bearer ' . $token . "\r\n";
            }
            if ($media !== '') {
                $head .= 'Content-Type: ' . $media . "\r\n";
            }
            foreach ($headers as $name => $value) {
                $head .= $name . ': ' . $value . "\r\n";
            }
            if ($body !== '' || in_array($method, ['PUT', 'POST', 'PATCH'], true)) {
                $head .= 'Content-Length: ' . strlen($body) . "\r\n";
            }
            $head .= "\r\n";
            if (strlen($head) > 8192) {
                throw new \InvalidArgumentException('yamora: request headers exceed limit');
            }
            self::remaining($deadline, $control);
            $onDispatch?->__invoke();
            foreach ([$head, $body] as $part) {
                $offset = 0;
                while ($offset < strlen($part)) {
                    self::remaining($deadline, $control);
                    $sent = @fwrite($socket, substr($part, $offset, 65536));
                    if ($sent === false || feof($socket)) {
                        throw new TransportException('yamora: request write failed');
                    }
                    $offset += $sent;
                    if ($sent === 0) {
                        self::wait($socket, true, $deadline, $control);
                    }
                }
            }
            $buffer = '';
            while (($end = strpos($buffer, "\r\n\r\n")) === false) {
                if (strlen($buffer) >= 16384) {
                    throw new ProtocolException('yamora: response headers exceed limit');
                }
                $chunk = self::read($socket, min(4096, 16384 - strlen($buffer)), $deadline, $control);
                if ($chunk === '') {
                    if ($control !== null && $buffer === '') { throw new TransportException('yamora: response lost before headers'); }
                    throw new ProtocolException('yamora: truncated response headers');
                }
                $buffer .= $chunk;
            }
            [$status, $response] = self::parseHeaders(substr($buffer, 0, $end));
            // Standalone rejection behavior is preserved. Cluster errors also validate
            // bounded framing before a rejection can be considered definitive.
            if ($control === null && !in_array($status, $statuses, true)) {
                throw new HttpException($status);
            }
            $maximum = min(in_array($status, $statuses, true) ? $maximum : 65536, $this->maxResponseBytes);
            if (isset($response['transfer-encoding']) || isset($response['content-encoding']) ||
                isset($response['upgrade']) || !isset($response['content-length'])) {
                throw new ProtocolException('yamora: unsupported response framing or encoding');
            }
            $declared = $response['content-length'];
            if (!preg_match('/\A(?:0|[1-9][0-9]{0,9})\z/D', $declared) || (int) $declared > $maximum) {
                throw new ProtocolException('yamora: response length exceeds limit or is invalid');
            }
            $length = (int) $declared;
            $payload = substr($buffer, $end + 4);
            if (strlen($payload) > $length) {
                throw new ProtocolException('yamora: bytes beyond declared response');
            }
            while (strlen($payload) < $length) {
                $chunk = self::read($socket, min(65536, $length - strlen($payload)), $deadline, $control);
                if ($chunk === '') {
                    throw new ProtocolException('yamora: truncated response body');
                }
                $payload .= $chunk;
            }
            // One response per connection: validate its close boundary regardless of
            // TCP/TLS packet splitting, without refreshing the request deadline.
            if (self::read($socket, 1, $deadline, $control) !== '') {
                throw new ProtocolException('yamora: bytes beyond declared response');
            }
            self::remaining($deadline, $control);
            if (!in_array($status, $statuses, true)) {
                throw new HttpException($status);
            }
            return [$payload, $response, $status];
        } finally {
            fclose($socket);
        }
    }

    private static function parseHeaders(string $head): array
    {
        $lines = explode("\r\n", $head);
        $statusLine = array_shift($lines);
        if (!preg_match('/\AHTTP\/1\.[01] ([1-5][0-9]{2})(?: [\x20-\x7e]*)?\z/D', $statusLine, $match) || count($lines) > 64) {
            throw new ProtocolException('yamora: invalid response status or header count');
        }
        $headers = [];
        foreach ($lines as $line) {
            if (!preg_match('/\A([!#$%&\x27*+.^_`|~0-9A-Za-z-]+):[\t ]*([\t\x20-\x7e]*)\z/D', $line, $field)) {
                throw new ProtocolException('yamora: malformed response header');
            }
            $name = strtolower($field[1]);
            if ($name === 'cache-control' && ($headers[$name] ?? null) === 'no-store' && trim($field[2], " \t") === 'no-store') { continue; }
            if (isset($headers[$name])) {
                throw new ProtocolException('yamora: duplicate response header');
            }
            $headers[$name] = trim($field[2], " \t");
        }
        return [(int) $match[1], $headers];
    }
}
