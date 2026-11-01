<?php
declare(strict_types=1);
namespace Yamora;

require_once __DIR__ . '/BinaryEnvelope.php';

/** Frozen, explicit trust. No SSL contexts, caller paths, callbacks or global defaults. */
final class BinaryConfig
{
    public readonly string $host;
    public readonly int $port;
    public readonly string $serverName;
    public readonly float $timeout;
    public readonly int $maxFrame;
    private readonly string $caPem;
    private readonly ?string $clientCertPem;
    private readonly ?string $clientKeyPem;
    private readonly string $privateDirectory;

    public function __construct(mixed $host, mixed $port, mixed $serverName,
        #[\SensitiveParameter] mixed $caPem, mixed $privateDirectory,
        #[\SensitiveParameter] mixed $clientCertPem = null, #[\SensitiveParameter] mixed $clientKeyPem = null,
        mixed $timeout = 10.0, mixed $maxFrame = 65536)
    {
        if (PHP_INT_SIZE !== 8 || PHP_OS_FAMILY !== 'Linux' || !function_exists('posix_geteuid') ||
            !extension_loaded('openssl') || !defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT')) {
            throw new \InvalidArgumentException('yamora: Linux 64-bit PHP with OpenSSL TLS 1.3 and POSIX required');
        }
        // Routing remains numeric/private. The separate identity never resolves
        // DNS: OpenSSL uses it only for hostname verification and TLS SNI.
        self::address($host);
        if (!CertificateIdentity::validDnsName($serverName)) { self::address($serverName); }
        if (!is_int($port) || $port < 1 || $port > 65535 ||
            (!is_int($timeout) && !is_float($timeout)) || !is_finite((float)$timeout) || $timeout <= 0 || $timeout > 30 ||
            !is_int($maxFrame) || $maxFrame < 4096 || $maxFrame > 65536) {
            throw new \InvalidArgumentException('yamora: invalid binary endpoint or limits');
        }
        self::directory($privateDirectory);
        self::certificates($caPem, true);
        if (($clientCertPem === null) !== ($clientKeyPem === null)) {
            throw new \InvalidArgumentException('yamora: complete client identity required');
        }
        if ($clientCertPem !== null) {
            $cert = self::certificates($clientCertPem, false);
            if (!is_string($clientKeyPem) || $clientKeyPem === '' || strlen($clientKeyPem) > 1048576 ||
                str_contains($clientKeyPem, 'ENCRYPTED') || !self::privateKeyPem($clientKeyPem)) {
                throw new \InvalidArgumentException('yamora: bounded unencrypted client key required');
            }
            $key = BinaryTls::quiet(static fn() => openssl_pkey_get_private($clientKeyPem, ''));
            if ($key === false || !BinaryTls::quiet(static fn() => openssl_x509_check_private_key($cert, $key))) {
                throw new \InvalidArgumentException('yamora: invalid owned client identity');
            }
        }
        $this->host = $host; $this->port = $port; $this->serverName = $serverName;
        $this->caPem = $caPem; $this->privateDirectory = $privateDirectory;
        $this->clientCertPem = $clientCertPem; $this->clientKeyPem = $clientKeyPem;
        $this->timeout = (float)$timeout; $this->maxFrame = $maxFrame;
    }

    /** Validate inline bytes before OpenSSL, whose string input also accepts file://. */
    private static function privateKeyPem(#[\SensitiveParameter] string $pem): bool
    {
        if (preg_match('~\A[ \t\r\n]*-----BEGIN (PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY|DSA PRIVATE KEY)-----\r?\n([A-Za-z0-9+/=\r\n]+)\r?\n-----END \1-----[ \t\r\n]*\z~D', $pem, $parts) !== 1) {
            return false;
        }
        $encoded = str_replace(["\r", "\n"], '', $parts[2]);
        $der = base64_decode($encoded, true);
        return $der !== false && $der !== '' && base64_encode($der) === $encoded;
    }

    private static function address(mixed $host): void
    {
        if (!is_string($host) || filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false || inet_ntop(inet_pton($host)) !== $host) {
            throw new \InvalidArgumentException('yamora: canonical private IPv4 identity required');
        }
        $parts = array_map('intval', explode('.', $host));
        if (!($parts[0] === 127 || $parts[0] === 10 || ($parts[0] === 172 && $parts[1] >= 16 && $parts[1] <= 31) ||
            ($parts[0] === 192 && $parts[1] === 168))) { throw new \InvalidArgumentException('yamora: private IPv4 required'); }
    }

    /** @internal The credential parent is explicit, canonical, owned, and not shared writable. */
    public static function directory(mixed $root): void
    {
        if (!is_string($root) || str_contains($root, "\0") || !str_starts_with($root, '/') ||
            realpath($root) !== $root || !is_dir($root)) { throw new \InvalidArgumentException('yamora: private credential directory required'); }
        clearstatcache(true, $root);
        $stat = BinaryTls::quiet(static fn() => stat($root));
        if ($stat === false || $stat['uid'] !== posix_geteuid() || ($stat['mode'] & 0022) !== 0) {
            throw new \InvalidArgumentException('yamora: owned credential directory required');
        }
    }

    private static function certificates(#[\SensitiveParameter] mixed $pem, bool $ca): \OpenSSLCertificate
    {
        if (!is_string($pem) || $pem === '' || strlen($pem) > 1048576) {
            throw new \InvalidArgumentException('yamora: bounded explicit PEM trust required');
        }
        $count = preg_match_all('~-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----~', $pem, $matches);
        $tail = preg_replace('~-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----~', '', $pem);
        if (!$count || $count > 128 || trim($tail) !== '') { throw new \InvalidArgumentException('yamora: certificate PEM only'); }
        $first = null;
        foreach ($matches[0] as $block) {
            $cert = BinaryTls::quiet(static fn() => openssl_x509_read($block));
            $details = $cert === false ? false : BinaryTls::quiet(static fn() => openssl_x509_parse($cert));
            if ($details === false || ($ca && !str_contains($details['extensions']['basicConstraints'] ?? '', 'CA:TRUE'))) {
                throw new \InvalidArgumentException('yamora: invalid owned certificate material');
            }
            $first ??= $cert;
        }
        return $first;
    }

    /** @internal Every exchange owns and deletes its material before releasing admission. */
    public function material(OperationControl $control): BinaryTls
    {
        return new BinaryTls($this->privateDirectory, $this->caPem, $this->clientCertPem, $this->clientKeyPem, $control);
    }
    public function __debugInfo(): array { return ['host' => $this->host, 'port' => $this->port, 'serverName' => $this->serverName]; }
    public function __serialize(): array { throw new \LogicException('yamora: TLS configuration cannot be serialized'); }
}

/** @internal Private transient files bridge PHP's path-only TLS loader. */
final class BinaryTls
{
    private ?string $directory = null;
    private array $files = [];

    /** Never delegate warnings (including private paths) to application handlers. */
    public static function quiet(\Closure $call): mixed
    {
        set_error_handler(static fn(): bool => true);
        try { return $call(); } finally { restore_error_handler(); }
    }

    public function __construct(string $root, #[\SensitiveParameter] string $ca,
        #[\SensitiveParameter] ?string $cert, #[\SensitiveParameter] ?string $key, OperationControl $control)
    {
        BinaryConfig::directory($root);
        $control->check();
        $dir = $root . '/yamora-tls-' . bin2hex(random_bytes(16));
        if (!self::quiet(static fn() => mkdir($dir, 0700))) { throw new TransportException('yamora: private TLS storage unavailable'); }
        $this->directory = $dir;
        try {
            foreach (['ca' => $ca, 'cert' => $cert, 'key' => $key] as $name => $value) {
                if ($value === null) { continue; }
                $control->check();
                $path = $dir . '/' . $name . '.pem';
                $handle = self::quiet(static fn() => fopen($path, 'xb'));
                if ($handle === false) { throw new TransportException('yamora: private TLS material unavailable'); }
                $this->files[$name] = $path;
                try {
                    if (!self::quiet(static fn() => chmod($path, 0600))) { throw new TransportException('yamora: private TLS permissions failed'); }
                    for ($offset = 0, $n = strlen($value); $offset < $n;) {
                        $control->check();
                        $part = substr($value, $offset, 65536);
                        $wrote = self::quiet(static fn() => fwrite($handle, $part));
                        if ($wrote === false || $wrote === 0) { throw new TransportException('yamora: private TLS write failed'); }
                        $offset += $wrote;
                    }
                } finally { fclose($handle); }
            }
        } catch (\Throwable $e) { $this->close(); throw $e; }
    }

    public function context(string $identity): mixed
    {
        $ssl = ['verify_peer' => true, 'verify_peer_name' => true, 'allow_self_signed' => false,
            'peer_name' => $identity, 'SNI_enabled' => true, 'capture_peer_cert' => true, 'disable_compression' => true,
            'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT, 'alpn_protocols' => BinaryCodec::ALPN,
            'cafile' => $this->files['ca'], 'capath' => $this->directory, 'security_level' => 2];
        if (isset($this->files['cert'])) {
            $ssl['local_cert'] = $this->files['cert']; $ssl['local_pk'] = $this->files['key']; $ssl['passphrase'] = '';
        }
        return stream_context_create(['ssl' => $ssl]);
    }

    public function close(): void
    {
        $failed = false;
        foreach ($this->files as $name => $path) {
            if (self::quiet(static fn() => unlink($path))) { unset($this->files[$name]); } else { $failed = true; }
        }
        if ($this->directory !== null && $this->files === []) {
            $dir = $this->directory;
            if (self::quiet(static fn() => rmdir($dir))) { $this->directory = null; } else { $failed = true; }
        }
        if ($failed) { throw new TransportException('yamora: private TLS cleanup failed'); }
    }
    public function __destruct() { try { $this->close(); } catch (\Throwable) {} }
    public function __debugInfo(): array { return []; }
    public function __serialize(): array { throw new \LogicException('yamora: TLS material cannot be serialized'); }
}
