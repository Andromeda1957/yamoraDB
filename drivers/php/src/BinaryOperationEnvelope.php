<?php
declare(strict_types=1);
namespace Yamora;
require_once __DIR__ . '/BinaryClient.php';

/** Immutable schema-2 operation. Credentials and connection settings are excluded. */
final class BinaryOperationEnvelope
{
    public readonly string $method;
    public readonly string $target;
    public readonly string $contentType;
    public readonly string $source;
    public readonly ?string $ifMatch;
    public readonly ?string $ifNoneMatch;
    public readonly ?string $requestId;
    public function __construct(mixed $method, mixed $target, #[\SensitiveParameter] mixed $source = '',
        mixed $contentType = '', mixed $ifMatch = null, mixed $ifNoneMatch = null, mixed $requestId = null)
    {
        if (!is_string($method) || !is_string($target) || strlen($target) > 1024 ||
            !preg_match('/\A[\x21-\x7e]+\z/D', $target) || !is_string($source) || strlen($source) > BinaryCodec::MAX_SOURCE ||
            !is_string($contentType) || strlen($contentType) > 95 || !preg_match('/\A[\x20-\x7e]*\z/D', $contentType)) {
            throw new \InvalidArgumentException('yamora: bounded primitive operation bytes required');
        }
        $valid = match ($method) {
            'GET' => $source === '' && $contentType === '' &&
                (preg_match('~\A/v1/changes(?:\?[^#]*)?\z~D', $target) || str_starts_with($target, '/v1/changes/stream?')),
            'POST' => $target === '/v1/transactions' || preg_match('~\A/v1/(?:query|aggregate|search)/[a-z0-9-]{1,128}\z~D', $target),
            'PATCH' => preg_match('~\A/v1/collections/[a-z0-9-]{1,128}/documents/[a-z0-9-]{1,128}\z~D', $target),
            default => false,
        };
        if (!$valid || str_contains($target, '#') || ($method !== 'GET' &&
            !in_array(strtolower(explode(';', $contentType, 2)[0]), ['application/json', 'application/yaml', 'text/yaml'], true))) {
            throw new \InvalidArgumentException('yamora: unsupported binary operation');
        }
        foreach ([$ifMatch, $ifNoneMatch] as $condition) {
            if ($condition !== null && (!is_string($condition) || !preg_match('/\A[\x20-\x7e]{0,31}\z/D', $condition))) {
                throw new \InvalidArgumentException('yamora: invalid binary condition');
            }
        }
        if ($requestId === null && ($method === 'PATCH' || $target === '/v1/transactions')) {
            do { $requestId = bin2hex(random_bytes(16)); } while ($requestId === str_repeat('0', 32));
        }
        if ($requestId !== null && (!is_string($requestId) || !preg_match('/\A[0-9a-f]{32}\z/D', $requestId) || $requestId === str_repeat('0', 32))) {
            throw new \InvalidArgumentException('yamora: nonzero operation identity required');
        }
        $this->method = $method; $this->target = $target; $this->source = $source; $this->contentType = $contentType;
        $this->ifMatch = $ifMatch; $this->ifNoneMatch = $ifNoneMatch; $this->requestId = $requestId;
    }
    public function isMutation(): bool { return $this->method === 'PATCH' || $this->target === '/v1/transactions'; }
    public function __debugInfo(): array { return ['method' => $this->method, 'requestId' => $this->requestId]; }
}

/** One fully validated native page, including its original LF. */
final class BinaryChangePage
{
    public function __construct(public readonly string $bytes, public readonly string $after, public readonly ?int $terminalStatus) {}
    public function __debugInfo(): array { return ['bytes' => strlen($this->bytes), 'terminalStatus' => $this->terminalStatus]; }
}
final class BinaryFeedResult
{
    public function __construct(public readonly array $metadata, public readonly ?string $lastAfter, public readonly ?int $terminalStatus) {}
}
class BinaryOperationException extends DriverException
{
    public function __construct(public readonly string $reason, public readonly ?int $status,
        public readonly ?array $metadata, public readonly ?string $lastAfter,
        public readonly ?BinaryResponse $response = null)
    { parent::__construct('yamora: binary operation failed'); }
}
final class BinaryOperationUncertainException extends BinaryOperationException
{
    public function __construct(public readonly BinaryOperationEnvelope $envelope, string $reason, ?int $status,
        ?array $metadata, ?BinaryResponse $response = null)
    { parent::__construct($reason, $status, $metadata, null, $response); }
    public function __debugInfo(): array { return ['reason' => $this->reason, 'status' => $this->status]; }
}
