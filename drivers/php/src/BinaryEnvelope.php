<?php
declare(strict_types=1);
namespace Yamora;

require_once __DIR__ . '/Client.php';

/** Immutable operation, deliberately independent of credentials and connection settings. */
final class BinaryEnvelope
{
    public readonly string $method;
    public readonly string $collection;
    public readonly string $document;
    public readonly string $source;
    public readonly ?string $ifMatch;
    public readonly ?string $ifNoneMatch;
    public readonly ?string $requestId;

    public function __construct(mixed $method, mixed $collection, mixed $document,
        #[\SensitiveParameter] mixed $source = '', mixed $ifMatch = null,
        mixed $ifNoneMatch = null, mixed $requestId = null)
    {
        if (!is_string($method) || !in_array($method, ['GET', 'HEAD', 'PUT', 'DELETE'], true)) {
            throw new \InvalidArgumentException('yamora: binary document method required');
        }
        foreach ([$collection, $document] as $name) {
            if (!is_string($name) || !preg_match('/\A[a-z0-9-]{1,128}\z/D', $name)) {
                throw new \InvalidArgumentException('yamora: invalid binary document name');
            }
        }
        if (!is_string($source) || strlen($source) > 16777216 || ($method !== 'PUT' && $source !== '')) {
            throw new \InvalidArgumentException('yamora: bounded binary source bytes required');
        }
        foreach ([$ifMatch, $ifNoneMatch] as $condition) {
            if ($condition !== null && (!is_string($condition) || !preg_match('/\A[\x20-\x7e]{0,31}\z/D', $condition))) {
                throw new \InvalidArgumentException('yamora: invalid binary condition');
            }
        }
        if ($requestId === null && in_array($method, ['PUT', 'DELETE'], true)) {
            do { $requestId = bin2hex(random_bytes(16)); } while ($requestId === str_repeat('0', 32));
        }
        if ($requestId !== null && (!is_string($requestId) ||
            !preg_match('/\A[0-9a-f]{32}\z/D', $requestId) || $requestId === str_repeat('0', 32))) {
            throw new \InvalidArgumentException('yamora: nonzero binary request identity required');
        }
        $this->method = $method;
        $this->collection = $collection;
        $this->document = $document;
        // PHP strings have value semantics, including when the caller used a reference.
        $this->source = $source;
        $this->ifMatch = $ifMatch;
        $this->ifNoneMatch = $ifNoneMatch;
        $this->requestId = $requestId;
    }

    public function __debugInfo(): array { return ['method' => $this->method, 'requestId' => $this->requestId]; }
}

/** Owned bytes and scalar metadata; no borrowed frame or mutable decoded receipt. */
final class BinaryResponse
{
    public function __construct(public readonly array $metadata, public readonly string $body) {}
    public function __debugInfo(): array { return ['status' => $this->metadata['status']]; }
}

final class BinaryUncertainException extends DriverException
{
    public readonly ?string $requestId;
    public function __construct(public readonly BinaryEnvelope $envelope,
        public readonly string $reason, public readonly ?int $status = null)
    {
        $this->requestId = $envelope->requestId;
        parent::__construct('yamora: binary mutation outcome uncertain; reconcile before explicit recovery');
    }
    public function __debugInfo(): array { return ['requestId' => $this->requestId, 'reason' => $this->reason, 'status' => $this->status]; }
}

final class BinaryStatusException extends DriverException
{
    public function __construct(public readonly int $status)
    {
        parent::__construct('yamora: binary document status ' . $status);
    }
}
