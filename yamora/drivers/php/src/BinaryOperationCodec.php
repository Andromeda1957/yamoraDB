<?php
declare(strict_types=1);
namespace Yamora;
require_once __DIR__ . '/BinaryOperationEnvelope.php';
require_once __DIR__ . '/BinaryRawJson.php';

/** @internal Strict schema-2 correlation. No YAML parsing or numeric conversion. */
final class BinaryOperationCodec
{
    private static function integer(string $bytes, int $width, int $maximum): int
    {
        if (strlen($bytes) !== $width) { BinaryCodec::fail(); }
        if ($width === 8) {
            $n = unpack('Nhigh/Nlow', $bytes);
            if ($n['high'] !== 0 || $n['low'] > $maximum) { BinaryCodec::fail(); }
            return $n['low'];
        }
        $n = unpack($width === 1 ? 'Cn' : ($width === 2 ? 'nn' : 'Nn'), $bytes)['n'];
        if ($n > $maximum) { BinaryCodec::fail(); }
        return $n;
    }
    public static function request(BinaryOperationEnvelope $e, ?string $token, int $timeout): string
    {
        $fields = [1 => chr(['GET' => 1, 'POST' => 5, 'PATCH' => 6][$e->method]), 2 => $e->target,
            3 => $e->contentType, 4 => pack('NN', 0, strlen($e->source))];
        if ($token !== null) { $fields[5] = 'Bearer ' . $token; }
        if ($e->ifMatch !== null) { $fields[6] = $e->ifMatch; }
        if ($e->ifNoneMatch !== null) { $fields[7] = $e->ifNoneMatch; }
        if ($e->requestId !== null) { $fields[8] = hex2bin($e->requestId); }
        $fields[9] = pack('N', $timeout);
        $out = pack('nn', 2, count($fields));
        foreach ($fields as $id => $bytes) { $out .= pack('nn', $id, strlen($bytes)) . $bytes; }
        if (strlen($out) > 2048) { throw new \InvalidArgumentException('yamora: operation metadata limit'); }
        return $out;
    }
    public static function metadata(string $bytes, BinaryOperationEnvelope $e, bool $feed): array
    {
        $f = BinaryCodec::fields($bytes, 2);
        if (!isset($f[13])) { BinaryCodec::fail(); }
        $r = ['status' => self::integer($f[1], 2, 599), 'contentType' => $f[2],
            'bodyLength' => self::integer($f[3], 8, BinaryCodec::MAX_SOURCE),
            'representationLength' => self::integer($f[4], 8, BinaryCodec::MAX_SOURCE),
            'revision' => $f[5], 'streaming' => self::integer($f[13], 1, 1) === 1,
            'etag' => null, 'requestId' => null, 'collection' => null, 'document' => null];
        $status = $r['status']; $n = $r['bodyLength']; $rep = $r['representationLength'];
        if ($status < 200 || !preg_match('/\A[\x20-\x7e]{1,95}\z/D', $r['contentType']) ||
            !preg_match('/\A[0-9a-f]{16}\z/D', $r['revision']) || $n !== $rep) { BinaryCodec::fail(); }
        foreach ([6 => 'etag', 7 => 'collection', 8 => 'document'] as $id => $name) {
            if (!isset($f[$id])) { continue; }
            if (!preg_match($id === 6 ? '/\A"[0-9a-f]{16}"\z/D' : '/\A[a-z0-9-]{1,128}\z/D', $f[$id])) { BinaryCodec::fail(); }
            $r[$name] = $id === 6 ? substr($f[$id], 1, 16) : $f[$id];
        }
        foreach ([9 => 1, 10 => 1, 11 => 4] as $id => $width) {
            if (!isset($f[$id])) { continue; }
            $v = self::integer($f[$id], $width, $id === 9 ? 63 : ($id === 10 ? 1 : 0xffffffff));
            if (($id === 9 && (!$v || $status !== 405)) || ($id === 10 && ($v !== 1 || $status !== 401)) ||
                ($id === 11 && !in_array($status, [429, 503], true))) { BinaryCodec::fail(); }
        }
        if (isset($f[12])) {
            if (strlen($f[12]) !== 16 || $f[12] === str_repeat("\0", 16)) { BinaryCodec::fail(); }
            $r['requestId'] = bin2hex($f[12]);
        }
        if ($r['requestId'] !== $e->requestId || ($status === 401 && !isset($f[10])) || ($status === 405 && !isset($f[9]))) { BinaryCodec::fail(); }
        if ($e->method === 'PATCH') {
            $parts = explode('/', $e->target);
            if (($r['collection'] !== null && $r['collection'] !== $parts[3]) ||
                ($r['document'] !== null && $r['document'] !== $parts[5])) { BinaryCodec::fail(); }
        } elseif ($r['collection'] !== null || $r['document'] !== null || $r['etag'] !== null) { BinaryCodec::fail(); }
        $base = strtolower(explode(';', $r['contentType'], 2)[0]);
        if ($r['streaming']) {
            if (!$feed || $status !== 200 || $n !== 0 || $base !== 'application/x-ndjson' || $r['etag'] !== null) { BinaryCodec::fail(); }
        } elseif ($base !== 'application/json' || ($feed && $status < 400) ||
            ($status < 400 && $status !== 200) || (($e->isMutation() || $status >= 400) && ($n < 1 || $n > 4096))) { BinaryCodec::fail(); }
        return $r;
    }
    private static function exactKeys(\stdClass $value, array $keys): void
    {
        $actual = array_keys(get_object_vars($value)); sort($actual); sort($keys);
        if ($actual !== $keys) { BinaryCodec::fail(); }
    }
    public static function body(array $m, string $bytes, BinaryOperationEnvelope $e, OperationControl $control): void
    {
        $v = BinaryRawJson::object($bytes, $control);
        if ($m['status'] >= 400) {
            self::exactKeys($v, ['error']);
            if (!is_string($v->error) || !preg_match('/\A[a-z0-9_]{1,128}\z/D', $v->error)) { BinaryCodec::fail(); }
        } elseif ($e->method === 'PATCH') {
            self::exactKeys($v, ['status', 'collection', 'document', 'etag', 'revision']);
            $p = explode('/', $e->target);
            if ($v->status !== 'stored' || $v->collection !== $p[3] || $v->document !== $p[5] ||
                $v->revision !== $m['revision'] || $v->etag !== $m['etag'] || !is_string($v->etag) ||
                !preg_match('/\A[0-9a-f]{16}\z/D', $v->etag)) { BinaryCodec::fail(); }
        } elseif ($e->target === '/v1/transactions') {
            self::exactKeys($v, ['status', 'operations', 'revision']);
            if ($v->status !== 'committed' || $v->revision !== $m['revision'] || !$v->operations instanceof BinaryJsonNumber ||
                !preg_match('/\A(?:[1-9]|[1-9][0-9]|1[01][0-9]|12[0-8])\z/D', $v->operations->lexeme)) { BinaryCodec::fail(); }
        } elseif (str_starts_with($e->target, '/v1/changes')) {
            self::change($v, null);
            if ($v->revision !== $m['revision']) { BinaryCodec::fail(); }
        } elseif (!isset($v->revision) || $v->revision !== $m['revision']) { BinaryCodec::fail(); }
        $control->check();
    }
    public static function token(mixed $value): bool
    { return is_string($value) && preg_match('/\Av1\.[0-9a-f]{32}\.[0-9a-f]{16}\z/D', $value) === 1; }
    private static function change(\stdClass $v, ?string $last): array
    {
        if (($v->terminal ?? false) === true) {
            self::exactKeys($v, ['terminal', 'status', 'after', 'detail']);
            if (!$v->status instanceof BinaryJsonNumber || !preg_match('/\A[45][0-9]{2}\z/D', $v->status->lexeme) ||
                !self::token($v->after) || ($last !== null && $v->after !== $last) || !$v->detail instanceof \stdClass) { BinaryCodec::fail(); }
            return [$v->after, (int)$v->status->lexeme];
        }
        self::exactKeys($v, ['transactions', 'next_after', 'oldest_after', 'checkpoint', 'revision', 'has_more']);
        if (!is_array($v->transactions) || count($v->transactions) > 100 || !is_bool($v->has_more) ||
            !self::token($v->next_after) || !self::token($v->oldest_after) || !self::token($v->checkpoint) ||
            !is_string($v->revision) || !preg_match('/\A[0-9a-f]{16}\z/D', $v->revision)) { BinaryCodec::fail(); }
        $identity = substr($v->next_after, 0, 36);
        foreach ([$v->oldest_after, $v->checkpoint, $last] as $token) {
            if ($token !== null && substr($token, 0, 36) !== $identity) { BinaryCodec::fail(); }
        }
        if (strcmp(substr($v->oldest_after, 36), substr($v->next_after, 36)) > 0 ||
            strcmp(substr($v->next_after, 36), substr($v->checkpoint, 36)) > 0 ||
            ($last !== null && strcmp(substr($v->next_after, 36), substr($last, 36)) < 0)) { BinaryCodec::fail(); }
        $previous = $last;
        foreach ($v->transactions as $transaction) {
            if (!$transaction instanceof \stdClass) { BinaryCodec::fail(); }
            self::exactKeys($transaction, ['token', 'previous_revision', 'revision', 'resnapshot_required', 'operations']);
            if (!self::token($transaction->token) || substr($transaction->token, 0, 36) !== $identity ||
                ($previous !== null && strcmp(substr($transaction->token, 36), substr($previous, 36)) <= 0) ||
                !is_string($transaction->revision) || !preg_match('/\A[0-9a-f]{16}\z/D', $transaction->revision) ||
                !is_string($transaction->previous_revision) || !preg_match('/\A[0-9a-f]{16}\z/D', $transaction->previous_revision) ||
                !is_bool($transaction->resnapshot_required) || !is_array($transaction->operations) || count($transaction->operations) > 256 ||
                ($transaction->resnapshot_required && $transaction->operations)) { BinaryCodec::fail(); }
            foreach ($transaction->operations as $op) {
                if (!$op instanceof \stdClass) { BinaryCodec::fail(); }
                $keys = array_keys(get_object_vars($op)); sort($keys);
                if ($keys === ['collection', 'create_collection']) {
                    if (!is_string($op->collection) || !preg_match('/\A[a-z0-9-]{1,128}\z/D', $op->collection) || $op->create_collection !== true) { BinaryCodec::fail(); }
                    continue;
                }
                if ($keys !== ['collection', 'document', 'put'] && $keys !== ['collection', 'delete', 'document']) { BinaryCodec::fail(); }
                if (!is_string($op->collection) || !is_string($op->document) ||
                    !preg_match('/\A[a-z0-9-]{1,128}\z/D', $op->collection) || !preg_match('/\A[a-z0-9-]{1,128}\z/D', $op->document) ||
                    (property_exists($op, 'put') ? !is_string($op->put) : $op->delete !== true)) { BinaryCodec::fail(); }
            }
            $previous = $transaction->token;
        }
        if (($previous !== null && $previous !== $v->next_after) || ($v->has_more && !$v->transactions)) { BinaryCodec::fail(); }
        return [$v->next_after, null];
    }
    public static function page(string $bytes, ?string $last, OperationControl $control): BinaryChangePage
    {
        if (!str_ends_with($bytes, "\n") || str_contains(substr($bytes, 0, -1), "\n") || str_contains($bytes, "\r")) { BinaryCodec::fail(); }
        [$after, $status] = self::change(BinaryRawJson::object(substr($bytes, 0, -1), $control), $last);
        return new BinaryChangePage($bytes, $after, $status);
    }
}
