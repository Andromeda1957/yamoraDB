<?php
declare(strict_types=1);
namespace Yamora;

require_once __DIR__ . '/BinaryEnvelope.php';
require_once __DIR__ . '/StrictJson.php';

/** @internal Schema 1 only. Integers are decoded with bounds before allocation. */
final class BinaryCodec
{
    public const ALPN = 'yamora-binary/1';
    public const MAX_SOURCE = 16777216;

    public static function fail(): never { throw new ProtocolException('yamora: invalid binary document response'); }

    public static function header(string $header, int $maximum): array
    {
        if (strlen($header) !== 16) { self::fail(); }
        $h = unpack('a4magic/Cversion/Ckind/nflags/Nstream/Nsize', $header);
        $kind = $h['kind']; $stream = $h['stream']; $size = $h['size'];
        if ($h['magic'] !== 'YMBF' || $h['version'] !== 1 || $h['flags'] !== 0 || $size > $maximum) { self::fail(); }
        $fixed = [1 => 12, 5 => 0, 7 => 4, 8 => 8, 9 => 8, 10 => 0];
        if (!in_array($kind, [1, 3, 4, 5, 7, 8, 9, 10], true) ||
            $stream !== (in_array($kind, [1, 8, 9, 10], true) ? 0 : 1) ||
            (isset($fixed[$kind]) && $size !== $fixed[$kind]) ||
            ($kind === 3 && ($size < 1 || $size > 2048)) || ($kind === 4 && $size === 0)) { self::fail(); }
        return [$kind, $size];
    }

    public static function fields(string $payload, int $schema = 1): array
    {
        $length = strlen($payload);
        if ($length < 4 || $length > 2048) { self::fail(); }
        $prefix = unpack('nschema/ncount', $payload);
        $maximum = $schema === 2 ? 13 : 12;
        if (!in_array($schema, [1, 2], true) || $prefix['schema'] !== $schema || $prefix['count'] < 5 || $prefix['count'] > $maximum) { self::fail(); }
        $fields = []; $offset = 4; $last = 0;
        for ($i = 0; $i < $prefix['count']; ++$i) {
            if ($offset + 4 > $length) { self::fail(); }
            $tlv = unpack('nid/nsize', $payload, $offset); $offset += 4;
            if ($tlv['id'] <= $last || $tlv['id'] > $maximum || $tlv['size'] > $length - $offset) { self::fail(); }
            $last = $tlv['id']; $fields[$last] = substr($payload, $offset, $tlv['size']); $offset += $tlv['size'];
        }
        if ($offset !== $length) { self::fail(); }
        foreach ([1, 2, 3, 4, 5] as $id) { if (!isset($fields[$id])) { self::fail(); } }
        return $fields;
    }

    private static function integer(string $value, int $width): int
    {
        if (strlen($value) !== $width) { self::fail(); }
        // Only lengths use u64. Reject high bits before any signed arithmetic.
        if ($width === 8) {
            $v = unpack('Nhigh/Nlow', $value);
            if ($v['high'] !== 0 || $v['low'] > self::MAX_SOURCE) { self::fail(); }
            return $v['low'];
        }
        return unpack(match ($width) { 1 => 'Cvalue', 2 => 'nvalue', 4 => 'Nvalue' }, $value)['value'];
    }

    public static function metadata(string $payload, BinaryEnvelope $e): array
    {
        $f = self::fields($payload);
        $r = ['status' => self::integer($f[1], 2), 'contentType' => $f[2],
            'bodyLength' => self::integer($f[3], 8), 'representationLength' => self::integer($f[4], 8),
            'revision' => $f[5], 'etag' => null, 'collection' => null, 'document' => null, 'requestId' => null];
        $status = $r['status']; $n = $r['bodyLength']; $rep = $r['representationLength'];
        if ($status < 200 || $status > 599 || !preg_match('/\A[\x20-\x7e]{1,95}\z/D', $f[2]) ||
            !preg_match('/\A[0-9a-f]{16}\z/D', $f[5]) || ($n !== 0 && $n !== $rep) ||
            ($status === 204 && ($n !== 0 || $rep !== 0)) || ($status === 304 && $n !== 0)) { self::fail(); }
        foreach ([6 => 'etag', 7 => 'collection', 8 => 'document'] as $id => $name) {
            if (!isset($f[$id])) { continue; }
            if (!preg_match($id === 6 ? '/\A"[0-9a-f]{16}"\z/D' : '/\A[a-z0-9-]{1,128}\z/D', $f[$id])) { self::fail(); }
            $r[$name] = $id === 6 ? substr($f[$id], 1, 16) : $f[$id];
        }
        foreach ([9 => ['allow', 1], 10 => ['authenticate', 1], 11 => ['retryAfterSeconds', 4]] as $id => [$name, $width]) {
            if (!isset($f[$id])) { continue; }
            $v = self::integer($f[$id], $width);
            if (($id === 9 && ($v < 1 || $v > 15 || $status !== 405)) ||
                ($id === 10 && ($v !== 1 || $status !== 401)) ||
                ($id === 11 && !in_array($status, [429, 503], true))) { self::fail(); }
            $r[$name] = $v;
        }
        if (isset($f[12])) {
            if (strlen($f[12]) !== 16 || $f[12] === str_repeat("\0", 16)) { self::fail(); }
            $r['requestId'] = bin2hex($f[12]);
        }
        if ($r['requestId'] !== $e->requestId ||
            ($r['collection'] !== null && $r['collection'] !== $e->collection) ||
            ($r['document'] !== null && $r['document'] !== $e->document) ||
            ($e->method === 'HEAD' ? $n !== 0 : ($status !== 304 && $n !== $rep))) { self::fail(); }
        $base = strtolower(explode(';', $r['contentType'], 2)[0]);
        if ($status >= 400) {
            if ($base !== 'application/json' || $rep > 4096) { self::fail(); }
            return $r;
        }
        if (in_array($e->method, ['GET', 'HEAD'], true)) {
            if (!in_array($status, [200, 304], true) || ($status === 304 && !in_array($e->ifNoneMatch, ['*', '"' . $r['etag'] . '"'], true)) ||
                !in_array($base, ['application/yaml', 'text/yaml'], true) || $r['etag'] === null ||
                $r['collection'] !== $e->collection || $r['document'] !== $e->document) { self::fail(); }
        } elseif ($e->method === 'PUT') {
            if (!in_array($status, [200, 201], true) || $base !== 'application/json' || $n < 1 || $n > 4096 || $r['etag'] === null ||
                ($e->ifNoneMatch === '*' && $status !== 201) || ($e->ifMatch !== null && $status !== 200)) { self::fail(); }
        } elseif ($status !== 204 || $n !== 0 || $rep !== 0 || $base !== 'application/json' || $r['etag'] !== null) { self::fail(); }
        return $r;
    }

    public static function request(BinaryEnvelope $e, ?string $token, int $timeout): string
    {
        $f = [1 => chr(['GET' => 1, 'HEAD' => 2, 'PUT' => 3, 'DELETE' => 4][$e->method]),
            2 => '/v1/collections/' . $e->collection . '/documents/' . $e->document,
            3 => $e->method === 'PUT' ? 'application/yaml' : '', 4 => pack('NN', 0, strlen($e->source))];
        if ($token !== null) { $f[5] = 'Bearer ' . $token; }
        if ($e->ifMatch !== null) { $f[6] = $e->ifMatch; }
        if ($e->ifNoneMatch !== null) { $f[7] = $e->ifNoneMatch; }
        if ($e->requestId !== null) { $f[8] = hex2bin($e->requestId); }
        $f[9] = pack('N', $timeout);
        $out = pack('nn', 1, count($f));
        foreach ($f as $id => $value) { $out .= pack('nn', $id, strlen($value)) . $value; }
        return $out;
    }

    public static function utf8(string $source, OperationControl $control): void
    {
        // Keep at most three continuation bytes with the next chunk; native PCRE
        // sees bounded complete UTF-8 sequences and never normalizes source.
        for ($offset = 0, $length = strlen($source); $offset < $length;) {
            $control->check();
            $end = min($length, $offset + 65536);
            if ($end < $length) {
                $boundary = $end;
                while ($end > $offset && (ord($source[$end]) & 0xc0) === 0x80 && $boundary - $end < 4) { --$end; }
            }
            if ($end === $offset || preg_match('//u', substr($source, $offset, $end - $offset)) !== 1) { self::fail(); }
            $offset = $end;
        }
        $control->check();
    }

    public static function sourceHash(string $source, OperationControl $control): string
    {
        // Native offset basis 0x14650fb0739d0383, NOT standard FNV's basis.
        // (hi,lo) * (2^40 + 435), with every intermediate below 2^42.
        // Never multiply a 64-bit hash in PHP (overflow would become a float).
        $hi = 0x14650fb0; $lo = 0x739d0383;
        for ($i = 0, $length = strlen($source); $i < $length; ++$i) {
            if (($i & 4095) === 0) { $control->check(); }
            $lo ^= ord($source[$i]);
            $product = $lo * 435;
            $hi = ($hi * 435 + ($product >> 32) + (($lo & 0xffffff) << 8)) & 0xffffffff;
            $lo = $product & 0xffffffff;
        }
        $control->check();
        return sprintf('%08x%08x', $hi, $lo);
    }

    public static function body(array $r, string $body, BinaryEnvelope $e, OperationControl $control): void
    {
        if (strlen($body) !== $r['bodyLength']) { self::fail(); }
        if ($r['status'] >= 400) {
            // HEAD errors intentionally suppress their JSON representation.
            if ($e->method !== 'HEAD') { StrictJson::decode($body, $control); }
            return;
        }
        if ($e->method === 'GET' && $r['status'] === 200) {
            self::utf8($body, $control);
            if (self::sourceHash($body, $control) !== $r['etag']) { self::fail(); }
        }
        if ($e->method === 'PUT') {
            $receipt = get_object_vars(StrictJson::decode($body, $control));
            $expected = ['status' => 'stored', 'collection' => $e->collection, 'document' => $e->document,
                'etag' => $r['etag'], 'revision' => $r['revision']];
            if (count($receipt) !== count($expected)) { self::fail(); }
            foreach ($expected as $key => $value) { if (($receipt[$key] ?? null) !== $value) { self::fail(); } }
            if (self::sourceHash($e->source, $control) !== $r['etag']) { self::fail(); }
        }
        $control->check();
    }
}
