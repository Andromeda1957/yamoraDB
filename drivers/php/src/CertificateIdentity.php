<?php
declare(strict_types=1);

namespace Yamora;

/** @internal Check typed SAN bytes only after OpenSSL has verified the leaf's chain. */
final class CertificateIdentity
{
    public static function hasIPv4San(\OpenSSLCertificate $leaf, string $host): bool
    {
        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) { return false; }
        return self::hasSan($leaf, 0x87, inet_pton($host));
    }

    /** Exact ASCII DNS identity only; no wildcards, trailing dot, IDNA or numeric-IP aliases. */
    public static function validDnsName(mixed $name): bool
    {
        if (!is_string($name) || $name === '' || strlen($name) > 253 ||
            preg_match('/\A[0-9.]+\z/D', $name) === 1) { return false; }
        foreach (explode('.', $name) as $label) {
            if (preg_match('/\A[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\z/D', $label) !== 1) {
                return false;
            }
        }
        return true;
    }

    public static function hasDnsSan(\OpenSSLCertificate $leaf, string $name): bool
    {
        if (!self::validDnsName($name)) { return false; }
        return self::hasSan($leaf, 0x82, strtolower($name));
    }

    private static function hasSan(\OpenSSLCertificate $leaf, int $nameTag, string $identity): bool
    {
        if (!openssl_x509_export($leaf, $pem) || strlen($pem) > 128 * 1024) {
            return false;
        }
        $encoded = str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\r", "\n"], '', $pem);
        $der = base64_decode($encoded, true);
        if ($der === false || $der === '') { return false; }
        try {
            $offset = 0;
            [$tag, $start, $end] = self::element($der, $offset, strlen($der));
            if ($tag !== 0x30 || $offset !== strlen($der)) { return false; }
            $offset = $start;
            [$tag, $start, $end] = self::element($der, $offset, $end); // TBSCertificate
            if ($tag !== 0x30) { return false; }
            $offset = $start;
            [$tag] = self::element($der, $offset, $end);
            if ($tag === 0xa0) { [$tag] = self::element($der, $offset, $end); } // version
            if ($tag !== 0x02) { return false; } // serial
            // signature, issuer, validity, subject, subjectPublicKeyInfo
            for ($field = 0; $field < 5; ++$field) {
                [$tag] = self::element($der, $offset, $end);
                if ($tag !== 0x30) { return false; }
            }
            while ($offset < $end) {
                [$tag, $start, $limit] = self::element($der, $offset, $end);
                if ($tag === 0xa3 && $offset === $end) {
                    return self::extensionsMatch($der, $start, $limit, $nameTag, $identity);
                }
                if ($tag !== 0x81 && $tag !== 0x82) { return false; }
            }
        } catch (\UnexpectedValueException) {
            return false;
        }
        return false;
    }

    private static function extensionsMatch(string $der, int $offset, int $end, int $nameTag, string $identity): bool
    {
        [$tag, $start, $limit] = self::element($der, $offset, $end);
        if ($tag !== 0x30 || $offset !== $end) { return false; }
        $offset = $start;
        $found = false;
        $matched = false;
        while ($offset < $limit) {
            [$tag, $entry, $entryEnd] = self::element($der, $offset, $limit);
            if ($tag !== 0x30) { return false; }
            [$tag, $oid, $oidEnd] = self::element($der, $entry, $entryEnd);
            if ($tag !== 0x06) { return false; }
            $isSan = substr($der, $oid, $oidEnd - $oid) === "\x55\x1d\x11"; // 2.5.29.17
            [$tag, $value, $valueEnd] = self::element($der, $entry, $entryEnd);
            if ($tag === 0x01) { [$tag, $value, $valueEnd] = self::element($der, $entry, $entryEnd); }
            if ($tag !== 0x04 || $entry !== $entryEnd) { return false; }
            if (!$isSan) { continue; }
            if ($found) { return false; }
            $found = true;
            [$tag, $names, $namesEnd] = self::element($der, $value, $valueEnd);
            if ($tag !== 0x30 || $value !== $valueEnd) { return false; }
            while ($names < $namesEnd) {
                [$tag, $name, $nameEnd] = self::element($der, $names, $namesEnd);
                // iPAddress is the primitive context-specific tag 7, four octets for IPv4.
                // PHP's openssl_x509_parse display string cannot distinguish DNS text
                // containing ', IP Address:...' from an actual typed iPAddress name.
                // dNSName is primitive tag 2. Compare the whole SAN value, never
                // CN or a display string, so OpenSSL's CN/wildcard matches alone
                // cannot authorize bearer dispatch for an explicit DNS identity.
                if ($tag === $nameTag && $nameEnd - $name === strlen($identity)) {
                    $candidate = substr($der, $name, $nameEnd - $name);
                    if (($nameTag === 0x82 ? strtolower($candidate) : $candidate) === $identity) {
                        $matched = true;
                    }
                }
            }
        }
        return $found && $matched;
    }

    /** Bounded DER field reader; no recursion, indefinite lengths or unbounded integers. */
    private static function element(string $der, int &$offset, int $end): array
    {
        if ($offset + 2 > $end) { throw new \UnexpectedValueException(); }
        $tag = ord($der[$offset++]);
        $length = ord($der[$offset++]);
        if (($tag & 0x1f) === 0x1f) { throw new \UnexpectedValueException(); }
        if ($length >= 128) {
            $count = $length & 0x7f;
            if ($count < 1 || $count > 3 || $offset + $count > $end || $der[$offset] === "\0") {
                throw new \UnexpectedValueException();
            }
            $length = 0;
            for ($byte = 0; $byte < $count; ++$byte) { $length = ($length << 8) | ord($der[$offset++]); }
            if ($length < 128) { throw new \UnexpectedValueException(); }
        }
        if ($length > $end - $offset) { throw new \UnexpectedValueException(); }
        $start = $offset;
        $offset += $length;
        return [$tag, $start, $offset];
    }
}
