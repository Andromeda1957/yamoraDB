<?php
declare(strict_types=1);
namespace Yamora;

/** @internal Bounded duplicate-property guard, including escaped equivalent names.
 * PHP's native decoder remains the syntax/UTF-8/number decoder. The guard visits
 * every object before json_decode can discard a duplicate identity or receipt.
 */
final class StrictJson
{
    private int $offset = 0;
    private int $nodes = 100000;
    private function __construct(private readonly string $text, private readonly OperationControl $control) {}
    public static function decode(string $text, OperationControl $control): \stdClass
    {
        if (strlen($text) > Client::MAX_RESPONSE_BYTES) { throw new ProtocolException('yamora: JSON limit'); }
        $parser = new self($text, $control);
        try {
            $parser->value(0);
            $parser->space();
            if ($parser->offset !== strlen($text)) { throw new \JsonException(); }
            $value = json_decode($text, false, 65, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
            if (!$value instanceof \stdClass || !self::finite($value)) { throw new \JsonException(); }
        } catch (\JsonException) {
            throw new ProtocolException('yamora: invalid or duplicate JSON properties');
        }
        $control->check();
        return $value;
    }
    private static function finite(mixed $v): bool
    {
        if (is_float($v)) { return is_finite($v); }
        if (is_array($v) || $v instanceof \stdClass) {
            foreach ($v as $child) { if (!self::finite($child)) { return false; } }
        }
        return true;
    }
    private function space(): void
    {
        $this->offset += strspn($this->text, " \t\r\n", $this->offset);
    }
    private function string(): string
    {
        $start = $this->offset++;
        $length = strlen($this->text);
        while ($this->offset < $length) {
            if (($this->offset & 4095) === 0) { $this->control->check(); }
            $c = $this->text[$this->offset++];
            if ($c === '"') {
                return json_decode(substr($this->text, $start, $this->offset - $start), false, 2, JSON_THROW_ON_ERROR);
            }
            if ($c === "\\") { ++$this->offset; }
        }
        throw new \JsonException();
    }
    private function value(int $depth): void
    {
        $this->control->check();
        if ($depth > 64 || --$this->nodes < 0) { throw new \JsonException(); }
        $this->space();
        $c = $this->text[$this->offset] ?? '';
        if ($c === '"') { $this->string(); return; }
        if ($c === '{' || $c === '[') {
            ++$this->offset;
            $end = $c === '{' ? '}' : ']';
            $this->space();
            if (($this->text[$this->offset] ?? '') === $end) { ++$this->offset; return; }
            $seen = [];
            while (true) {
                $this->space();
                if ($c === '{') {
                    if (($this->text[$this->offset] ?? '') !== '"') { throw new \JsonException(); }
                    $key = $this->string();
                    // Prefix prevents PHP's integer-key coercion changing identity.
                    if (isset($seen['k' . $key])) { throw new \JsonException(); }
                    $seen['k' . $key] = true;
                    $this->space();
                    if (($this->text[$this->offset++] ?? '') !== ':') { throw new \JsonException(); }
                }
                $this->value($depth + 1);
                $this->space();
                $separator = $this->text[$this->offset++] ?? '';
                if ($separator === $end) { return; }
                if ($separator !== ',') { throw new \JsonException(); }
            }
        }
        $start = $this->offset;
        $this->offset += strcspn($this->text, " \t\r\n,]}", $this->offset);
        if ($start === $this->offset) { throw new \JsonException(); }
        // Syntax is checked by the bounded native decoder after the guard.
    }
}
