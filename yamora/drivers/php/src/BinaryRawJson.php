<?php
declare(strict_types=1);
namespace Yamora;

/** @internal A JSON number's original spelling, never a PHP float. */
final class BinaryJsonNumber
{
    public function __construct(public readonly string $lexeme) {}
}

/** @internal Bounded, duplicate-aware JSON used only to validate raw operation pages. */
final class BinaryRawJson
{
    private int $at = 0;
    private int $nodes = 0;
    private function __construct(private readonly string $bytes, private readonly OperationControl $control) {}
    public static function object(string $bytes, OperationControl $control): \stdClass
    {
        if (strlen($bytes) > BinaryCodec::MAX_SOURCE) { BinaryCodec::fail(); }
        BinaryCodec::utf8($bytes, $control);
        $p = new self($bytes, $control);
        $value = $p->value(0);
        $p->space();
        if (!$value instanceof \stdClass || $p->at !== strlen($bytes)) { BinaryCodec::fail(); }
        return $value;
    }
    private function space(): void { $this->at += strspn($this->bytes, " \t\r\n", $this->at); }
    private function text(): string
    {
        $start = $this->at++;
        while ($this->at < strlen($this->bytes)) {
            if (($this->at & 4095) === 0) { $this->control->check(); }
            $c = $this->bytes[$this->at++];
            if ($c === '"') {
                try { $text = json_decode(substr($this->bytes, $start, $this->at - $start), false, 2, JSON_THROW_ON_ERROR); }
                catch (\JsonException) { BinaryCodec::fail(); }
                if (!is_string($text)) { BinaryCodec::fail(); }
                return $text;
            }
            if ($c === '\\') { ++$this->at; }
            elseif (ord($c) < 32) { BinaryCodec::fail(); }
        }
        BinaryCodec::fail();
    }
    private function value(int $depth): mixed
    {
        $this->control->check();
        if ($depth > 80 || ++$this->nodes > 65536) { BinaryCodec::fail(); }
        $this->space();
        $c = $this->bytes[$this->at] ?? '';
        if ($c === '"') { return $this->text(); }
        if ($c === '{' || $c === '[') {
            ++$this->at; $this->space();
            $end = $c === '{' ? '}' : ']';
            $result = $c === '{' ? new \stdClass() : [];
            if (($this->bytes[$this->at] ?? '') === $end) { ++$this->at; return $result; }
            while (true) {
                $this->space();
                if ($c === '{') {
                    if (($this->bytes[$this->at] ?? '') !== '"') { BinaryCodec::fail(); }
                    $key = $this->text(); $this->space();
                    if (str_contains($key, "\0")) { BinaryCodec::fail(); }
                    if (property_exists($result, $key) || ($this->bytes[$this->at++] ?? '') !== ':') { BinaryCodec::fail(); }
                    $result->{$key} = $this->value($depth + 1);
                } else { $result[] = $this->value($depth + 1); }
                $this->space(); $separator = $this->bytes[$this->at++] ?? '';
                if ($separator === $end) { return $result; }
                if ($separator !== ',') { BinaryCodec::fail(); }
            }
        }
        if ($c === '') { BinaryCodec::fail(); }
        foreach (['true' => true, 'false' => false, 'null' => null] as $literal => $value) {
            if (substr_compare($this->bytes, $literal, $this->at, strlen($literal)) === 0) {
                $this->at += strlen($literal); return $value;
            }
        }
        if (!preg_match('/\G-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/', $this->bytes, $match, 0, $this->at)) { BinaryCodec::fail(); }
        $this->at += strlen($match[0]);
        return new BinaryJsonNumber($match[0]);
    }
}
