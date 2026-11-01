<?php
declare(strict_types=1);
namespace Yamora;
require_once __DIR__ . '/BinaryOperationCodec.php';

/** Additive raw schema-2 calls; one admitted synchronous owner and one connection per call. */
final class BinaryOperationClient
{
    private bool $busy = false;
    private bool $closed = false;
    public function __construct(private readonly BinaryConfig $config) {}
    public function operation(mixed $method, mixed $target, #[\SensitiveParameter] mixed $source = '', mixed $contentType = '',
        #[\SensitiveParameter] mixed $token = null, mixed $ifMatch = null, mixed $ifNoneMatch = null,
        mixed $requestId = null, mixed $timeout = null, mixed $cancellation = null): BinaryResponse
    {
        return $this->run($method, $target, $source, $contentType, $token, $ifMatch, $ifNoneMatch, $requestId, $timeout, $cancellation, null);
    }
    /** Callback returns true to continue or false to cancel after that complete page.
     * It runs before another page is read. Retaining pages is the caller's choice. */
    public function feed(mixed $target, callable $onPage, #[\SensitiveParameter] mixed $token = null,
        mixed $ifMatch = null, mixed $ifNoneMatch = null, mixed $requestId = null,
        mixed $timeout = null, mixed $cancellation = null): BinaryFeedResult
    {
        return $this->run('GET', $target, '', '', $token, $ifMatch, $ifNoneMatch, $requestId, $timeout, $cancellation, $onPage);
    }
    private function run(mixed $method, mixed $target, #[\SensitiveParameter] mixed $source, mixed $contentType,
        #[\SensitiveParameter] mixed $token, mixed $ifMatch, mixed $ifNoneMatch, mixed $requestId,
        mixed $timeout, mixed $cancellation, ?callable $onPage): BinaryResponse|BinaryFeedResult
    {
        $started = hrtime(true) / 1e9;
        $admitted = false; $dispatched = false; $e = null; $metadata = null; $last = null; $response = null;
        try {
            if (\Fiber::getCurrent() !== null || $this->busy || $this->closed) { throw new \LogicException('yamora: open nonreentrant synchronous owner required'); }
            $duration = $timeout ?? $this->config->timeout;
            if ((!is_int($duration) && !is_float($duration)) || !is_finite((float)$duration) || $duration <= 0 || $duration > 30 ||
                ($cancellation !== null && !$cancellation instanceof CancellationToken)) { throw new \InvalidArgumentException('yamora: invalid binary operation control'); }
            $control = new OperationControl($started + $duration, $cancellation); $control->check();
            $this->busy = true; $admitted = true;
            $e = new BinaryOperationEnvelope($method, $target, $source, $contentType, $ifMatch, $ifNoneMatch, $requestId);
            if (($onPage !== null) !== str_starts_with($e->target, '/v1/changes/stream?')) { throw new \InvalidArgumentException('yamora: streaming target requires feed API'); }
            if ($token !== null && (!is_string($token) || !preg_match('/\A[!-~]{1,512}\z/D', $token))) { throw new \InvalidArgumentException('yamora: invalid per-call bearer'); }
            BinaryCodec::utf8($e->source, $control);
            $material = $this->config->material($control); $channel = null;
            try {
                $channel = new BinaryChannel($this->config, $material, $control); $channel->hello(2);
                $control->check();
                $ms = max(1, min(30000, (int)(($control->deadline - hrtime(true) / 1e9) * 1000)));
                $request = BinaryOperationCodec::request($e, $token, $ms); $control->check();
                $dispatched = true;
                $channel->send(2, 1, $request);
                for ($at = 0; $at < strlen($e->source); $at += $channel->maxFrame) { $channel->send(4, 1, substr($e->source, $at, $channel->maxFrame)); }
                $channel->send(5, 1, '');
                $pending = ''; $total = 0; $terminal = null; $goaway = false; $controls = 0;
                $resume = null;
                if ($onPage !== null && preg_match('/(?:\?|&)after=([^&]+)/', $e->target, $m) && BinaryOperationCodec::token($m[1])) { $resume = $m[1]; }
                while (true) {
                    $control->check();
                    [$kind, $bytes] = $channel->receive($metadata === null ? 0 :
                        ($metadata['streaming'] ? BinaryCodec::MAX_SOURCE - $total : $metadata['bodyLength'] - strlen($pending)));
                    if ($kind === 8) {
                        if (++$controls > 16) { BinaryCodec::fail(); }
                        $channel->send(9, 0, $bytes); continue;
                    }
                    if ($kind === 10) {
                        if ($goaway || ++$controls > 16) { BinaryCodec::fail(); }
                        $goaway = true; continue;
                    }
                    if ($kind === 7) {
                        if ($bytes === str_repeat("\0", 4)) { BinaryCodec::fail(); }
                        throw new TransportException('yamora: binary operation interrupted');
                    }
                    if ($kind === 3) {
                        if ($metadata !== null) { BinaryCodec::fail(); }
                        $metadata = BinaryOperationCodec::metadata($bytes, $e, $onPage !== null); continue;
                    }
                    if ($metadata === null) { BinaryCodec::fail(); }
                    if ($kind === 4) {
                        if ($terminal !== null) { BinaryCodec::fail(); }
                        $total += strlen($bytes);
                        if ($total > BinaryCodec::MAX_SOURCE) { BinaryCodec::fail(); }
                        if (!$metadata['streaming']) { $pending .= $bytes; continue; }
                        // Append only through one LF. Multiple pages in one frame
                        // are validated/delivered individually, never accumulated.
                        for ($offset = 0; $offset < strlen($bytes);) {
                            if ($terminal !== null) { BinaryCodec::fail(); }
                            $lf = strpos($bytes, "\n", $offset);
                            $end = $lf === false ? strlen($bytes) : $lf + 1;
                            $pending .= substr($bytes, $offset, $end - $offset); $offset = $end;
                            if (strlen($pending) > BinaryCodec::MAX_SOURCE) { BinaryCodec::fail(); }
                            if ($lf === false) { break; }
                            if ($resume === null) { BinaryCodec::fail(); }
                            $page = BinaryOperationCodec::page($pending, $last ?? $resume, $control);
                            $control->check();
                            $accepted = $onPage($page);
                            if (!is_bool($accepted)) { throw new \LogicException('yamora: page callback must return bool'); }
                            $last = $page->after; $terminal = $page->terminalStatus;
                            unset($page); $pending = '';
                            if (!$accepted) { throw new CancelledException('yamora: feed callback cancelled'); }
                            $control->check();
                        }
                    } elseif ($kind === 5) {
                        if ($metadata['streaming']) {
                            if ($pending !== '' || $last === null) { BinaryCodec::fail(); }
                            $control->check();
                            $result = new BinaryFeedResult($metadata, $last, $terminal); break;
                        }
                        if (strlen($pending) !== $metadata['bodyLength']) { BinaryCodec::fail(); }
                        BinaryOperationCodec::body($metadata, $pending, $e, $control);
                        $response = new BinaryResponse($metadata, $pending);
                        if ($metadata['status'] >= 400) { throw new BinaryStatusException($metadata['status']); }
                        $result = $response; break;
                    } else { BinaryCodec::fail(); }
                }
            } finally { $channel?->close(); $material->close(); }
            $control->check();
            return $result;
        } catch (DriverException $error) {
            // A race after a typed receipt/rejection still belongs to the one
            // absolute budget. Keep the original dispatched mutation unchanged.
            if (isset($control)) {
                try { $control->check(); } catch (DriverException $race) { $error = $race; }
            }
            $status = $error instanceof BinaryStatusException ? $error->status : null;
            $certain = $status !== null && $status < 500 && $status !== 408;
            if ($e !== null && $e->isMutation() && $dispatched && !$certain) {
                throw new BinaryOperationUncertainException($e, $error::class, $status, $metadata, $response);
            }
            throw new BinaryOperationException($error::class, $status, $metadata, $last, $response);
        } finally { if ($admitted) { $this->busy = false; } }
    }
    public function close(): void
    {
        if ($this->busy) { throw new \LogicException('yamora: cancel synchronous owner before closing'); }
        $this->closed = true;
    }
    public function __debugInfo(): array { return ['busy' => $this->busy, 'closed' => $this->closed]; }
    public function __serialize(): array { throw new \LogicException('yamora: operation client cannot be serialized'); }
}
