<?php
declare(strict_types=1);
namespace Yamora;

final class CancelledException extends DriverException {}

/** One-way synchronous/cooperative cancellation; no background task or global handler. */
final class CancellationToken
{
    private bool $cancelled = false;
    public function cancel(): void { $this->cancelled = true; }
    public function isCancelled(): bool { return $this->cancelled; }
}

/** @internal Passed explicitly to each exchange; never stored in shared transport state. */
final class OperationControl
{
    public function __construct(public readonly float $deadline, private readonly ?CancellationToken $token = null) {}
    public function check(): void
    {
        if ($this->token?->isCancelled()) { throw new CancelledException('yamora: operation cancelled'); }
        if (hrtime(true) / 1e9 >= $this->deadline) { throw new DeadlineException('yamora: operation deadline exceeded'); }
    }
    public function budget(float $maximum, int $shares): self
    {
        $this->check();
        return new self(min($this->deadline, hrtime(true) / 1e9 + min($maximum, ($this->deadline - hrtime(true) / 1e9) / $shares)), $this->token);
    }
    public function backoff(float $delay): void
    {
        $end = min($this->deadline, hrtime(true) / 1e9 + $delay);
        do {
            $this->check();
            $left = $end - hrtime(true) / 1e9;
            if ($left <= 0) { return; }
            usleep(max(1, (int) (min(0.01, $left) * 1e6)));
        } while (true);
    }
}
