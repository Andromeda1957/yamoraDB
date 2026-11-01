package io.yamora;

import java.util.concurrent.atomic.AtomicBoolean;

/** One-way cancellation signal. No callback registrations or caller-owned socket access. */
public final class BinaryCancellation {
    private final AtomicBoolean cancelled = new AtomicBoolean();
    public void cancel() { cancelled.set(true); }
    public boolean isCancelled() { return cancelled.get(); }
}
