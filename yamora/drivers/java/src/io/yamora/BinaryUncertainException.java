package io.yamora;

/** A dispatched mutation lacks a verified terminal receipt. Never replay automatically.
 * IDs on standalone stores do not deduplicate; recovery/discovery is not implemented. */
public final class BinaryUncertainException extends BinaryException {
    private static final long serialVersionUID = 1L;
    @SuppressWarnings("serial") // Envelopes deliberately do not support Java object serialization.
    private final BinaryEnvelope envelope;
    BinaryUncertainException(BinaryEnvelope envelope, BinaryException failure) {
        super(failure.kind(), failure.status());
        this.envelope = envelope;
    }
    public BinaryEnvelope envelope() { return envelope; }
    public String requestId() { return envelope.requestId(); }
}
