package io.yamora;

/** Exposes only validated metadata and the last completely accepted page cursor. */
public class BinaryOperationException extends BinaryException {
    private static final long serialVersionUID = 1L;
    @SuppressWarnings("serial") private final BinaryOperation envelope;
    @SuppressWarnings("serial") private final BinaryResponse response;
    private final String lastAfter;
    BinaryOperationException(BinaryException failure, BinaryOperation envelope, BinaryResponse response, String lastAfter) {
        super(failure.kind(), failure.status()); this.envelope = envelope; this.response = response; this.lastAfter = lastAfter;
    }
    /** Non-null only when a dispatched mutation lacks its verified terminal receipt. */
    public BinaryOperation envelope() { return envelope; }
    public boolean uncertain() { return envelope != null; }
    public BinaryResponse response() { return response; }
    public String lastAfter() { return lastAfter; }
}
