package io.yamora;

import java.io.IOException;

/** Safe binary diagnostics; no credentials, source, or peer error text. */
public class BinaryException extends IOException {
    private static final long serialVersionUID = 1L;
    public enum Kind { TRANSPORT, PROTOCOL, STATUS, TIMEOUT, CANCELLED }
    private final Kind kind;
    private final int status;
    BinaryException(Kind kind, int status) {
        super("yamora binary: " + kind.name().toLowerCase(java.util.Locale.ROOT)
                + (status == 0 ? "" : " status " + status));
        this.kind = kind;
        this.status = status;
    }
    public final Kind kind() { return kind; }
    public final int status() { return status; }
    static BinaryException protocol() { return new BinaryException(Kind.PROTOCOL, 0); }
}
