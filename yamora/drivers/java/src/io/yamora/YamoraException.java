package io.yamora;

import java.io.IOException;

/** Safe diagnostics: never includes response bodies, credentials, or authored documents. */
public final class YamoraException extends IOException {
    private static final long serialVersionUID = 1L;
    public enum Kind { HTTP, TRANSPORT, PROTOCOL, SCHEMA_POLICY_REPLICATION_UNSUPPORTED }
    private final Kind kind;
    private final int status;
    private final boolean outcomeUncertain;
    private final String requestId;

    YamoraException(Kind kind, int status, boolean outcomeUncertain, String detail, Throwable cause) {
        this(kind, status, outcomeUncertain, detail, cause, null);
    }
    private YamoraException(Kind kind, int status, boolean outcomeUncertain, String detail, Throwable cause, String requestId) {
        super("yamora: " + detail, cause);
        this.kind = kind;
        this.status = status;
        this.outcomeUncertain = outcomeUncertain;
        this.requestId = requestId;
    }
    public Kind kind() { return kind; }
    /** Remote refusal status, 409 for policy-source preflight, or zero for other local failures. */
    public int status() { return status; }
    /** Reconcile before resubmitting. Even a remote 5xx can follow publication. */
    public boolean outcomeUncertain() { return outcomeUncertain; }
    /** Persist this ID and the original arguments to reconcile an ambiguous cluster mutation. */
    public String requestId() { return requestId; }

    YamoraException uncertain(String id) {
        return new YamoraException(kind, status, true,
                "replica-set write outcome uncertain; recover the same request ID and bytes", this, id);
    }
}
