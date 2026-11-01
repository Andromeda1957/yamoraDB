package io.yamora;

import java.util.Map;

/** Validated complete terminal response. Authored source is copied on access. */
public final class BinaryResponse {
    private final BinaryMessageCodec.Response metadata;
    private final byte[] body;
    private final Map<String, Object> receipt;
    BinaryResponse(BinaryMessageCodec.Response metadata, byte[] ownedBody, Map<String, Object> receipt) {
        this.metadata = metadata; this.body = ownedBody; this.receipt = receipt;
    }
    public BinaryMessageCodec.Response metadata() { return metadata; }
    public int status() { return metadata.status(); }
    public byte[] body() { return body.clone(); }
    /** Validated PUT, PATCH or transaction receipt; empty for reads and DELETE. */
    public Map<String, Object> receipt() { return receipt; }
    @Override public String toString() { return "BinaryResponse[status=" + status() + ",redacted]"; }
}
