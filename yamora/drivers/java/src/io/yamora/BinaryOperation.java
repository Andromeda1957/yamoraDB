package io.yamora;

import java.util.Objects;
import java.util.UUID;

/** Immutable, credential-free schema-2 request. Raw specification bytes are never re-encoded. */
public final class BinaryOperation {
    private final String method, target, contentType, ifMatch, ifNoneMatch, requestId;
    private final byte[] source;
    BinaryOperation(String method, String target, String contentType, byte[] source,
            String ifMatch, String ifNoneMatch, String requestId) {
        Objects.requireNonNull(source);
        BinaryEnvelope.ascii(target, 1, 511); BinaryEnvelope.ascii(contentType, 0, 95);
        BinaryEnvelope.condition(ifMatch); BinaryEnvelope.condition(ifNoneMatch);
        boolean document = target.matches("/v1/collections/[a-z0-9-]{1,128}/documents/[a-z0-9-]{1,128}");
        boolean query = target.matches("/v1/(query|aggregate|search)/[a-z0-9-]{1,128}");
        boolean changes = target.equals("/v1/changes") || target.startsWith("/v1/changes?") || target.startsWith("/v1/changes/stream?");
        if (!(method.equals("GET") && changes || method.equals("POST") && (query || target.equals("/v1/transactions"))
                || method.equals("PATCH") && document) || source.length > BinaryClient.MAX_SOURCE) throw BinaryEnvelope.invalid();
        String media = contentType.split(";", 2)[0];
        if (method.equals("GET") ? source.length != 0 || !contentType.isEmpty()
                : !(media.equalsIgnoreCase("application/json") || media.equalsIgnoreCase("application/yaml") || media.equalsIgnoreCase("text/yaml"))) throw BinaryEnvelope.invalid();
        this.requestId = requestId == null ? UUID.randomUUID().toString().replace("-", "") : requestId;
        if (!this.requestId.matches("[0-9a-f]{32}") || this.requestId.equals("0".repeat(32))) throw BinaryEnvelope.invalid();
        this.method = method; this.target = target; this.contentType = contentType;
        this.ifMatch = ifMatch; this.ifNoneMatch = ifNoneMatch; this.source = source.clone();
    }
    public String method() { return method; }
    public String target() { return target; }
    public String contentType() { return contentType; }
    public String ifMatch() { return ifMatch; }
    public String ifNoneMatch() { return ifNoneMatch; }
    public String requestId() { return requestId; }
    public byte[] source() { return source.clone(); }
    byte[] ownedSource() { return source; }
    boolean mutation() { return method.equals("PATCH") || target.equals("/v1/transactions"); }
    int wire() { return method.equals("GET") ? 1 : method.equals("POST") ? 5 : 6; }
    @Override public String toString() { return "BinaryOperation[redacted]"; }
}
