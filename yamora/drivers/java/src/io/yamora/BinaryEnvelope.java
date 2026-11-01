package io.yamora;

import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;

/** Admitted immutable logical request. Credentials are deliberately excluded.
 * Accessors return copies of authored bytes; toString always redacts the operation. */
public final class BinaryEnvelope {
    public enum Method {
        GET(1), HEAD(2), PUT(3), DELETE(4);
        final int wire;
        Method(int wire) { this.wire = wire; }
        public boolean mutation() { return this == PUT || this == DELETE; }
    }
    private final Method method;
    private final String collection, document, target, ifMatch, ifNoneMatch, requestId;
    private final byte[] source;

    // Only BinaryClient creates these, after local slot admission and before I/O.
    BinaryEnvelope(Method method, String collection, String document, byte[] source,
            String ifMatch, String ifNoneMatch, String requestId) {
        this.method = Objects.requireNonNull(method);
        name(collection); name(document);
        condition(ifMatch); condition(ifNoneMatch);
        Objects.requireNonNull(source);
        if (source.length > BinaryClient.MAX_SOURCE || method != Method.PUT && source.length != 0) throw invalid();
        this.collection = collection;
        this.document = document;
        this.target = "/v1/collections/" + collection + "/documents/" + document;
        this.ifMatch = ifMatch;
        this.ifNoneMatch = ifNoneMatch;
        this.requestId = requestId == null ? UUID.randomUUID().toString().replace("-", "") : requestId;
        if (!this.requestId.matches("[0-9a-f]{32}") || this.requestId.equals("0".repeat(32))) throw invalid();
        this.source = source.clone();
    }
    static IllegalArgumentException invalid() { return new IllegalArgumentException("yamora binary: invalid configuration/request"); }
    static void name(String value) { if (value == null || !value.matches("[a-z0-9-]{1,128}")) throw invalid(); }
    static void ascii(String value, int min, int max) {
        if (value == null || value.length() < min || value.length() > max) throw invalid();
        for (int i = 0; i < value.length(); i++) if (value.charAt(i) < 32 || value.charAt(i) > 126) throw invalid();
    }
    static void condition(String value) { if (value != null) ascii(value, 0, 31); }
    static void bearer(String value) {
        if (value == null) return;
        ascii(value, 1, 512);
        if (value.indexOf(' ') >= 0) throw invalid();
    }
    public Method method() { return method; }
    public String collection() { return collection; }
    public String document() { return document; }
    public String target() { return target; }
    public String ifMatch() { return ifMatch; }
    public String ifNoneMatch() { return ifNoneMatch; }
    public String requestId() { return requestId; }
    public byte[] source() { return source.clone(); }
    public int sourceLength() { return source.length; }
    byte[] ownedSource() { return source; }
    byte[] idBytes() { return HexFormat.of().parseHex(requestId); }
    @Override public String toString() { return "BinaryEnvelope[redacted]"; }
}
