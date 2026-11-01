package io.yamora;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

/** Strict schema-1 TLVs, independent from the C implementation. */
public final class BinaryMessageCodec {
    private BinaryMessageCodec() {}
    public record Response(int status, String contentType, int bodyLength, int representationLength,
            String revision, String etag, String collection, String document, int allow,
            boolean authenticate, Long retryAfterSeconds, String requestId, boolean streaming) {
        public Response(int status, String contentType, int bodyLength, int representationLength, String revision,
                String etag, String collection, String document, int allow, boolean authenticate, Long retryAfterSeconds, String requestId) {
            this(status, contentType, bodyLength, representationLength, revision, etag, collection, document, allow, authenticate, retryAfterSeconds, requestId, false);
        }
    }

    public static byte[] request(BinaryEnvelope envelope, String bearer, int timeoutMs) {
        BinaryEnvelope.bearer(bearer);
        if (timeoutMs < 1 || timeoutMs > 30000) throw BinaryEnvelope.invalid();
        ByteArrayOutputStream out = new ByteArrayOutputStream(2048);
        int count = 6 + (bearer == null ? 0 : 1) + (envelope.ifMatch() == null ? 0 : 1) + (envelope.ifNoneMatch() == null ? 0 : 1);
        out.writeBytes(ByteBuffer.allocate(4).putShort((short) 1).putShort((short) count).array());
        field(out, 1, new byte[]{(byte) envelope.method().wire});
        field(out, 2, ascii(envelope.target()));
        field(out, 3, ascii(envelope.method() == BinaryEnvelope.Method.PUT ? "application/yaml" : ""));
        field(out, 4, ByteBuffer.allocate(8).putLong(envelope.sourceLength()).array());
        if (bearer != null) field(out, 5, ascii("Bearer " + bearer));
        if (envelope.ifMatch() != null) field(out, 6, ascii(envelope.ifMatch()));
        if (envelope.ifNoneMatch() != null) field(out, 7, ascii(envelope.ifNoneMatch()));
        field(out, 8, envelope.idBytes());
        field(out, 9, ByteBuffer.allocate(4).putInt(timeoutMs).array());
        if (out.size() > 2048) throw BinaryEnvelope.invalid();
        return out.toByteArray();
    }
    private static byte[] ascii(String text) { return text.getBytes(StandardCharsets.US_ASCII); }
    private static void field(ByteArrayOutputStream out, int id, byte[] value) {
        out.writeBytes(ByteBuffer.allocate(4).putShort((short) id).putShort((short) value.length).array());
        out.writeBytes(value);
    }
    public static Response response(byte[] payload) throws BinaryException { return response(payload, 1); }
    static Response response(byte[] payload, int expectedSchema) throws BinaryException {
        if (payload.length < 4 || payload.length > 2048) throw BinaryException.protocol();
        ByteBuffer buffer = ByteBuffer.wrap(payload);
        int schema = Short.toUnsignedInt(buffer.getShort()), count = Short.toUnsignedInt(buffer.getShort());
        if (schema != expectedSchema || count < 5 || count > (schema == 2 ? 13 : 12)) throw BinaryException.protocol();
        byte[][] fields = new byte[14][]; int previous = 0;
        for (int i = 0; i < count; i++) {
            if (buffer.remaining() < 4) throw BinaryException.protocol();
            int id = Short.toUnsignedInt(buffer.getShort()), size = Short.toUnsignedInt(buffer.getShort());
            if (id <= previous || id > (schema == 2 ? 13 : 12) || size > buffer.remaining()) throw BinaryException.protocol();
            fields[id] = new byte[size]; buffer.get(fields[id]); previous = id;
        }
        if (buffer.hasRemaining()) throw BinaryException.protocol();
        for (int id = 1; id <= 5; id++) if (fields[id] == null) throw BinaryException.protocol();
        int status = (int) integer(fields[1], 2);
        String media = text(fields[2], 1, 95);
        long body = integer(fields[3], 8), representation = integer(fields[4], 8);
        String revision = text(fields[5], 16, 16);
        if (!revision.matches("[0-9a-f]{16}") || status < 200 || status > 599
                || body < 0 || body > BinaryClient.MAX_SOURCE || representation < 0 || representation > BinaryClient.MAX_SOURCE
                || body != 0 && body != representation || status == 204 && (body != 0 || representation != 0)
                || status == 304 && body != 0) throw BinaryException.protocol();
        String etag = fields[6] == null ? null : text(fields[6], 18, 18);
        if (etag != null && !etag.matches("\"[0-9a-f]{16}\"")) throw BinaryException.protocol();
        String collection = name(fields[7]), document = name(fields[8]);
        int allow = fields[9] == null ? 0 : (int) integer(fields[9], 1);
        if (fields[9] != null && (allow < 1 || allow > (schema == 2 ? 63 : 15))) throw BinaryException.protocol();
        boolean auth = fields[10] != null;
        if (auth && integer(fields[10], 1) != 1) throw BinaryException.protocol();
        Long retry = fields[11] == null ? null : integer(fields[11], 4);
        String id = null;
        if (fields[12] != null) {
            if (fields[12].length != 16) throw BinaryException.protocol();
            id = HexFormat.of().formatHex(fields[12]);
            if (id.equals("0".repeat(32))) throw BinaryException.protocol();
        }
        boolean streaming = false;
        if (schema == 2) {
            if (fields[13] == null) throw BinaryException.protocol();
            long mode = integer(fields[13], 1);
            if (mode > 1 || mode == 1 && (status != 200 || body != 0 || representation != 0)) throw BinaryException.protocol();
            streaming = mode == 1;
        }
        return new Response(status, media, (int) body, (int) representation, revision, etag, collection, document, allow, auth, retry, id, streaming);
    }
    static long integer(byte[] value, int width) throws BinaryException {
        if (value.length != width) throw BinaryException.protocol();
        long result = 0; for (byte b : value) result = result << 8 | b & 255L;
        return result;
    }
    private static String name(byte[] bytes) throws BinaryException {
        if (bytes == null) return null;
        String name = text(bytes, 1, 128);
        if (!name.matches("[a-z0-9-]{1,128}")) throw BinaryException.protocol();
        return name;
    }
    private static String text(byte[] value, int min, int max) throws BinaryException {
        if (value.length < min || value.length > max) throw BinaryException.protocol();
        for (byte b : value) if (b < 32 || b > 126) throw BinaryException.protocol();
        return new String(value, StandardCharsets.US_ASCII);
    }
}
