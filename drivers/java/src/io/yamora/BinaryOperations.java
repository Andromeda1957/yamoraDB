package io.yamora;

import static io.yamora.BinaryFrameCodec.*;
import static io.yamora.BinaryClient.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

/** Schema-2 application semantics on the existing bounded TLS/frame primitives. */
final class BinaryOperations {
    private BinaryOperations() {}
    static BinaryClient.FeedResult run(BinaryConfig config, Semaphore slots, String method, String target,
            String contentType, byte[] source, String bearer, String match, String none, String id,
            BinaryCancellation cancellation, BinaryClient.PageConsumer consumer) throws BinaryException {
        long deadline = System.nanoTime() + config.timeoutNanos;
        boolean acquired = false, dispatched = false;
        BinaryOperation operation = null; BinaryResponse observed = null;
        String after = after(target);
        BinaryClient.Guard guard = null;
        try {
            Objects.requireNonNull(cancellation);
            while (!acquired) { check(deadline, cancellation); acquired = slots.tryAcquire(Math.min(10_000_000L, remaining(deadline)), TimeUnit.NANOSECONDS); }
            check(deadline, cancellation); BinaryEnvelope.bearer(bearer);
            operation = new BinaryOperation(method, target, contentType, source, match, none, id);
            if ((consumer != null) != target.startsWith("/v1/changes/stream?")) throw BinaryEnvelope.invalid();
            check(deadline, cancellation);
            Socket raw = new Socket(java.net.Proxy.NO_PROXY);
            guard = new BinaryClient.Guard(raw, deadline, cancellation);
            raw.connect(new InetSocketAddress(config.endpoint(), config.port), milliseconds(deadline));
            raw.setTcpNoDelay(true); raw.setSoTimeout(milliseconds(deadline));
            try (SSLSocket tls = (SSLSocket) config.tls().getSocketFactory().createSocket(raw, config.serverName, config.port, true)) {
                SSLParameters parameters = tls.getSSLParameters(); parameters.setProtocols(new String[]{"TLSv1.3"});
                parameters.setEndpointIdentificationAlgorithm("HTTPS"); parameters.setApplicationProtocols(new String[]{"yamora-binary/1"});
                if (!config.serverName.matches("[0-9.]+")) parameters.setServerNames(List.of(new SNIHostName(config.serverName)));
                tls.setSSLParameters(parameters); check(deadline, cancellation); tls.startHandshake(); check(deadline, cancellation);
                if (!"TLSv1.3".equals(tls.getSession().getProtocol()) || !"yamora-binary/1".equals(tls.getApplicationProtocol())) throw BinaryException.protocol();
                var input = guarded(tls.getInputStream(), deadline, cancellation);
                var output = guarded(tls.getOutputStream(), deadline, cancellation);
                BinaryFrameCodec.write(output, HELLO, 0, ByteBuffer.allocate(12).putShort((short)1).putShort((short)2).putInt(config.maxFrame).putInt(1).array(), config.maxFrame);
                Frame hello = BinaryFrameCodec.read(input, config.maxFrame);
                if (hello.type() != HELLO) throw BinaryException.protocol();
                ByteBuffer peer = ByteBuffer.wrap(hello.payload());
                int min = Short.toUnsignedInt(peer.getShort()), max = Short.toUnsignedInt(peer.getShort());
                long frame = Integer.toUnsignedLong(peer.getInt()), streams = Integer.toUnsignedLong(peer.getInt());
                if (min < 1 || max < min || frame < 4096 || frame > 1048576 || streams < 1 || streams > 128) throw BinaryException.protocol();
                if (min > 2 || max < 2) throw new BinaryUnsupportedPeerException();
                int cap = Math.min(config.maxFrame, (int)frame);
                byte[] metadata = request(operation, bearer, milliseconds(deadline));
                check(deadline, cancellation); dispatched = true;
                BinaryFrameCodec.write(output, REQUEST, 1, metadata, cap);
                for (int offset = 0; offset < operation.ownedSource().length; offset += cap)
                    BinaryFrameCodec.write(output, DATA, 1, operation.ownedSource(), offset, Math.min(cap, operation.ownedSource().length - offset), cap);
                BinaryFrameCodec.write(output, END, 1, new byte[0], cap);
                Frame first = receive(input, output, cap);
                if (first.type() != RESPONSE || first.stream() != 1) throw BinaryException.protocol();
                var meta = BinaryMessageCodec.response(first.payload(), 2);
                correlate(meta, operation, consumer != null);
                if (meta.streaming()) {
                    observed = new BinaryResponse(meta, new byte[0], Map.of());
                    ByteArrayOutputStream page = new ByteArrayOutputStream(); int total = 0; boolean terminal = false, started = false;
                    for (;;) {
                        Frame next = receive(input, output, cap);
                        if (next.stream() != 1) throw BinaryException.protocol();
                        if (next.type() == END) { if (!started || page.size() != 0) throw BinaryException.protocol(); break; }
                        if (next.type() != DATA || terminal || next.payload().length > BinaryClient.MAX_SOURCE - total) throw BinaryException.protocol();
                        total += next.payload().length;
                        for (byte value : next.payload()) {
                            require(!terminal); page.write(value);
                            if (value == '\n') {
                                byte[] complete = page.toByteArray(); page.reset();
                                Page parsed = page(complete, after);
                                check(deadline, cancellation); consumer.page(complete);
                                after = parsed.after(); terminal = parsed.terminal(); started = true; check(deadline, cancellation);
                            } else if (terminal) throw BinaryException.protocol();
                        }
                    }
                    check(deadline, cancellation); return new BinaryClient.FeedResult(observed, after);
                }
                byte[] body = new byte[meta.bodyLength()]; int used = 0;
                for (;;) {
                    Frame next = receive(input, output, cap);
                    if (next.stream() != 1) throw BinaryException.protocol();
                    if (next.type() == END) { if (used != body.length) throw BinaryException.protocol(); break; }
                    if (next.type() != DATA || next.payload().length > body.length - used) throw BinaryException.protocol();
                    System.arraycopy(next.payload(), 0, body, used, next.payload().length); used += next.payload().length;
                }
                Map<String,Object> value = object(body); check(deadline, cancellation);
                semantics(meta, value, operation);
                observed = new BinaryResponse(meta, body, operation.mutation() && meta.status() < 400 ? value : Map.of());
                if (meta.status() >= 400) throw new BinaryException(BinaryException.Kind.STATUS, meta.status());
                return new BinaryClient.FeedResult(observed, after);
            }
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new BinaryOperationException(new BinaryException(BinaryException.Kind.CANCELLED, 0), dispatched && operation.mutation() ? operation : null, observed, after);
        } catch (IOException failure) {
            if (failure instanceof BinaryUnsupportedPeerException unsupported) throw unsupported;
            BinaryException safe;
            if (cancellation.isCancelled() || Thread.currentThread().isInterrupted()) safe = new BinaryException(BinaryException.Kind.CANCELLED, 0);
            else if (remaining(deadline) <= 0 || failure instanceof java.net.SocketTimeoutException) safe = new BinaryException(BinaryException.Kind.TIMEOUT, 0);
            else safe = failure instanceof BinaryException binary ? binary : new BinaryException(BinaryException.Kind.TRANSPORT, 0);
            boolean uncertain = dispatched && operation.mutation() && (safe.kind() != BinaryException.Kind.STATUS || safe.status() == 408 || safe.status() >= 500);
            throw new BinaryOperationException(safe, uncertain ? operation : null, observed, after);
        } finally { if (guard != null) guard.close(); if (acquired) slots.release(); }
    }
    private static byte[] request(BinaryOperation op, String token, int timeout) {
        var fields = new ArrayList<byte[]>();
        fields.add(field(1, new byte[]{(byte)op.wire()})); fields.add(field(2, op.target().getBytes(StandardCharsets.US_ASCII)));
        fields.add(field(3, op.contentType().getBytes(StandardCharsets.US_ASCII))); fields.add(field(4, ByteBuffer.allocate(8).putLong(op.ownedSource().length).array()));
        if (token != null) fields.add(field(5, ("Bearer " + token).getBytes(StandardCharsets.US_ASCII)));
        if (op.ifMatch() != null) fields.add(field(6, op.ifMatch().getBytes(StandardCharsets.US_ASCII)));
        if (op.ifNoneMatch() != null) fields.add(field(7, op.ifNoneMatch().getBytes(StandardCharsets.US_ASCII)));
        fields.add(field(8, HexFormat.of().parseHex(op.requestId()))); fields.add(field(9, ByteBuffer.allocate(4).putInt(timeout).array()));
        var out = new ByteArrayOutputStream(); out.writeBytes(ByteBuffer.allocate(4).putShort((short)2).putShort((short)fields.size()).array());
        for (byte[] value : fields) out.writeBytes(value);
        if (out.size() > 2048) throw BinaryEnvelope.invalid(); return out.toByteArray();
    }
    private static byte[] field(int id, byte[] value) { return ByteBuffer.allocate(4 + value.length).putShort((short)id).putShort((short)value.length).put(value).array(); }
    static Map<String,Object> object(byte[] body) throws BinaryException {
        return object(body, true);
    }
    private static Map<String,Object> object(byte[] body, boolean response) throws BinaryException {
        try {
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(body)).toString();
            return response ? Json.operationResponseObject(text) : Json.object(text);
        }
        catch (IllegalArgumentException | java.nio.charset.CharacterCodingException failure) { throw BinaryException.protocol(); }
    }
    private static void require(boolean value) throws BinaryException { if (!value) throw BinaryException.protocol(); }
    private static boolean media(String value, String expected) { return value.split(";", 2)[0].equalsIgnoreCase(expected); }
    private static void correlate(BinaryMessageCodec.Response m, BinaryOperation op, boolean feed) throws BinaryException {
        require(op.requestId().equals(m.requestId()) && m.bodyLength() == m.representationLength());
        require(!m.streaming() || feed);
        require(m.status() >= 400 ? !m.streaming() && m.bodyLength() <= 4096 : m.status() == 200 && (feed == m.streaming()));
        require(media(m.contentType(), m.streaming() ? "application/x-ndjson" : "application/json"));
        require(!(op.mutation() && m.bodyLength() > 4096));
        require((m.status() == 401) == m.authenticate() && (m.status() == 405) == (m.allow() != 0));
        require(m.retryAfterSeconds() == null || m.status() == 503 || m.status() == 429);
        if (op.method().equals("PATCH")) {
            String[] parts = op.target().split("/");
            require((m.collection() == null || m.collection().equals(parts[3])) && (m.document() == null || m.document().equals(parts[5])));
        } else require(m.collection() == null && m.document() == null && m.etag() == null);
    }
    private static void semantics(BinaryMessageCodec.Response m, Map<String,Object> value, BinaryOperation op) throws BinaryException {
        if (m.status() >= 400) { require(value.size() == 1 && value.get("error") instanceof String error && error.matches("[a-z0-9_]{1,128}")); return; }
        require(m.revision().equals(value.get("revision")));
        if (op.method().equals("PATCH")) {
            String[] parts = op.target().split("/");
            require(value.size() == 5 && "stored".equals(value.get("status")) && parts[3].equals(value.get("collection")) && parts[5].equals(value.get("document"))
                && value.get("etag") instanceof String tag && tag.matches("[0-9a-f]{16}") && ("\""+tag+"\"").equals(m.etag()));
        } else if (op.mutation()) {
            long count = integer(value.get("operations"));
            require(value.size() == 3 && "committed".equals(value.get("status")) && count >= 1 && count <= 128);
            if (op.contentType().split(";", 2)[0].equalsIgnoreCase("application/json")) {
                Object operations = object(op.ownedSource(), false).get("operations");
                require(operations instanceof List<?> entries && entries.size() == count);
            }
        }
        else if (op.target().startsWith("/v1/changes")) page(value, after(op.target()));
    }
    static String after(String target) { for (String part : target.substring(target.indexOf('?') + 1).split("&")) if (part.startsWith("after=")) return part.substring(6); return ""; }
    static boolean token(Object value) { return value instanceof String text && text.matches("v1\\.[0-9a-f]{32}\\.[0-9a-f]{16}"); }
    private static long integer(Object value) throws BinaryException { try { if (value instanceof Json.NumberValue number) return number.longValueExact(); } catch (ArithmeticException ignored) { /* invalid integer */ } throw BinaryException.protocol(); }
    record Page(String after, boolean terminal) {}
    static Page page(byte[] raw, String after) throws BinaryException { return page(object(raw), after); }
    static Page page(Map<String,Object> p, String after) throws BinaryException {
        if (p.containsKey("terminal")) {
            require(p.size() == 4 && Boolean.TRUE.equals(p.get("terminal")) && integer(p.get("status")) >= 400 && integer(p.get("status")) <= 599 && after.equals(p.get("after")) && p.get("detail") instanceof Map);
            return new Page(after, true);
        }
        require(token(p.get("next_after")) && token(p.get("checkpoint")) && token(p.get("oldest_after")) && p.get("revision") instanceof String revision && revision.matches("[0-9a-f]{16}") && p.get("has_more") instanceof Boolean && p.get("transactions") instanceof List);
        String next = (String)p.get("next_after"), tip = (String)p.get("checkpoint"), oldest = (String)p.get("oldest_after");
        require(next.substring(0,36).equals(tip.substring(0,36)) && oldest.substring(0,36).equals(tip.substring(0,36)) && oldest.compareTo(next) <= 0 && next.compareTo(tip) <= 0 && p.get("has_more").equals(next.compareTo(tip) < 0));
        require(after.isEmpty() || token(after) && after.substring(0,36).equals(next.substring(0,36)) && after.compareTo(next) <= 0);
        List<?> transactions = (List<?>)p.get("transactions"); require(transactions.size() <= 100 && (!after.isEmpty() || transactions.isEmpty()));
        String previous = after, previousRevision = "";
        for (Object item : transactions) {
            require(item instanceof Map); Map<?,?> tx = (Map<?,?>)item;
            require(token(tx.get("token")) && tx.get("revision") instanceof String r && r.matches("[0-9a-f]{16}") && tx.get("previous_revision") instanceof String before && before.matches("[0-9a-f]{16}") && tx.get("resnapshot_required") instanceof Boolean && tx.get("operations") instanceof List);
            String cursor = (String)tx.get("token"); require(cursor.substring(0,36).equals(tip.substring(0,36)) && cursor.compareTo(previous) > 0 && cursor.compareTo(tip) <= 0 && (previousRevision.isEmpty() || previousRevision.equals(tx.get("previous_revision"))));
            List<?> operations = (List<?>)tx.get("operations"); require(operations.size() <= 256 && (!Boolean.TRUE.equals(tx.get("resnapshot_required")) || operations.isEmpty()));
            Set<String> seen = new HashSet<>(); int sourceBytes = 0;
            for (Object entry : operations) {
                require(entry instanceof Map); Map<?,?> op = (Map<?,?>)entry;
                require(op.get("collection") instanceof String c && c.matches("[a-z0-9-]{1,128}"));
                Object doc = op.get("document"); require(seen.add(op.get("collection") + "/" + (doc == null ? "" : doc)));
                if (doc == null) require(op.size() == 2 && Boolean.TRUE.equals(op.get("create_collection")));
                else { require(doc instanceof String d && d.matches("[a-z0-9-]{1,128}") && op.size() == 3 && (op.get("put") instanceof String ^ Boolean.TRUE.equals(op.get("delete"))));
                    if (op.get("put") instanceof String text) { int n = text.getBytes(StandardCharsets.UTF_8).length; require(n > 0 && n <= BinaryClient.MAX_SOURCE - sourceBytes); sourceBytes += n; }
                }
            }
            previous = cursor; previousRevision = (String)tx.get("revision");
        }
        require(transactions.isEmpty() ? !Boolean.TRUE.equals(p.get("has_more")) && (after.isEmpty() || after.equals(next)) : previous.equals(next));
        return new Page(next, false);
    }
}
