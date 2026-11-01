package io.yamora;

import static io.yamora.BinaryEnvelope.Method.*;
import static io.yamora.BinaryFrameCodec.*;

import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

/** Additive dependency-free document CRUD transport. One owned, verified TLS 1.3
 * connection per call; no reconnect, replay, cluster discovery or recovery.
 * Keep at most four admitted calls per client. Queued callers retain their own
 * arguments: do not mutate source until the call returns or is admitted. */
public final class BinaryClient {
    public static final int MAX_SOURCE = 16 * 1024 * 1024;
    private static final byte[] EMPTY = new byte[0];
    private final BinaryConfig config;
    private final Semaphore slots;
    public BinaryClient(BinaryConfig config) { this.config = Objects.requireNonNull(config); slots = new Semaphore(config.maxCalls, true); }

    public BinaryResponse get(String collection, String document, String bearer) throws BinaryException {
        return call(GET, collection, document, EMPTY, bearer, null, null, null, new BinaryCancellation());
    }
    public BinaryResponse head(String collection, String document, String bearer) throws BinaryException {
        return call(HEAD, collection, document, EMPTY, bearer, null, null, null, new BinaryCancellation());
    }
    public BinaryResponse put(String collection, String document, byte[] source, String bearer,
            String ifMatch, String ifNoneMatch, String requestId, BinaryCancellation cancellation) throws BinaryException {
        return call(PUT, collection, document, source, bearer, ifMatch, ifNoneMatch, requestId, cancellation);
    }
    public BinaryResponse delete(String collection, String document, String bearer, String ifMatch,
            String requestId, BinaryCancellation cancellation) throws BinaryException {
        return call(DELETE, collection, document, EMPTY, bearer, ifMatch, null, requestId, cancellation);
    }
    /** Conditions, including present empty values, are sent unchanged to native validators.
     * null bearer omits authentication. null requestId creates a nonzero random ID.
     * The deadline begins at entry, including admission, freeze and receipt decoding. */
    public BinaryResponse call(BinaryEnvelope.Method method, String collection, String document, byte[] source,
            String bearer, String ifMatch, String ifNoneMatch, String requestId, BinaryCancellation cancellation)
            throws BinaryException {
        Objects.requireNonNull(cancellation);
        long deadline = System.nanoTime() + config.timeoutNanos;
        boolean acquired = false, dispatched = false;
        BinaryEnvelope envelope = null;
        Guard guard = null;
        try {
            while (!acquired) {
                check(deadline, cancellation);
                acquired = slots.tryAcquire(Math.min(10_000_000L, remaining(deadline)), TimeUnit.NANOSECONDS);
            }
            check(deadline, cancellation);
            BinaryEnvelope.bearer(bearer);
            envelope = new BinaryEnvelope(method, collection, document, source, ifMatch, ifNoneMatch, requestId);
            check(deadline, cancellation);
            Socket raw = new Socket(java.net.Proxy.NO_PROXY);
            guard = new Guard(raw, deadline, cancellation);
            raw.connect(new InetSocketAddress(config.endpoint(), config.port), milliseconds(deadline));
            raw.setTcpNoDelay(true);
            raw.setSoTimeout(milliseconds(deadline));
            try (SSLSocket tls = (SSLSocket) config.tls().getSocketFactory().createSocket(raw, config.serverName, config.port, true)) {
                SSLParameters parameters = tls.getSSLParameters();
                parameters.setProtocols(new String[]{"TLSv1.3"});
                parameters.setEndpointIdentificationAlgorithm("HTTPS");
                parameters.setApplicationProtocols(new String[]{"yamora-binary/1"});
                if (!config.serverName.matches("[0-9.]+")) parameters.setServerNames(java.util.List.of(new SNIHostName(config.serverName)));
                tls.setSSLParameters(parameters);
                check(deadline, cancellation); tls.startHandshake(); check(deadline, cancellation);
                if (!"TLSv1.3".equals(tls.getSession().getProtocol()) || !"yamora-binary/1".equals(tls.getApplicationProtocol())) throw BinaryException.protocol();
                InputStream input = guarded(tls.getInputStream(), deadline, cancellation);
                OutputStream output = guarded(tls.getOutputStream(), deadline, cancellation);
                BinaryFrameCodec.write(output, HELLO, 0, ByteBuffer.allocate(12).putShort((short) 1).putShort((short) 1)
                        .putInt(config.maxFrame).putInt(1).array(), config.maxFrame);
                Frame hello = BinaryFrameCodec.read(input, config.maxFrame);
                if (hello.type() != HELLO) throw BinaryException.protocol();
                ByteBuffer peer = ByteBuffer.wrap(hello.payload());
                int min = Short.toUnsignedInt(peer.getShort()), max = Short.toUnsignedInt(peer.getShort());
                long frame = Integer.toUnsignedLong(peer.getInt()), streams = Integer.toUnsignedLong(peer.getInt());
                if (min != 1 || max < 1 || frame < 4096 || frame > 1048576 || streams < 1 || streams > 128) throw BinaryException.protocol();
                int cap = Math.min(config.maxFrame, (int) frame);
                byte[] metadata = BinaryMessageCodec.request(envelope, bearer, milliseconds(deadline));
                check(deadline, cancellation);
                // From the first attempted REQUEST byte onward a mutation is ambiguous
                // until its complete native receipt and END are validated.
                dispatched = true;
                BinaryFrameCodec.write(output, REQUEST, 1, metadata, cap);
                byte[] owned = envelope.ownedSource();
                for (int offset = 0; offset < owned.length; offset += cap) {
                    BinaryFrameCodec.write(output, DATA, 1, owned, offset, Math.min(cap, owned.length - offset), cap);
                }
                BinaryFrameCodec.write(output, END, 1, EMPTY, cap);
                Frame response = receive(input, output, cap);
                if (response.type() != RESPONSE || response.stream() != 1) throw BinaryException.protocol();
                BinaryMessageCodec.Response message = BinaryMessageCodec.response(response.payload());
                correlate(message, envelope);
                byte[] body = new byte[message.bodyLength()]; int position = 0;
                while (true) {
                    Frame next = receive(input, output, cap);
                    if (next.stream() != 1) throw BinaryException.protocol();
                    if (next.type() == END) { if (position != body.length) throw BinaryException.protocol(); break; }
                    byte[] part = next.payload();
                    if (next.type() != DATA || part.length > body.length - position) throw BinaryException.protocol();
                    System.arraycopy(part, 0, body, position, part.length); position += part.length;
                }
                Map<String, Object> receipt = semantics(message, body, envelope, deadline, cancellation);
                check(deadline, cancellation);
                if (message.status() >= 400) throw new BinaryException(BinaryException.Kind.STATUS, message.status());
                return new BinaryResponse(message, body, receipt);
            }
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            BinaryException stopped = new BinaryException(BinaryException.Kind.CANCELLED, 0);
            if (dispatched && envelope.method().mutation()) throw new BinaryUncertainException(envelope, stopped);
            throw stopped;
        } catch (IOException failure) {
            BinaryException safe;
            if (cancellation.isCancelled() || Thread.currentThread().isInterrupted()) safe = new BinaryException(BinaryException.Kind.CANCELLED, 0);
            else if (remaining(deadline) <= 0 || failure instanceof java.net.SocketTimeoutException) safe = new BinaryException(BinaryException.Kind.TIMEOUT, 0);
            else safe = failure instanceof BinaryException binary ? binary : new BinaryException(BinaryException.Kind.TRANSPORT, 0);
            if (dispatched && envelope.method().mutation()
                    && (safe.kind() != BinaryException.Kind.STATUS || safe.status() >= 500 || safe.status() == 408)) {
                throw new BinaryUncertainException(envelope, safe);
            }
            throw safe;
        } finally {
            if (guard != null) guard.close();
            if (acquired) slots.release();
        }
    }
    /** Finite schema-2 operation; no HTTP fallback or automatic replay. */
    public BinaryResponse operation(String method, String target, String contentType, byte[] source,
            String bearer, String ifMatch, String ifNoneMatch, String requestId, BinaryCancellation cancellation) throws BinaryException {
        return BinaryOperations.run(config, slots, method, target, contentType, source, bearer, ifMatch, ifNoneMatch, requestId, cancellation, null).response();
    }
    @FunctionalInterface public interface PageConsumer { void page(byte[] completeRawPage) throws BinaryException; }
    public record FeedResult(BinaryResponse response, String lastAfter) {}
    /** Callback owns a complete validated page including LF. Returning applies backpressure. */
    public FeedResult feed(String target, String bearer, String requestId, BinaryCancellation cancellation, PageConsumer consumer) throws BinaryException {
        return feed(target, bearer, null, null, requestId, cancellation, consumer);
    }
    public FeedResult feed(String target, String bearer, String ifMatch, String ifNoneMatch, String requestId, BinaryCancellation cancellation, PageConsumer consumer) throws BinaryException {
        return BinaryOperations.run(config, slots, "GET", target, "", new byte[0], bearer, ifMatch, ifNoneMatch, requestId, cancellation, Objects.requireNonNull(consumer));
    }
    static Frame receive(InputStream input, OutputStream output, int cap) throws IOException {
        int pings = 0;
        while (true) {
            Frame frame = BinaryFrameCodec.read(input, cap);
            if (frame.type() != PING) return frame;
            if (++pings > 4) throw BinaryException.protocol();
            BinaryFrameCodec.write(output, PONG, 0, frame.payload(), cap);
        }
    }
    private static void correlate(BinaryMessageCodec.Response m, BinaryEnvelope e) throws BinaryException {
        if (!e.requestId().equals(m.requestId()) || m.collection() != null && !e.collection().equals(m.collection())
                || m.document() != null && !e.document().equals(m.document())
                || (e.method() == HEAD ? m.bodyLength() != 0 : m.status() != 304 && m.bodyLength() != m.representationLength())
                || (e.method().mutation() || m.status() >= 400) && m.representationLength() > 4096
                || m.status() < 400 && switch (e.method()) {
                    case GET, HEAD -> m.status() != 200;
                    case PUT -> m.status() != 200 && m.status() != 201;
                    case DELETE -> m.status() != 204;
                }) throw BinaryException.protocol();
        if (m.status() == 200 && (e.method() == GET || e.method() == HEAD)) {
            if (!yaml(m.contentType()) || m.etag() == null || !e.collection().equals(m.collection()) || !e.document().equals(m.document())) throw BinaryException.protocol();
        } else if (!json(m.contentType())) throw BinaryException.protocol();
        if (m.status() == 401 && !m.authenticate() || m.authenticate() && m.status() != 401
                || m.status() == 405 && m.allow() == 0 || m.allow() != 0 && m.status() != 405
                || m.retryAfterSeconds() != null && m.status() != 503 && m.status() != 429) throw BinaryException.protocol();
    }
    private static boolean yaml(String media) { String base = media.split(";", 2)[0]; return base.equalsIgnoreCase("application/yaml") || base.equalsIgnoreCase("text/yaml"); }
    private static boolean json(String media) { return media.split(";", 2)[0].equalsIgnoreCase("application/json"); }
    private static Map<String, Object> semantics(BinaryMessageCodec.Response m, byte[] body, BinaryEnvelope e,
            long deadline, BinaryCancellation cancellation) throws BinaryException {
        if (e.method() == GET && m.status() == 200) {
            if (!sourceEtag(body, deadline, cancellation).equals(m.etag())) throw BinaryException.protocol();
            return Map.of();
        }
        if (e.method() == HEAD || m.status() == 204) return Map.of();
        Map<String, Object> value;
        try {
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(body)).toString();
            // 4 KiB total plus Json's strict depth/node/number limits bounds all tokens.
            value = Json.object(text);
        } catch (IllegalArgumentException | CharacterCodingException failure) { throw BinaryException.protocol(); }
        if (m.status() >= 400) {
            if (value.size() != 1 || !(value.get("error") instanceof String code) || !code.matches("[a-z0-9_]{1,128}")) throw BinaryException.protocol();
        } else if (e.method() == PUT) {
            if (value.size() != 5 || !"stored".equals(value.get("status")) || !e.collection().equals(value.get("collection"))
                    || !e.document().equals(value.get("document")) || !m.revision().equals(value.get("revision"))
                    || !(value.get("etag") instanceof String tag) || !tag.matches("[0-9a-f]{16}")
                    || !("\"" + tag + "\"").equals(m.etag())
                    || !sourceEtag(e.ownedSource(), deadline, cancellation).equals(m.etag())) throw BinaryException.protocol();
        } else throw BinaryException.protocol();
        return value;
    }
    /** Native source hash, deliberately using the disk engine's noncanonical FNV
     * seed. Java long overflow is the required arithmetic modulo 2^64. Hash the
     * owned raw bytes in place, including unsigned UTF-8 octets and CRLF/comments. */
    private static String sourceEtag(byte[] source, long deadline, BinaryCancellation cancellation) throws BinaryException {
        long hash = 1469598103934665603L;
        for (int offset = 0; offset < source.length; offset += 4096) {
            check(deadline, cancellation);
            int end = Math.min(source.length, offset + 4096);
            for (int i = offset; i < end; i++) hash = (hash ^ (source[i] & 255L)) * 1099511628211L;
        }
        check(deadline, cancellation);
        return "\"" + java.util.HexFormat.of().toHexDigits(hash) + "\"";
    }
    static long remaining(long deadline) { return deadline - System.nanoTime(); }
    static int milliseconds(long deadline) throws BinaryException {
        long nanos = remaining(deadline);
        if (nanos <= 0) throw new BinaryException(BinaryException.Kind.TIMEOUT, 0);
        return (int) Math.min(30000, Math.max(1, (nanos + 999999) / 1000000));
    }
    static void check(long deadline, BinaryCancellation cancellation) throws BinaryException {
        if (cancellation.isCancelled() || Thread.currentThread().isInterrupted()) throw new BinaryException(BinaryException.Kind.CANCELLED, 0);
        if (remaining(deadline) <= 0) throw new BinaryException(BinaryException.Kind.TIMEOUT, 0);
    }
    static InputStream guarded(InputStream stream, long deadline, BinaryCancellation cancellation) {
        return new FilterInputStream(stream) {
            @Override public int read(byte[] bytes, int offset, int length) throws IOException {
                check(deadline, cancellation); int n = in.read(bytes, offset, length); check(deadline, cancellation); return n;
            }
            @Override public int read() throws IOException { check(deadline, cancellation); int n = in.read(); check(deadline, cancellation); return n; }
        };
    }
    static OutputStream guarded(OutputStream stream, long deadline, BinaryCancellation cancellation) {
        return new FilterOutputStream(stream) {
            @Override public void write(byte[] bytes, int offset, int length) throws IOException { check(deadline, cancellation); out.write(bytes, offset, length); check(deadline, cancellation); }
            @Override public void write(int value) throws IOException { check(deadline, cancellation); out.write(value); check(deadline, cancellation); }
        };
    }
    /** One watchdog per admitted I/O call, never a global timer or unbounded registry.
     * Close the raw socket (not SSL close_notify) to interrupt TCP/TLS/read/write.
     * Every exit interrupts and joins the watchdog before releasing admission. */
    static final class Guard implements AutoCloseable {
        final Socket socket; final Thread thread;
        Guard(Socket socket, long deadline, BinaryCancellation cancellation) {
            this.socket = socket;
            Thread owner = Thread.currentThread();
            thread = new Thread(() -> {
                try {
                    while (remaining(deadline) > 0 && !cancellation.isCancelled() && !owner.isInterrupted()) {
                        TimeUnit.NANOSECONDS.sleep(Math.max(1L, Math.min(5_000_000L, remaining(deadline))));
                    }
                    closeSocket();
                } catch (InterruptedException expected) { /* owner finished */ }
            }, "yamora-binary-deadline");
            thread.setDaemon(true); thread.start();
        }
        private void closeSocket() { try { socket.close(); } catch (IOException ignored) { /* owned */ } }
        @Override public void close() {
            thread.interrupt(); closeSocket();
            boolean interrupted = Thread.interrupted();
            while (thread.isAlive()) {
                try { thread.join(); } catch (InterruptedException failure) { interrupted = true; }
            }
            if (interrupted) Thread.currentThread().interrupt();
        }
    }
}
