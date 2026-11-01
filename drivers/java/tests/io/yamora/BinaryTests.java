package io.yamora;

import static io.yamora.DriverTests.*;
import static io.yamora.BinaryEnvelope.Method.*;
import static io.yamora.BinaryFrameCodec.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ProxySelector;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

/** Literal independent vectors and verified hostile TLS peers; no protocol mocks. */
public final class BinaryTests {
    private BinaryTests() {}
    static final String ID = "0102030405060708090a0b0c0d0e0f10";
    static Path certs;
    static Tls server;
    static int cases;
    @FunctionalInterface interface Session { void handle(SSLSocket socket, int index) throws Exception; }
    static final class Peer implements AutoCloseable {
        final SSLServerSocket listener;
        final Thread thread;
        final AtomicInteger accepted = new AtomicInteger();
        final AtomicReference<Throwable> failure = new AtomicReference<>();
        volatile boolean closed;
        Peer(Session session, String alpn, String protocol) throws Exception {
            listener = (SSLServerSocket) server.context().getServerSocketFactory().createServerSocket(0, 8, InetAddress.getByName("127.0.0.1"));
            check(listener.getLocalPort() != 8000, "reserved port");
            var parameters = listener.getSSLParameters();
            parameters.setProtocols(new String[]{protocol});
            parameters.setApplicationProtocols(alpn == null ? new String[0] : new String[]{alpn});
            listener.setSSLParameters(parameters);
            thread = new Thread(() -> {
                try {
                    while (!closed) {
                        try (SSLSocket socket = (SSLSocket) listener.accept()) {
                            socket.setSoTimeout(3000);
                            session.handle(socket, accepted.incrementAndGet());
                        }
                    }
                } catch (java.net.SocketException stopped) { if (!closed) failure.set(stopped); }
                catch (Throwable error) { failure.set(error); }
            }, "binary-test-peer");
            thread.start();
        }
        Peer(Session session) throws Exception { this(session, "yamora-binary/1", "TLSv1.3"); }
        BinaryClient client(Duration timeout, int calls) throws Exception { return new BinaryClient(config(listener.getLocalPort(), timeout, calls)); }
        @Override public void close() throws IOException {
            closed = true; listener.close();
            try { thread.join(5000); } catch (InterruptedException error) { Thread.currentThread().interrupt(); throw new IOException(error); }
            check(!thread.isAlive(), "hostile peer leaked");
            if (failure.get() != null) throw new AssertionError("hostile peer failed", failure.get());
        }
    }
    static BinaryConfig config(int port, Duration timeout, int calls) throws Exception {
        return new BinaryConfig("127.0.0.1", port, "127.0.0.1", Files.readAllBytes(certs.resolve("ca.pem")), null, null, timeout, calls, 4096);
    }
    // Independent test encoder: deliberately does not call either production codec.
    static byte[] raw(int kind, int stream, byte[] payload) {
        return ByteBuffer.allocate(16 + payload.length).putInt(0x594d4246).put((byte) 1).put((byte) kind).putShort((short) 0)
                .putInt(stream).putInt(payload.length).put(payload).array();
    }
    static byte[] meta(Map<Integer, byte[]> fields) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(ByteBuffer.allocate(4).putShort((short) 1).putShort((short) fields.size()).array());
        fields.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(entry -> {
            out.writeBytes(ByteBuffer.allocate(4).putShort(entry.getKey().shortValue()).putShort((short) entry.getValue().length).array());
            out.writeBytes(entry.getValue());
        });
        return out.toByteArray();
    }
    static Map<Integer, byte[]> fields(int status, int length, int representation, String media, String id) {
        Map<Integer, byte[]> fields = new java.util.TreeMap<>();
        fields.put(1, ByteBuffer.allocate(2).putShort((short) status).array());
        fields.put(2, bytes(media)); fields.put(3, ByteBuffer.allocate(8).putLong(length).array());
        fields.put(4, ByteBuffer.allocate(8).putLong(representation).array()); fields.put(5, bytes(REV));
        fields.put(12, HexFormat.of().parseHex(id));
        return fields;
    }
    static byte[] receipt() { return receipt("d25cb84ad7e05b47"); }
    static byte[] receipt(String tag) { return bytes("{\"status\":\"stored\",\"collection\":\"config\",\"document\":\"one\",\"etag\":\"" + tag + "\",\"revision\":\"" + REV + "\"}\n"); }
    static Map<Integer, byte[]> putFields(byte[] receipt) {
        var fields = fields(201, receipt.length, receipt.length, "application/json", ID); fields.put(6, bytes("\"d25cb84ad7e05b47\"")); return fields;
    }
    static void hello(SSLSocket socket) throws Exception {
        hello(socket, 1);
    }
    static void hello(SSLSocket socket, int streams) throws Exception {
        socket.startHandshake();
        Frame hello = BinaryFrameCodec.read(socket.getInputStream(), 65536);
        check(hello.type() == HELLO, "client HELLO");
        check(ByteBuffer.wrap(hello.payload()).getInt(8) == 1, "client must retain single-stream admission");
        socket.getOutputStream().write(raw(HELLO, 0, ByteBuffer.allocate(12).putShort((short) 1)
                .putShort((short) 1).putInt(4096).putInt(streams).array()));
    }
    static void peerCapacity() throws Exception {
        for (int streams : new int[]{4, 128}) {
            try (Peer peer = new Peer((socket, index) -> {
                hello(socket, streams);
                success(socket, upload(socket));
            })) {
                put(peer.client(Duration.ofSeconds(2), 1), bytes("a: 1\n"), new BinaryCancellation());
                check(peer.accepted.get() == 1, "capacity negotiation must not replay"); cases++;
            }
        }
        for (int streams : new int[]{0, 129, -1}) {
            try (Peer peer = new Peer((socket, index) -> hello(socket, streams))) {
                fails(() -> put(peer.client(Duration.ofSeconds(2), 1), bytes("a: 1\n"), new BinaryCancellation()),
                        BinaryException.Kind.PROTOCOL, false); cases++;
            }
        }
    }
    static byte[] upload(SSLSocket socket) throws Exception {
        Frame request = BinaryFrameCodec.read(socket.getInputStream(), 4096);
        check(request.type() == REQUEST && request.stream() == 1, "client request");
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        while (true) {
            Frame next = BinaryFrameCodec.read(socket.getInputStream(), 4096);
            if (next.type() == END) break;
            check(next.type() == DATA && next.stream() == 1, "client fragments"); body.writeBytes(next.payload());
        }
        return body.toByteArray();
    }
    static void success(SSLSocket socket, byte[] source) throws IOException {
        String tag = Arrays.equals(source, bytes("a: 1\n")) ? "d25cb84ad7e05b47" : "d255f04ad7da9bc1";
        check(Arrays.equals(source, bytes("a: 1\n")) || Arrays.equals(source, bytes("a: 7\n")), "missing admission source golden");
        byte[] receipt = receipt(tag);
        var fields = putFields(receipt); fields.put(6, bytes("\"" + tag + "\""));
        socket.getOutputStream().write(raw(RESPONSE, 1, meta(fields)));
        socket.getOutputStream().write(raw(DATA, 1, receipt));
        socket.getOutputStream().write(raw(END, 1, new byte[0]));
    }
    static BinaryException fails(Action action, BinaryException.Kind kind, boolean uncertain) throws Exception {
        try { action.run(); throw new AssertionError("binary call accepted hostile behavior"); }
        catch (BinaryException failure) {
            check(failure.kind() == kind, "binary kind " + failure + " wanted " + kind);
            check((failure instanceof BinaryUncertainException) == uncertain, "uncertainty classification");
            if (uncertain) {
                BinaryUncertainException u = (BinaryUncertainException) failure;
                check(ID.equals(u.requestId()), "original mutation ID lost");
                byte[] owned = u.envelope().source(); owned[0] ^= 1;
                check(u.envelope().source()[0] != owned[0], "uncertain source not immutable");
                check(!u.envelope().toString().contains("config") && !u.toString().contains(WRITE), "uncertainty leaked private data");
            }
            cases++; return failure;
        }
    }
    static void put(BinaryClient client, byte[] source, BinaryCancellation signal) throws BinaryException {
        client.put("config", "one", source, WRITE, null, "*", ID, signal);
    }
    static void codec() throws Exception {
        byte[] end = HexFormat.of().parseHex("594d4246010500000000000100000000");
        var frame = BinaryFrameCodec.read(new ByteArrayInputStream(end), 4096);
        check(frame.type() == END && frame.stream() == 1 && frame.payload().length == 0, "literal END");
        ByteArrayOutputStream out = new ByteArrayOutputStream(); BinaryFrameCodec.write(out, END, 1, new byte[0], 4096);
        check(Arrays.equals(end, out.toByteArray()), "END encoding differs from literal");
        BinaryEnvelope envelope = new BinaryEnvelope(PUT, "a", "b", bytes("x: 1\n"), null, "*", ID);
        byte[] expected = HexFormat.of().parseHex("0001000800010001030002001d2f76312f636f6c6c656374696f6e732f612f646f63756d656e74732f62000300106170706c69636174696f6e2f79616d6c000400080000000000000005000500084265617265722074000700012a000800100102030405060708090a0b0c0d0e0f100009000400007530");
        check(Arrays.equals(expected, BinaryMessageCodec.request(envelope, "t", 30000)), "literal request metadata");
        byte[] response = HexFormat.of().parseHex("000100050001000200cc000200106170706c69636174696f6e2f6a736f6e0003000800000000000000000004000800000000000000000005001030313233343536373839616263646566");
        check(BinaryMessageCodec.response(response).status() == 204, "literal response metadata");
        for (int offset = 0; offset < end.length; offset++) {
            byte[] shortFrame = Arrays.copyOf(end, offset);
            try { BinaryFrameCodec.read(new ByteArrayInputStream(shortFrame), 4096); throw new AssertionError("accepted truncated header"); }
            catch (IOException expectedFailure) { cases++; }
        }
        for (int offset : new int[]{0, 4, 5, 6, 12}) {
            byte[] bad = end.clone(); bad[offset] ^= (byte) 128;
            fails(() -> BinaryFrameCodec.read(new ByteArrayInputStream(bad), 4096), BinaryException.Kind.PROTOCOL, false);
        }
        for (int offset = 0; offset < response.length; offset++) {
            byte[] shortMetadata = Arrays.copyOf(response, offset);
            fails(() -> BinaryMessageCodec.response(shortMetadata), BinaryException.Kind.PROTOCOL, false);
        }
        var malformed = fields(204, 0, 0, "application/json", ID);
        for (int field : new int[]{1, 3, 4, 5, 6, 9, 10, 11, 12}) {
            var bad = new java.util.TreeMap<>(malformed); bad.put(field, new byte[7]);
            fails(() -> BinaryMessageCodec.response(meta(bad)), BinaryException.Kind.PROTOCOL, false);
        }
        byte[] duplicate = response.clone(); duplicate[11] = 1;
        fails(() -> BinaryMessageCodec.response(duplicate), BinaryException.Kind.PROTOCOL, false);
        byte[] trailer = Arrays.copyOf(response, response.length + 1);
        fails(() -> BinaryMessageCodec.response(trailer), BinaryException.Kind.PROTOCOL, false);
        cases++;
    }
    static void hostile() throws Exception {
        // Each case completes TLS and consumes the request. Mutations retain uncertainty.
        for (String mode : List.of("wrong-id", "oversized", "eof", "error", "goaway", "partial", "bad-json", "wrong-document", "wrong-revision", "head", "end", "wrong-stream", "huge-frame", "duplicate-json", "invalid-utf8", "number-token", "nested-token", "get-source-hash", "put-source-hash")) {
            String only = System.getProperty("yamora.binary.hostile");
            if (only != null && !only.equals(mode)) continue;
            try (Peer peer = new Peer((socket, index) -> {
                hello(socket); byte[] uploaded = upload(socket);
                if (mode.equals("get-source-hash") || mode.equals("put-source-hash")) {
                    boolean get = mode.equals("get-source-hash");
                    byte[] source = bytes("# café λ\r\nvalue: 01 # 雪\r\n");
                    check(get ? uploaded.length == 0 : Arrays.equals(uploaded, source), "hash peer received wrong source");
                    // Literal native hash for a different source, a: 1\n. Identity,
                    // names, revision, lengths, JSON/TLV agreement and END are valid.
                    String wrong = "d25cb84ad7e05b47";
                    byte[] body = get ? source : bytes("{\"status\":\"stored\",\"collection\":\"config\",\"document\":\"one\",\"etag\":\"" + wrong + "\",\"revision\":\"" + REV + "\"}\n");
                    var fields = fields(get ? 200 : 201, body.length, body.length, get ? "application/yaml" : "application/json", ID);
                    fields.put(6, bytes("\"" + wrong + "\""));
                    fields.put(7, bytes("config")); fields.put(8, bytes("one"));
                    ByteArrayOutputStream coalesced = new ByteArrayOutputStream();
                    coalesced.writeBytes(raw(RESPONSE, 1, meta(fields)));
                    coalesced.writeBytes(raw(DATA, 1, body)); coalesced.writeBytes(raw(END, 1, new byte[0]));
                    socket.getOutputStream().write(coalesced.toByteArray()); return;
                }
                if (mode.equals("eof")) return;
                if (mode.equals("error")) { socket.getOutputStream().write(raw(ERROR, 1, new byte[]{0, 0, 0, 1})); return; }
                if (mode.equals("goaway")) { socket.getOutputStream().write(raw(GOAWAY, 0, new byte[0])); return; }
                if (mode.equals("huge-frame")) { socket.getOutputStream().write(HexFormat.of().parseHex("594d424601030000000000017fffffff")); return; }
                byte[] receipt = receipt();
                if (mode.equals("bad-json")) receipt = bytes(new String(receipt, java.nio.charset.StandardCharsets.UTF_8).replace("stored", "failed"));
                if (mode.equals("wrong-document")) receipt = bytes(new String(receipt, java.nio.charset.StandardCharsets.UTF_8).replace("one", "two"));
                if (mode.equals("wrong-revision")) receipt = bytes(new String(receipt, java.nio.charset.StandardCharsets.UTF_8).replace("\"revision\":\"" + REV, "\"revision\":\"" + "0".repeat(16)));
                if (mode.equals("duplicate-json")) receipt = bytes("{\"status\":\"stored\",\"status\":\"stored\"}");
                if (mode.equals("invalid-utf8")) receipt = new byte[]{'{', '\"', (byte) 0xff, '\"', ':', '1', '}'};
                if (mode.equals("number-token")) receipt = bytes("{\"status\":" + "1".repeat(1025) + "}");
                if (mode.equals("nested-token")) receipt = bytes("{\"status\":" + "[".repeat(65) + "0" + "]".repeat(65) + "}");
                var fields = putFields(receipt);
                if (mode.equals("wrong-id")) fields.put(12, HexFormat.of().parseHex("11".repeat(16)));
                if (mode.equals("oversized")) { fields.put(3, ByteBuffer.allocate(8).putLong(4097).array()); fields.put(4, fields.get(3)); }
                if (mode.equals("head")) fields.put(1, new byte[]{0, (byte) 204});
                if (mode.equals("wrong-id")) {
                    ByteArrayOutputStream coalesced = new ByteArrayOutputStream();
                    coalesced.writeBytes(raw(RESPONSE, 1, meta(fields)));
                    coalesced.writeBytes(raw(DATA, 1, receipt)); coalesced.writeBytes(raw(END, 1, new byte[0]));
                    socket.getOutputStream().write(coalesced.toByteArray()); return;
                }
                socket.getOutputStream().write(raw(RESPONSE, mode.equals("wrong-stream") ? 3 : 1, meta(fields)));
                if (List.of("wrong-id", "oversized", "head", "wrong-stream").contains(mode)) return;
                if (mode.equals("partial")) { socket.getOutputStream().write(Arrays.copyOf(raw(DATA, 1, receipt), 20)); return; }
                socket.getOutputStream().write(raw(DATA, 1, receipt));
                if (!mode.equals("end")) socket.getOutputStream().write(raw(END, 1, new byte[0]));
            })) {
                BinaryException.Kind kind = List.of("eof", "partial", "end").contains(mode) ? BinaryException.Kind.TRANSPORT : BinaryException.Kind.PROTOCOL;
                if (mode.equals("get-source-hash") || mode.equals("put-source-hash")) {
                    boolean get = mode.equals("get-source-hash");
                    byte[] source = bytes("# café λ\r\nvalue: 01 # 雪\r\n");
                    BinaryException failure = fails(() -> peer.client(Duration.ofSeconds(2), 1).call(get ? GET : PUT,
                            "config", "one", get ? new byte[0] : source, get ? READ : WRITE, null, get ? null : "*", ID,
                            new BinaryCancellation()), BinaryException.Kind.PROTOCOL, !get);
                    if (!get) {
                        BinaryEnvelope original = ((BinaryUncertainException) failure).envelope();
                        check(Arrays.equals(source, original.source()) && original.ifNoneMatch().equals("*")
                                && original.target().equals("/v1/collections/config/documents/one"), "hash mismatch lost original envelope");
                    }
                } else fails(() -> put(peer.client(Duration.ofSeconds(2), 1), bytes("a: 1\n"), new BinaryCancellation()), kind, true);
                check(peer.accepted.get() == 1, "automatic replay");
            }
        }
    }
    static void sourceHashes() throws Exception {
        String[] sources = {"", "a: 1\n", "# café λ\r\nvalue: 01 # 雪\r\n"};
        String[] tags = {"14650fb0739d0383", "d25cb84ad7e05b47", "64dd05d0db749f4e"};
        for (int i = 0; i < sources.length; i++) {
            byte[] source = bytes(sources[i]); String tag = tags[i];
            for (boolean get : new boolean[]{true, false}) {
                try (Peer peer = new Peer((socket, index) -> {
                    hello(socket); byte[] uploaded = upload(socket);
                    check(get ? uploaded.length == 0 : Arrays.equals(source, uploaded), "source golden upload changed");
                    byte[] body = get ? source : receipt(tag);
                    var fields = fields(get ? 200 : 201, body.length, body.length, get ? "application/yaml" : "application/json", ID);
                    fields.put(6, bytes("\"" + tag + "\"")); fields.put(7, bytes("config")); fields.put(8, bytes("one"));
                    ByteArrayOutputStream coalesced = new ByteArrayOutputStream();
                    coalesced.writeBytes(raw(RESPONSE, 1, meta(fields)));
                    if (body.length != 0) coalesced.writeBytes(raw(DATA, 1, body));
                    coalesced.writeBytes(raw(END, 1, new byte[0])); socket.getOutputStream().write(coalesced.toByteArray());
                })) {
                    BinaryResponse response = peer.client(Duration.ofSeconds(2), 1).call(get ? GET : PUT, "config", "one", get ? new byte[0] : source,
                            get ? READ : WRITE, null, null, ID, new BinaryCancellation());
                    check(response.metadata().etag().equals("\"" + tag + "\""), "native source hash golden");
                    check(!get || Arrays.equals(source, response.body()), "hashed GET source changed");
                    check(watchdogs() == 0, "hash verification leaked watchdog"); cases++;
                }
            }
        }
    }
    static void tls() throws Exception {
        for (String version : List.of("TLSv1.2", "TLSv1.3")) {
            try (Peer peer = new Peer((socket, i) -> { try { socket.startHandshake(); } catch (IOException expected) { /* reject */ } }, null, version)) {
                BinaryException failure;
                try { peer.client(Duration.ofSeconds(2), 1).get("config", "one", READ); throw new AssertionError("TLS profile accepted"); }
                catch (BinaryException expected) { failure = expected; }
                check(!(failure instanceof BinaryUncertainException), "predispatch TLS failure uncertain"); cases++;
            }
        }
        try (Peer peer = new Peer((socket, i) -> { try { socket.startHandshake(); } catch (IOException expected) { /* client reject */ } })) {
            BinaryConfig wrong = new BinaryConfig("127.0.0.1", peer.listener.getLocalPort(), "wrong.test", Files.readAllBytes(certs.resolve("ca.pem")), null, null, Duration.ofSeconds(2), 1, 4096);
            fails(() -> new BinaryClient(wrong).get("config", "one", READ), BinaryException.Kind.TRANSPORT, false);
        }
        for (String address : List.of("localhost", "127.00.0.1", "127.1", "8.8.8.8", "169.254.169.254", "::1", "0.0.0.0")) {
            invalid(() -> new BinaryConfig(address, 1234, "test", new byte[]{1}, null, null, Duration.ofSeconds(1), 1, 4096));
        }
        for (int calls : new int[]{0, 5}) invalid(() -> config(1234, Duration.ofSeconds(1), calls));
        cases++;
    }
    static long watchdogs() { return Thread.getAllStackTraces().keySet().stream().filter(t -> t.getName().equals("yamora-binary-deadline") && t.isAlive()).count(); }
    static long descriptors() throws IOException {
        try (var files = Files.list(Path.of("/proc/self/fd"))) { return files.count(); }
    }
    static void deadlines() throws Exception {
        long beforeDescriptors = descriptors();
        for (String phase : List.of("tcp-tls", "hello", "receipt", "body")) {
            try (Peer peer = new Peer((socket, i) -> {
                if (phase.equals("tcp-tls")) { Thread.sleep(600); return; }
                if (phase.equals("hello")) { socket.startHandshake(); BinaryFrameCodec.read(socket.getInputStream(), 4096); }
                else hello(socket);
                if (phase.equals("receipt") || phase.equals("body")) upload(socket);
                if (phase.equals("body")) socket.getOutputStream().write(raw(RESPONSE, 1, meta(putFields(receipt()))));
                try { while (socket.getInputStream().read() >= 0) { /* await owned cancellation/timeout */ } } catch (IOException expected) { /* closed */ }
            })) {
                long start = System.nanoTime();
                fails(() -> put(peer.client(Duration.ofMillis(300), 1), bytes("a: 1\n"), new BinaryCancellation()), BinaryException.Kind.TIMEOUT,
                        phase.equals("receipt") || phase.equals("body"));
                check(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(2), "absolute deadline was reset");
                check(watchdogs() == 0, "deadline timer leaked");
            }
        }
        CountDownLatch admitted = new CountDownLatch(1), release = new CountDownLatch(1);
        AtomicReference<byte[]> received = new AtomicReference<>();
        try (Peer peer = new Peer((socket, index) -> {
            hello(socket);
            if (index == 1) { admitted.countDown(); check(release.await(3, TimeUnit.SECONDS), "release blocker"); }
            byte[] source = upload(socket);
            if (index == 1) check(Arrays.equals(source, bytes("a: 1\n")), "admitted source was not frozen");
            received.set(source); success(socket, source);
        })) {
            BinaryClient client = peer.client(Duration.ofSeconds(3), 1);
            AtomicReference<Throwable> firstError = new AtomicReference<>();
            byte[] first = bytes("a: 1\n");
            Thread firstThread = new Thread(() -> { try { put(client, first, new BinaryCancellation()); } catch (Throwable error) { firstError.set(error); } });
            firstThread.start(); check(admitted.await(2, TimeUnit.SECONDS), "admission blocker not entered");
            first[3] = '9'; // Already admitted: the peer must receive the old source.
            BinaryCancellation waiting = new BinaryCancellation();
            Thread cancel = new Thread(() -> { try { Thread.sleep(80); waiting.cancel(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); } });
            cancel.start();
            fails(() -> put(client, new byte[BinaryClient.MAX_SOURCE], waiting), BinaryException.Kind.CANCELLED, false);
            cancel.join(); check(peer.accepted.get() == 1, "waiter opened connection");
            byte[] queued = bytes("a: 2\n");
            CountDownLatch started = new CountDownLatch(1);
            AtomicReference<Throwable> queuedError = new AtomicReference<>();
            Thread queuedThread = new Thread(() -> { started.countDown(); try { put(client, queued, new BinaryCancellation()); } catch (Throwable error) { queuedError.set(error); } });
            queuedThread.start(); check(started.await(1, TimeUnit.SECONDS), "waiter absent"); Thread.sleep(50); queued[3] = '7';
            release.countDown(); firstThread.join(3000);
            check(firstError.get() == null, "first admitted call failed");
            // second connection starts only after the first releases its owned guard.
            queuedThread.join(3000); check(!queuedThread.isAlive() && queuedError.get() == null, "queued call failed");
            check(Arrays.equals(received.get(), queued), "source was copied before slot admission");
            check(watchdogs() == 0, "admission timer leaked");
        } finally { release.countDown(); }
        for (int i = 0; i < 4; i++) {
            CountDownLatch dispatched = new CountDownLatch(1);
            try (Peer peer = new Peer((socket, n) -> { hello(socket); upload(socket); dispatched.countDown(); try { socket.getInputStream().read(); } catch (IOException expected) { /* cancelled */ } })) {
                BinaryCancellation signal = new BinaryCancellation();
                Thread cancel = new Thread(() -> { try { if (dispatched.await(2, TimeUnit.SECONDS)) signal.cancel(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); } });
                cancel.start();
                try { fails(() -> put(peer.client(Duration.ofSeconds(3), 1), bytes("a: 1\n"), signal), BinaryException.Kind.CANCELLED, true); }
                finally { cancel.join(3000); }
                check(watchdogs() == 0, "cancellation timer leaked");
            }
        }
        check(descriptors() <= beforeDescriptors, "binary operation leaked descriptors");
    }
    static void admissionAndCancellation() throws Exception {
        for (String phase : List.of("tls", "hello", "upload", "response")) {
            CountDownLatch entered = new CountDownLatch(1);
            try (Peer peer = new Peer((socket, n) -> {
                if (phase.equals("tls")) { entered.countDown(); Thread.sleep(400); return; }
                if (phase.equals("hello")) {
                    socket.startHandshake(); BinaryFrameCodec.read(socket.getInputStream(), 4096); entered.countDown();
                } else {
                    hello(socket);
                    if (phase.equals("response")) upload(socket);
                    else { Frame request = BinaryFrameCodec.read(socket.getInputStream(), 4096); check(request.type() == REQUEST, "upload request absent"); }
                    entered.countDown();
                }
                try { while (socket.getInputStream().read() >= 0) { /* cancellation closes only this stream */ } } catch (IOException expected) { /* close */ }
            })) {
                BinaryCancellation signal = new BinaryCancellation();
                Thread trigger = new Thread(() -> { try { if (entered.await(2, TimeUnit.SECONDS)) signal.cancel(); } catch (InterruptedException error) { Thread.currentThread().interrupt(); } });
                trigger.start();
                try {
                    byte[] source = phase.equals("upload") ? new byte[BinaryClient.MAX_SOURCE] : bytes("a: 1\n");
                    fails(() -> put(peer.client(Duration.ofSeconds(3), 1), source, signal), BinaryException.Kind.CANCELLED,
                            phase.equals("upload") || phase.equals("response"));
                } finally { trigger.join(3000); }
                check(watchdogs() == 0, "phase cancellation leaked watchdog");
            }
        }
        // Four admitted calls hold all slots, while a fifth cancellation creates no
        // socket, source snapshot, watchdog or callback registration.
        try (Peer peer = new Peer((socket, n) -> {
            try { socket.startHandshake(); while (socket.getInputStream().read() >= 0) { /* await cancellation */ } }
            catch (IOException expected) { /* queued handshake closed by owner */ }
        })) {
            BinaryClient client = peer.client(Duration.ofSeconds(3), 4);
            List<Thread> callers = new java.util.ArrayList<>();
            List<BinaryCancellation> signals = new java.util.ArrayList<>();
            AtomicReference<Throwable> error = new AtomicReference<>();
            try {
                for (int i = 0; i < 4; i++) {
                    BinaryCancellation signal = new BinaryCancellation(); signals.add(signal);
                    Thread thread = new Thread(() -> {
                        try { put(client, bytes("a: 1\n"), signal); error.compareAndSet(null, new AssertionError("cancelled admitted call succeeded")); }
                        catch (BinaryException failure) { if (failure.kind() != BinaryException.Kind.CANCELLED) error.compareAndSet(null, failure); }
                    });
                    callers.add(thread); thread.start();
                }
                long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
                while (watchdogs() != 4 && System.nanoTime() < until) Thread.sleep(5);
                check(watchdogs() == 4, "four-call admission not reached");
                BinaryCancellation fifth = new BinaryCancellation();
                Thread trigger = new Thread(() -> { try { Thread.sleep(80); fifth.cancel(); } catch (InterruptedException stopped) { Thread.currentThread().interrupt(); } });
                trigger.start();
                try { fails(() -> put(client, new byte[BinaryClient.MAX_SOURCE], fifth), BinaryException.Kind.CANCELLED, false); }
                finally { trigger.join(1000); }
                check(watchdogs() == 4, "fifth call bypassed admission");
            } finally {
                signals.forEach(BinaryCancellation::cancel);
                for (Thread thread : callers) { thread.join(3000); check(!thread.isAlive(), "admitted caller leaked"); }
            }
            check(error.get() == null, "admitted cancellation failed: " + error.get());
            check(watchdogs() == 0, "four-call admission leaked timers"); cases++;
        }
    }

    static void operationsHello(SSLSocket socket) throws Exception { operationsHello(socket, 1); }
    static void operationsHello(SSLSocket socket, int minimum) throws Exception {
        socket.startHandshake(); var hello=BinaryFrameCodec.read(socket.getInputStream(),4096);
        check(hello.type()==HELLO && ByteBuffer.wrap(hello.payload()).getShort(2)==2,"operations negotiation missing");
        socket.getOutputStream().write(raw(HELLO,0,ByteBuffer.allocate(12).putShort((short)minimum).putShort((short)2).putInt(4096).putInt(1).array()));
    }
    static byte[] operationMetadata(byte[] body,boolean stream,String id) {
        var fields=fields(200,stream?0:body.length,stream?0:body.length,stream?"application/x-ndjson":"application/json",id);
        fields.put(13,new byte[]{(byte)(stream?1:0)});byte[] wire=meta(fields);wire[1]=2;return wire;
    }
    static void operationsPeer() throws Exception {
        byte[] body=bytes("{\"revision\":\""+REV+"\",\"documents\":[]}");
        try(Peer peer=new Peer((socket,n)->{operationsHello(socket,2);try { upload(socket); } catch(java.io.EOFException closed) { return; }socket.getOutputStream().write(raw(RESPONSE,1,operationMetadata(body,false,ID)));socket.getOutputStream().write(raw(DATA,1,body));socket.getOutputStream().write(raw(END,1,new byte[0]));})) {
            try { check(peer.client(Duration.ofSeconds(2),1).operation("POST","/v1/query/config","application/json",bytes("{}"),READ,null,null,ID,new BinaryCancellation()).status()==200,"schema2-only peer status"); }
            catch(BinaryException error) { throw new AssertionError("schema2-only peer rejected",error); } cases++;
        }
    }
    static void operationsCount() throws Exception {
        byte[] source=bytes("{\"operations\":[{\"collection\":\"config\",\"document\":\"one\",\"put\":\"n: 1\\n\"}]}");
        byte[] body=bytes("{\"status\":\"committed\",\"operations\":2,\"revision\":\""+REV+"\"}");
        try(Peer peer=new Peer((socket,n)->{operationsHello(socket);check(Arrays.equals(upload(socket),source),"transaction specification changed");socket.getOutputStream().write(raw(RESPONSE,1,operationMetadata(body,false,ID)));socket.getOutputStream().write(raw(DATA,1,body));socket.getOutputStream().write(raw(END,1,new byte[0]));})) {
            try { peer.client(Duration.ofSeconds(2),1).operation("POST","/v1/transactions","application/json",source,WRITE,null,null,ID,new BinaryCancellation());throw new AssertionError("transaction count mismatch accepted"); }
            catch(BinaryOperationException error) { check(error.kind()==BinaryException.Kind.PROTOCOL&&error.uncertain()&&Arrays.equals(error.envelope().source(),source),"transaction count uncertainty lost");cases++; }
        }
    }
    static void operations() throws Exception {
        String mapping="{\"deep\":"+"{\"n\":".repeat(63)+"{}"+"}".repeat(64);
        for(String value:List.of("{\"value\":"+"[".repeat(64)+"0"+"]".repeat(64)+"}",mapping,"{\"edge\":["+mapping+"]}")) {
            byte[] edge=bytes("{\"revision\":\""+REV+"\",\"documents\":["+value+"]}");
            try(Peer peer=new Peer((socket,n)->{operationsHello(socket);upload(socket);socket.getOutputStream().write(raw(RESPONSE,1,operationMetadata(edge,false,ID)));socket.getOutputStream().write(raw(DATA,1,edge));socket.getOutputStream().write(raw(END,1,new byte[0]));})) {
                byte[] actual=null;
                try { actual=peer.client(Duration.ofSeconds(2),1).operation("POST","/v1/query/config","application/json",bytes("{}"),READ,null,null,ID,new BinaryCancellation()).body(); }
                catch(BinaryException failure) { check(false,"native domain edge response was rejected: "+failure.kind()); }
                check(Arrays.equals(actual,edge),"deep response bytes changed");cases++;
            }
        }
        try { Json.parse("{\"v\":"+"[".repeat(64)+"0"+"]".repeat(64)+"}");throw new AssertionError("ordinary JSON depth changed"); }
        catch(IllegalArgumentException expected) { cases++; }
        for(String value:List.of("[".repeat(80)+"0"+"]".repeat(80),"1,\"v\":2","\"invalid\"")) {
            byte[] invalid=bytes("{\"revision\":\""+REV+"\",\"v\":"+value+"}");
            if(value.equals("\"invalid\"")) invalid[invalid.length-3]=(byte)255;
            try(Peer peer=new Peer((socket,n)->{operationsHello(socket);upload(socket);socket.getOutputStream().write(raw(RESPONSE,1,operationMetadata(invalid,false,ID)));socket.getOutputStream().write(raw(DATA,1,invalid));socket.getOutputStream().write(raw(END,1,new byte[0]));})) {
                try { peer.client(Duration.ofSeconds(2),1).operation("POST","/v1/query/config","application/json",bytes("{}"),READ,null,null,ID,new BinaryCancellation());throw new AssertionError("response JSON guard changed"); }
                catch(BinaryOperationException expected) { check(expected.kind()==BinaryException.Kind.PROTOCOL,"wrong response JSON failure");cases++; }
            }
        }
        byte[] domain=bytes("{\"operations\":[{}],\"v\":"+"[".repeat(64)+"0"+"]".repeat(64)+"}");
        byte[] committedDomain=bytes("{\"status\":\"committed\",\"operations\":1,\"revision\":\""+REV+"\"}");
        try(Peer peer=new Peer((socket,n)->{operationsHello(socket);upload(socket);socket.getOutputStream().write(raw(RESPONSE,1,operationMetadata(committedDomain,false,ID)));socket.getOutputStream().write(raw(DATA,1,committedDomain));socket.getOutputStream().write(raw(END,1,new byte[0]));})) {
            try { peer.client(Duration.ofSeconds(2),1).operation("POST","/v1/transactions","application/json",domain,WRITE,null,null,ID,new BinaryCancellation());throw new AssertionError("transaction domain depth changed"); }
            catch(BinaryOperationException expected) { check(expected.kind()==BinaryException.Kind.PROTOCOL&&expected.uncertain(),"transaction domain uncertainty lost");cases++; }
        }
        byte[] spec=bytes("{\"limit\":1,\"filter\":{\"n\":9007199254740993}}");
        byte[] body=bytes("{\"revision\":\""+REV+"\",\"documents\":[{\"n\":9007199254740993}]}");
        try(Peer peer=new Peer((socket,n)->{operationsHello(socket);check(Arrays.equals(upload(socket),spec),"operation specification changed");socket.getOutputStream().write(raw(RESPONSE,1,operationMetadata(body,false,ID)));socket.getOutputStream().write(raw(DATA,1,body));socket.getOutputStream().write(raw(END,1,new byte[0]));})) {
            var response=peer.client(Duration.ofSeconds(2),1).operation("POST","/v1/query/config","application/json",spec,READ,null,null,ID,new BinaryCancellation());
            check(Arrays.equals(response.body(),body),"numeric response spelling lost");cases++;
        }
        byte[] patched=receipt("1111111111111111");
        try(Peer peer=new Peer((socket,n)->{operationsHello(socket);upload(socket);var f=fields(200,patched.length,patched.length,"application/json",ID);f.put(6,bytes("\"1111111111111111\""));f.put(7,bytes("config"));f.put(8,bytes("one"));f.put(13,new byte[]{0});byte[] wire=meta(f);wire[1]=2;socket.getOutputStream().write(raw(RESPONSE,1,wire));socket.getOutputStream().write(raw(DATA,1,patched));socket.getOutputStream().write(raw(END,1,new byte[0]));})) {
            var result=peer.client(Duration.ofSeconds(2),1).operation("PATCH","/v1/collections/config/documents/one","application/json",bytes("{\"$inc\":{\"n\":1}}"),WRITE,null,null,ID,new BinaryCancellation());
            check(Arrays.equals(result.body(),patched),"PATCH hashed its specification");cases++;
        }
        try(Peer peer=new Peer((socket,n)->{hello(socket);check(socket.getInputStream().read()==-1,"unsupported peer received REQUEST");})) {
            try { peer.client(Duration.ofSeconds(2),1).operation("POST","/v1/transactions","application/json",spec,WRITE,"",null,ID,new BinaryCancellation());throw new AssertionError("unsupported peer accepted"); }
            catch(BinaryUnsupportedPeerException expected){cases++;}
        }
        byte[] txSpec=bytes("{\"operations\":[{\"collection\":\"config\",\"document\":\"one\",\"put\":\"n: 9007199254740993\\n\"}]}");
        byte[] committed=bytes("{\"status\":\"committed\",\"operations\":1,\"revision\":\""+REV+"\"}");
        for(String fault:List.of("id","mode","schema")) {
            try(Peer peer=new Peer((socket,n)->{operationsHello(socket);upload(socket);byte[] wire=operationMetadata(committed,false,fault.equals("id")?"ff".repeat(16):ID);if(fault.equals("mode"))wire[wire.length-1]=2;if(fault.equals("schema"))wire[1]=1;socket.getOutputStream().write(raw(RESPONSE,1,wire));socket.getOutputStream().write(raw(DATA,1,committed));socket.getOutputStream().write(raw(END,1,new byte[0]));})) {
                try { peer.client(Duration.ofSeconds(2),1).operation("POST","/v1/transactions","application/json",txSpec,WRITE,"",null,ID,new BinaryCancellation());throw new AssertionError("operation guard accepted "+fault); }
                catch(BinaryOperationException failure){check(failure.kind()==BinaryException.Kind.PROTOCOL && failure.uncertain(),"operation uncertainty lost");var original=failure.envelope();check(original.method().equals("POST")&&original.target().equals("/v1/transactions")&&original.contentType().equals("application/json")&&original.ifMatch().equals("")&&original.ifNoneMatch()==null&&original.requestId().equals(ID)&&Arrays.equals(original.source(),txSpec),"recovery envelope changed");var copy=original.source();copy[0]^=1;check(!Arrays.equals(copy,original.source()),"borrowed operation source");cases++;}
            }
        }
        String prefix="v1."+"a".repeat(32)+".", a=prefix+"0000000000000001", b=prefix+"0000000000000002", c=prefix+"0000000000000003";
        byte[] page=bytes("{\"transactions\":[{\"token\":\""+b+"\",\"previous_revision\":\"0000000000000001\",\"revision\":\"0000000000000002\",\"resnapshot_required\":false,\"operations\":[{\"collection\":\"config\",\"document\":\"one\",\"put\":\"n: 9007199254740993\\r\\n\"}]}],\"next_after\":\""+b+"\",\"oldest_after\":\""+a+"\",\"checkpoint\":\""+c+"\",\"revision\":\""+REV+"\",\"has_more\":true}\n");
        byte[] terminal=bytes("{\"terminal\":true,\"status\":503,\"after\":\""+b+"\",\"detail\":{\"error\":\"unavailable\"}}\n");
        for(boolean partial:List.of(false,true)) {
            var pages=new java.util.ArrayList<byte[]>();
            try(Peer peer=new Peer((socket,n)->{operationsHello(socket);upload(socket);socket.getOutputStream().write(raw(RESPONSE,1,operationMetadata(new byte[0],true,ID)));socket.getOutputStream().write(raw(DATA,1,page));socket.getOutputStream().write(raw(DATA,1,partial?bytes("{\"unfinished\":"):terminal));if(!partial)socket.getOutputStream().write(raw(END,1,new byte[0]));})) {
                try { var feed=peer.client(Duration.ofSeconds(2),1).feed("/v1/changes/stream?after="+a,READ,ID,new BinaryCancellation(),pages::add);check(!partial&&feed.lastAfter().equals(b),"feed used checkpoint as cursor"); }
                catch(BinaryOperationException failure){check(partial&&!failure.uncertain()&&failure.lastAfter().equals(b)&&failure.response()!=null,"incomplete page advanced cursor");}
                check(pages.size()==(partial?1:2)&&Arrays.equals(pages.get(0),page)&& (partial||Arrays.equals(pages.get(1),terminal)),"feed rewrote/rounded/unvalidated page");cases++;
            }
        }
    }
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory(Path.of(System.getProperty("java.io.tmpdir")), "binary-contract-");
        certs = root;
        try {
            NativeTests.certificates(root);
            server = Tls.trustPem(root.resolve("ca.pem"), root.resolve("server.p12"), "test-only-password".toCharArray());
            ProxySelector previous = ProxySelector.getDefault();
            ProxySelector.setDefault(new ProxySelector() {
                @Override public List<java.net.Proxy> select(java.net.URI uri) { throw new AssertionError("binary proxy consulted"); }
                @Override public void connectFailed(java.net.URI uri, java.net.SocketAddress address, IOException failure) { throw new AssertionError("binary proxy used"); }
            });
            try {
                switch (System.getProperty("yamora.binary.group", "all")) {
                    case "operations-peer" -> operationsPeer(); case "operations-count" -> operationsCount(); case "operations" -> { operationsPeer(); operationsCount(); operations(); } case "codec" -> codec(); case "capacity" -> peerCapacity(); case "hash" -> sourceHashes(); case "hostile" -> hostile(); case "deadline" -> { deadlines(); admissionAndCancellation(); } case "tls" -> tls();
                    case "all" -> { operationsPeer(); operationsCount(); operations(); codec(); peerCapacity(); tls(); hostile(); sourceHashes(); deadlines(); admissionAndCancellation(); }
                    default -> throw new IllegalArgumentException("unknown binary group");
                }
            } finally { ProxySelector.setDefault(previous); }
        } finally {
            try (var paths = Files.walk(root)) { for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path); }
        }
        System.out.println("Java binary contracts passed: " + cases + " cases, " + assertions + " assertions");
    }
}
