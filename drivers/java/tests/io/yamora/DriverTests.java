package io.yamora;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Executable contract tests, no test framework or network dependency. */
public final class DriverTests {
    static final String REV = "0123456789abcdef";
    static final String READ = "r".repeat(32);
    static final String WRITE = "w".repeat(32);
    static int assertions;
    private DriverTests() {}

    @FunctionalInterface interface Action { void run() throws Exception; }
    @FunctionalInterface interface Responder { void handle(Socket socket) throws Exception; }

    static void check(boolean condition, String detail) {
        assertions++;
        if (!condition) throw new AssertionError(detail);
    }
    static void invalid(Action action) throws Exception {
        try { action.run(); throw new AssertionError("accepted invalid input"); }
        catch (IllegalArgumentException expected) { assertions++; }
    }
    static YamoraException failure(Action action, YamoraException.Kind kind) throws Exception {
        try { action.run(); throw new AssertionError("accepted failed operation"); }
        catch (YamoraException expected) { check(expected.kind() == kind, "wrong failure kind: " + expected); return expected; }
    }
    static void status(Action action, int status) throws Exception {
        YamoraException failure = failure(action, YamoraException.Kind.HTTP);
        check(failure.status() == status, "wrong HTTP status");
        if (status != 408 && status < 500) check(!failure.outcomeUncertain(), "definite rejection marked uncertain");
    }
    static byte[] bytes(String text) { return text.getBytes(StandardCharsets.UTF_8); }
    static String wire(int status, String media, String body) {
        return "HTTP/1.1 " + status + " Result\r\nContent-Length: " + bytes(body).length + "\r\n"
                + "Content-Type: " + media + "\r\nX-YamlDB-Revision: " + REV + "\r\n\r\n" + body;
    }

    static final class Peer implements AutoCloseable {
        final ServerSocket listener;
        final Thread thread;
        final AtomicInteger accepted = new AtomicInteger();
        final AtomicReference<Throwable> error = new AtomicReference<>();
        volatile boolean closed;
        Peer(Responder responder) throws IOException {
            listener = new ServerSocket(0, 10, InetAddress.getByName("127.0.0.1"));
            check(listener.getLocalPort() != 8000, "reserved port selected");
            thread = new Thread(() -> {
                try {
                    while (!closed) {
                        try (Socket socket = listener.accept()) {
                            accepted.incrementAndGet();
                            socket.setSoTimeout(2000);
                            responder.handle(socket);
                        }
                    }
                } catch (SocketException expected) {
                    if (!closed) error.set(expected);
                } catch (Throwable unexpected) { error.set(unexpected); }
            }, "yamora-test-peer");
            thread.setDaemon(true);
            thread.start();
        }
        YamoraClient client() { return client(1024 * 1024, Duration.ofSeconds(2)); }
        YamoraClient client(int responseLimit, Duration timeout) {
            return new YamoraClient("127.0.0.1", listener.getLocalPort(), READ, WRITE, null,
                    timeout, YamoraClient.MAX_REQUEST_BYTES, responseLimit);
        }
        @Override public void close() throws IOException {
            closed = true;
            listener.close();
            try { thread.join(3000); }
            catch (InterruptedException failure) { Thread.currentThread().interrupt(); throw new IOException(failure); }
            check(!thread.isAlive(), "peer did not stop");
            if (error.get() != null) throw new AssertionError("peer failed", error.get());
        }
    }

    static byte[] request(Socket socket) throws IOException {
        InputStream input = socket.getInputStream();
        ByteArrayOutputStream header = new ByteArrayOutputStream();
        int state = 0;
        while (state < 4) {
            int next = input.read();
            if (next < 0 || header.size() > 8192) throw new IOException("bad request");
            header.write(next);
            int expected = state % 2 == 0 ? '\r' : '\n';
            state = next == expected ? state + 1 : (next == '\r' ? 1 : 0);
        }
        String headers = header.toString(StandardCharsets.US_ASCII);
        int length = 0;
        for (String line : headers.split("\r\n")) {
            if (line.startsWith("Content-Length: ")) length = Integer.parseInt(line.substring(16));
        }
        byte[] body = input.readNBytes(length);
        if (body.length != length) throw new IOException("short request");
        header.write(body);
        return header.toByteArray();
    }

    static void validation() throws Exception {
        for (String host : new String[]{"localhost", "::1", "[::1]", "8.8.8.8", "0.0.0.0", "169.254.169.254",
                "127.1", "0177.0.0.1", "127.00.0.1", "127.0.0.256", "127.0.0.1/path", "http://127.0.0.1",
                "user@127.0.0.1", "127.0.0.1?x", "127.0.0.1\r\n", "", null}) {
            invalid(() -> new YamoraClient(host, 12345, READ, WRITE, null));
        }
        for (int port : new int[]{0, -1, 65536}) invalid(() -> new YamoraClient("127.0.0.1", port, READ, WRITE, null));
        for (String host : new String[]{"127.0.0.2", "10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.2"}) {
            new YamoraClient(host, 12345, "", "", null);
        }
        for (String token : new String[]{"short", "x".repeat(513), " ".repeat(32), "x".repeat(31) + "\r",
                "x".repeat(31) + "\u007f", "é".repeat(32), null}) {
            invalid(() -> new YamoraClient("127.0.0.1", 12345, token, WRITE, null));
            invalid(() -> new YamoraClient("127.0.0.1", 12345, READ, token, null));
        }
        YamoraClient client = new YamoraClient("127.0.0.1", 12345, READ, WRITE, null);
        for (String id : new String[]{"../escape", "a/b", "a%2fb", "a?x=1", "a#x", ".", "Upper", "é", "", "x".repeat(129)}) {
            invalid(() -> client.get(id, "one", null));
            invalid(() -> client.get("examples", id, null));
        }
        invalid(() -> client.put("yamldb-system", "indexes", bytes("value: 1\n"), YamoraClient.WriteOptions.NONE));
        invalid(() -> new YamoraClient.WriteOptions(REV, true, null));
        invalid(() -> new YamoraClient.WriteOptions("\"" + REV + "\"", false, null));
        invalid(() -> new YamoraClient.WriteOptions(null, false, "0".repeat(32)));
        invalid(() -> client.documentPage("examples", 1, "one", null));
        invalid(() -> client.query("examples", "{\"after\":\"one\"}"));
        invalid(() -> client.changes("bad&limit=1", 1));
        invalid(() -> client.put("examples", "one", new byte[]{(byte) 0xc0, (byte) 0x80}, YamoraClient.WriteOptions.NONE));
        invalid(() -> client.put("examples", "one", new byte[YamoraClient.MAX_DOCUMENT_BYTES + 1], YamoraClient.WriteOptions.NONE));
        invalid(() -> client.patch("examples", "one", "{}", YamoraClient.WriteOptions.NONE));
        invalid(() -> client.transaction("{\"operations\":[]}", null));
        invalid(() -> client.transaction("{\"operations\":[{\"collection\":\"examples\",\"document\":\"one\",\"delete\":false}]}", null));
        for (Duration duration : new Duration[]{Duration.ZERO, Duration.ofSeconds(31), Duration.ofMillis(-1)}) {
            invalid(() -> new YamoraClient("127.0.0.1", 12345, READ, WRITE, null, duration, 1, 1));
        }
    }

    static void jsonCodec() throws Exception {
        String input = "{\"n\":9223372036854775807,\"u\":18446744073709551615,\"precise\":9007199254740993,"
                + "\"decimal\":1.2300e+4,\"sort\":{\"z\":1,\"a\":-1},\"null\":null,\"text\":\"😀\"}";
        Map<String, Object> parsed = Json.object(input);
        check(Json.stringify(parsed).equals(input), "number tokens or map order changed");
        check(((Json.NumberValue) parsed.get("n")).longValueExact() == Long.MAX_VALUE, "integer precision");
        check(((Json.NumberValue) parsed.get("precise")).longValueExact() == 9007199254740993L, "integer rounded through double");
        check(Json.stringify(Json.parse("\"a\u0085b\u2028c\u2029d\"")).equals("\"a\\u0085b\\u2028c\\u2029d\""), "YAML line separators not escaped");
        for (String source : new String[]{"{\"a\":null,\"a\":2}", "{\"a\":1,}", "[1,]", "01", "NaN", "1e", "true false",
                "\"\\ud800\"", "\"\\udc00\"", "\"\uD800\"", "\"a\nb\"", "{\"a\":}", "\"\\u１２３４\"",
                "[".repeat(66) + "0" + "]".repeat(66), "1".repeat(1025)}) invalid(() -> Json.parse(source));
        invalid(() -> Json.parse("[" + "0,".repeat(100_000) + "0]"));
        invalid(() -> Json.stringify(Map.of("lossy", 1.0d)));
        invalid(() -> Json.stringify(Map.of("bad", "\uD800")));
        try { parsed.put("changed", true); throw new AssertionError("mutable JSON"); }
        catch (UnsupportedOperationException expected) { assertions++; }
    }

    static void authoredSourceAndAuth() throws Exception {
        java.net.ProxySelector previous = java.net.ProxySelector.getDefault();
        java.net.ProxySelector.setDefault(new java.net.ProxySelector() {
            @Override public java.util.List<java.net.Proxy> select(java.net.URI uri) {
                throw new AssertionError("JVM proxy selector consulted");
            }
            @Override public void connectFailed(java.net.URI uri, java.net.SocketAddress address, IOException failure) {
                throw new AssertionError("proxy attempted");
            }
        });
        try { sourceAndAuth(); }
        finally { java.net.ProxySelector.setDefault(previous); }
    }

    private static void sourceAndAuth() throws Exception {
        byte[] authored = bytes("# exact café\r\nname: first\r\nn: 9007199254740993\r\n");
        AtomicReference<byte[]> received = new AtomicReference<>();
        String mutation = "{\"status\":\"stored\",\"collection\":\"examples\",\"document\":\"one\",\"etag\":\"" + REV
                + "\",\"revision\":\"" + REV + "\"}";
        try (Peer peer = new Peer(socket -> {
            received.set(request(socket));
            socket.getOutputStream().write(bytes(wire(201, "application/json", mutation)));
        })) {
            peer.client().put("examples", "one", authored, new YamoraClient.WriteOptions(null, true, "1".repeat(32)));
            byte[] request = received.get();
            String headers = new String(request, StandardCharsets.UTF_8);
            check(headers.startsWith("PUT /v1/collections/examples/documents/one HTTP/1.1\r\n"), "PUT target");
            check(headers.contains("Authorization: Bearer " + WRITE + "\r\n"), "write credential");
            check(headers.contains("If-None-Match: *\r\n"), "create precondition");
            check(headers.contains("X-Yamora-Request-Id: " + "1".repeat(32) + "\r\n"), "request identity");
            check(Arrays.equals(Arrays.copyOfRange(request, request.length - authored.length, request.length), authored), "authored bytes changed");
        }
        try (Peer peer = new Peer(socket -> {
            String request = new String(request(socket), StandardCharsets.UTF_8);
            check(request.contains("Authorization: Bearer " + READ + "\r\n"), "query must use read credential");
            check(request.contains("\\u0085"), "NEL reaches YAML parser literally");
            socket.getOutputStream().write(bytes(wire(200, "application/json", "{}")));
        })) { peer.client().query("examples", "{\"filter\":{\"name\":\"a\u0085b\"}}"); }
    }

    static void hostileResponses() throws Exception {
        for (int code : new int[]{301, 302, 303, 307, 308}) {
            try (Peer peer = new Peer(socket -> {
                request(socket);
                socket.getOutputStream().write(bytes("HTTP/1.1 " + code + " Redirect\r\nLocation: http://127.0.0.1:1/steal\r\nContent-Length: 0\r\n\r\n"));
            })) {
                YamoraException failure = failure(() -> peer.client().health(), YamoraException.Kind.HTTP);
                check(failure.status() == code, "redirect status lost");
                check(peer.accepted.get() == 1, "redirect replayed");
            }
        }
        for (String wire : new String[]{
                "HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n{}",
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}EXTRA",
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Encoding: gzip\r\n\r\n{}",
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
                "HTTP/1.1 200 OK\nContent-Length: 2\n\n{}",
                "HTTP/1.1 200 OK\r\nX-Large: " + "x".repeat(17 * 1024) + "\r\n\r\n",
                wire(200, "text/html", "{}"), wire(200, "application/json", "{\"n\":1,\"n\":2}"),
                wire(200, "application/json", "{\"revision\":\"ffffffffffffffff\"}"),
                wire(200, "application/json", "{}").replace("X-YamlDB-Revision: " + REV + "\r\n", "")}) {
            try (Peer peer = new Peer(socket -> { request(socket); socket.getOutputStream().write(bytes(wire)); })) {
                failure(() -> peer.client().health(), YamoraException.Kind.PROTOCOL);
            }
        }
        try (Peer peer = new Peer(socket -> {
            request(socket);
            socket.getOutputStream().write(bytes("HTTP/1.1 200 OK\r\nContent-Length: 129\r\n\r\n"));
        })) { failure(() -> peer.client(128, Duration.ofSeconds(1)).health(), YamoraException.Kind.PROTOCOL); }
        try (Peer peer = new Peer(socket -> {
            request(socket);
            socket.getOutputStream().write(bytes(wire(200, "application/yaml", "name: first\n")
                    .replace("\r\n\r\n", "\r\nETag: invalid\r\n\r\n")));
        })) { failure(() -> peer.client().get("examples", "one", null), YamoraException.Kind.PROTOCOL); }
        try (Peer peer = new Peer(socket -> {
            request(socket);
            socket.getOutputStream().write(bytes(wire(412, "application/json", "private body " + WRITE)));
        })) {
            YamoraException failure = failure(() -> peer.client().put("examples", "one", bytes("v: 1\n"),
                    YamoraClient.WriteOptions.NONE), YamoraException.Kind.HTTP);
            check(failure.status() == 412 && !failure.toString().contains(WRITE), "error leaks body/token");
        }
    }

    static void noReplay() throws Exception {
        for (String method : new String[]{"PUT", "PATCH", "DELETE", "POST"}) {
            try (Peer peer = new Peer(socket -> { request(socket); /* commit then lose the acknowledgement */ })) {
                YamoraClient client = peer.client();
                YamoraException failure = failure(() -> {
                    switch (method) {
                        case "PUT" -> client.put("examples", "one", bytes("v: 1\n"), YamoraClient.WriteOptions.NONE);
                        case "PATCH" -> client.patch("examples", "one", "{\"$inc\":{\"v\":1}}", YamoraClient.WriteOptions.NONE);
                        case "DELETE" -> client.delete("examples", "one", YamoraClient.WriteOptions.NONE);
                        default -> client.transaction("{\"operations\":[{\"collection\":\"examples\",\"document\":\"one\",\"delete\":true}]}", null);
                    }
                }, YamoraException.Kind.PROTOCOL);
                check(failure.outcomeUncertain(), "lost acknowledgement incorrectly definite");
                check(peer.accepted.get() == 1, method + " automatically replayed");
            }
        }
    }

    static void deadlinesAndInterruption() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch received = new CountDownLatch(1);
        try (Peer peer = new Peer(socket -> {
            request(socket);
            socket.getOutputStream().write(bytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\nX-YamlDB-Revision: " + REV + "\r\n\r\n{"));
            received.countDown();
            release.await(2, TimeUnit.SECONDS);
        })) {
            try {
                long start = System.nanoTime();
                failure(() -> peer.client(1024, Duration.ofMillis(150)).health(), YamoraException.Kind.TRANSPORT);
                check(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 1500, "body not covered by absolute deadline");
            } finally { release.countDown(); }
        }
        CountDownLatch writeRelease = new CountDownLatch(1);
        try (Peer peer = new Peer(socket -> { socket.setReceiveBufferSize(1024); writeRelease.await(3, TimeUnit.SECONDS); })) {
            try {
                YamoraClient client = peer.client(1024, Duration.ofMillis(200));
                byte[] large = bytes("value: " + "x".repeat(8 * 1024 * 1024));
                long start = System.nanoTime();
                YamoraException failure = failure(() -> client.put("examples", "blocked", large, YamoraClient.WriteOptions.NONE),
                        YamoraException.Kind.TRANSPORT);
                check(failure.outcomeUncertain(), "blocked write lost uncertainty");
                check(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 2000, "writes escape deadline");
            } finally { writeRelease.countDown(); }
        }
        CountDownLatch handshakeRelease = new CountDownLatch(1);
        try (Peer peer = new Peer(socket -> handshakeRelease.await(3, TimeUnit.SECONDS))) {
            try {
                YamoraClient client = new YamoraClient("127.0.0.1", peer.listener.getLocalPort(), READ, WRITE,
                        Tls.systemTrust(), Duration.ofMillis(150), 1024, 1024);
                long start = System.nanoTime();
                failure(client::ready, YamoraException.Kind.TRANSPORT);
                check(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 1500, "TLS handshake escapes deadline");
            } finally { handshakeRelease.countDown(); }
        }
        CountDownLatch block = new CountDownLatch(1);
        CountDownLatch started = new CountDownLatch(1);
        try (Peer peer = new Peer(socket -> { request(socket); started.countDown(); block.await(3, TimeUnit.SECONDS); })) {
            CompletableFuture<YamoraException> result = new CompletableFuture<>();
            Thread caller = new Thread(() -> {
                try { peer.client().health(); result.completeExceptionally(new AssertionError("interrupted call succeeded")); }
                catch (YamoraException expected) { result.complete(expected); }
            });
            caller.start();
            try {
                check(started.await(2, TimeUnit.SECONDS), "call not started");
                caller.interrupt();
                check(result.get(1, TimeUnit.SECONDS).kind() == YamoraException.Kind.TRANSPORT, "interrupt not delivered");
            } finally { block.countDown(); caller.join(3000); }
        }
    }

    static void replicationSourceGuard() throws Exception {
        for (String value : new String[] {"false", "null", "\"false\"", "\"true\"", "0", "1", "[]", "{}", "true", "absent", "nested"}) {
            String field = value.equals("absent") ? "" : value.equals("nested")
                    ? ",\"nested\":{\"replication_policy_free\":false}" : ",\"replication_policy_free\":" + value;
            String body = "{\"revision\":\"" + REV + "\"" + field + "}";
            try (Peer peer = new Peer(socket -> {
                check(new String(request(socket), StandardCharsets.UTF_8).startsWith("GET /readyz "), "guard dispatched mutation");
                socket.getOutputStream().write(bytes(wire(200, "application/json", body)));
            })) {
                if (value.equals("true") || value.equals("absent") || value.equals("nested")) {
                    check(peer.client().requireReplicationSource().json().equals(body), "readiness changed");
                } else {
                    var kind = value.equals("false") ? YamoraException.Kind.SCHEMA_POLICY_REPLICATION_UNSUPPORTED : YamoraException.Kind.PROTOCOL;
                    YamoraException error = failure(peer.client()::requireReplicationSource, kind);
                    check(!error.outcomeUncertain() && error.status() == (value.equals("false") ? 409 : 0), "guard certainty/status");
                }
                check(peer.accepted.get() == 1, "guard repeated source request");
            }
        }
    }

    public static void main(String[] arguments) throws Exception {
        String group = arguments.length == 0 ? "all" : arguments[0];
        switch (group) {
            case "validation" -> validation();
            case "json" -> jsonCodec();
            case "source" -> authoredSourceAndAuth();
            case "hostile" -> hostileResponses();
            case "replay" -> noReplay();
            case "deadlines" -> deadlinesAndInterruption();
            case "replication-source" -> replicationSourceGuard();
            case "all" -> { validation(); jsonCodec(); authoredSourceAndAuth(); hostileResponses(); noReplay(); deadlinesAndInterruption(); replicationSourceGuard(); }
            default -> throw new IllegalArgumentException("unknown test group");
        }
        System.out.println("Java HTTP contract tests passed: " + assertions + " assertions (" + group + ")");
    }
}
