package io.yamora;

import static io.yamora.DriverTests.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ProxySelector;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLServerSocket;

/** HTTPS boundary faults use real JSSE sockets; native replay is separately verified. */
public final class ClusterTests {
    private ClusterTests() {}
    static Tls trusted;
    static Tls server;
    static final String LEADER = "{\"node\":1,\"leader\":1,\"term\":1,\"role\":\"leader\"}";
    static final String STORED = "{\"status\":\"stored\",\"collection\":\"examples\",\"document\":\"one\",\"etag\":\""
            + REV + "\",\"revision\":\"" + REV + "\"}";
    static final String COMMITTED = "{\"status\":\"committed\",\"operations\":1,\"revision\":\"" + REV + "\"}";
    static final byte[] SOURCE = bytes("# exact café\r\ncount: 0 # keep\r\nn: 9223372036854775807\r\n");
    static final String TX = "{\"operations\":[{\"collection\":\"examples\",\"document\":\"one\",\"patch\":{\"$inc\":{\"count\":1}}}]}";
    static final String CATALOG = "{\"indexes\":[{\"collection\":\"examples\",\"name\":\"count\",\"fields\":[\"count\"]}]}";

    static final class TlsPeer implements AutoCloseable {
        final SSLServerSocket listener;
        final Thread acceptor;
        final ExecutorService workers = Executors.newFixedThreadPool(8);
        final Set<Socket> sockets = ConcurrentHashMap.newKeySet();
        final AtomicReference<Throwable> error = new AtomicReference<>();
        final AtomicInteger accepted = new AtomicInteger();
        volatile boolean closed;
        TlsPeer(Responder responder) throws IOException { this(server, responder); }
        TlsPeer(Tls identity, Responder responder) throws IOException {
            listener = (SSLServerSocket) identity.context().getServerSocketFactory()
                    .createServerSocket(0, 32, InetAddress.getByName("127.0.0.1"));
            listener.setEnabledProtocols(new String[]{"TLSv1.3"});
            check(listener.getLocalPort() != 8000, "owner port allocated");
            acceptor = new Thread(() -> {
                while (!closed) {
                    try {
                        Socket socket = listener.accept();
                        sockets.add(socket);
                        accepted.incrementAndGet();
                        workers.submit(() -> {
                            try (socket) { socket.setSoTimeout(4000); responder.handle(socket); }
                            catch (IOException expected) { /* client timeout/cancellation/negative TLS tests */ }
                            catch (InterruptedException expected) { Thread.currentThread().interrupt(); }
                            catch (Throwable failure) { error.compareAndSet(null, failure); }
                            finally { sockets.remove(socket); }
                        });
                    } catch (IOException failure) { if (!closed) error.compareAndSet(null, failure); }
                }
            }, "yamora-cluster-test-peer");
            acceptor.setDaemon(true);
            acceptor.start();
        }
        ClusterConfig.Seed seed() { return new ClusterConfig.Seed("127.0.0.1", listener.getLocalPort()); }
        @Override public void close() throws IOException {
            closed = true;
            listener.close();
            for (Socket socket : sockets) socket.close();
            workers.shutdownNow();
            try {
                acceptor.join(3000);
                check(workers.awaitTermination(3, TimeUnit.SECONDS) && !acceptor.isAlive(), "test peer leaked");
            } catch (InterruptedException failure) { Thread.currentThread().interrupt(); throw new IOException(failure); }
            if (error.get() != null) throw new AssertionError("TLS peer failed", error.get());
        }
    }

    static String text(byte[] value) { return new String(value, StandardCharsets.UTF_8); }
    static String first(byte[] value) { return text(value).split("\r\n", 2)[0]; }
    static String id(byte[] value) {
        for (String line : text(value).split("\r\n")) {
            if (line.startsWith("X-Yamora-Request-Id: ")) return line.substring(21);
        }
        return null;
    }
    static byte[] body(byte[] value) {
        int offset = text(value).indexOf("\r\n\r\n") + 4;
        return Arrays.copyOfRange(value, offset, value.length);
    }
    static boolean discovery(byte[] value) { return first(value).equals("GET /v1/cluster/leader HTTP/1.1"); }
    static void respond(Socket socket, String message) throws IOException { socket.getOutputStream().write(bytes(message)); }
    static YamoraClient client(List<ClusterConfig.Seed> seeds, Duration timeout, Duration attempt, int responseLimit) {
        return YamoraClient.replicaSet(new ClusterConfig(seeds, trusted, timeout, attempt,
                YamoraClient.MAX_REQUEST_BYTES, responseLimit), READ, WRITE);
    }
    static YamoraClient client(TlsPeer... peers) {
        return client(Arrays.stream(peers).map(TlsPeer::seed).toList(), Duration.ofSeconds(4), Duration.ofSeconds(1), 1 << 20);
    }
    static void operation(YamoraClient client, String method, String requestId) throws YamoraException {
        YamoraClient.WriteOptions options = new YamoraClient.WriteOptions(null, false, requestId);
        switch (method) {
            case "PUT" -> client.put("examples", "one", SOURCE, options);
            case "PATCH" -> client.patch("examples", "one", "{\"$inc\":{\"count\":1}}", options);
            case "DELETE" -> client.delete("examples", "one", options);
            case "TX" -> client.transaction(TX, requestId);
            case "CATALOG" -> client.setIndexes(CATALOG, null, requestId);
            default -> throw new AssertionError("unknown operation");
        }
    }
    static int successStatus(String operation) {
        return operation.equals("DELETE") ? 204 : operation.equals("PUT") ? 201 : 200;
    }
    static String successBody(String operation) {
        return switch (operation) {
            case "DELETE" -> "";
            case "TX", "CATALOG" -> COMMITTED;
            default -> STORED;
        };
    }
    static String success(String operation) {
        return wire(successStatus(operation), "application/json", successBody(operation));
    }

    static void configuration() throws Exception {
        for (String host : new String[]{"localhost", "127.1", "127.00.0.1", "::1", "8.8.8.8", "169.254.169.254",
                "https://127.0.0.1", "127.0.0.1/path", "127.0.0.1@10.0.0.1"}) invalid(() -> new ClusterConfig.Seed(host, 1234));
        ClusterConfig.Seed seed = new ClusterConfig.Seed("127.0.0.1", 1234);
        invalid(() -> new ClusterConfig(List.of(seed), null));
        invalid(() -> new ClusterConfig(List.of(), trusted));
        invalid(() -> new ClusterConfig(List.of(seed, seed), trusted));
        invalid(() -> new ClusterConfig(List.of(seed), trusted, Duration.ZERO, Duration.ofSeconds(1), 1, 1));
        invalid(() -> new ClusterConfig(List.of(seed), trusted, Duration.ofSeconds(1), Duration.ofSeconds(31), 1, 1));
        ArrayList<ClusterConfig.Seed> supplied = new ArrayList<>(List.of(seed));
        ClusterConfig config = new ClusterConfig(supplied, trusted);
        supplied.clear();
        check(config.seeds().equals(List.of(seed)), "caller changed trust set");
        try { config.seeds().clear(); throw new AssertionError("mutable configuration"); }
        catch (UnsupportedOperationException expected) { check(true, "immutable"); }
    }

    static void exactRetries() throws Exception {
        for (String method : List.of("PUT", "PATCH", "DELETE", "TX", "CATALOG")) {
            if (!System.getProperty("yamora.test.operation", method).equals(method)) continue;
            AtomicReference<byte[]> lost = new AtomicReference<>();
            AtomicReference<byte[]> retry = new AtomicReference<>();
            AtomicBoolean firstLeader = new AtomicBoolean(true);
            try (TlsPeer first = new TlsPeer(socket -> {
                byte[] request = request(socket);
                if (discovery(request)) respond(socket, wire(200, "application/json", LEADER).replace("\r\n\r\n",
                        "\r\nCache-Control: no-store\r\nCache-Control: no-store\r\n\r\n"));
                else { lost.set(request); firstLeader.set(false); /* lose acknowledgement */ }
            }); TlsPeer second = new TlsPeer(socket -> {
                byte[] request = request(socket);
                if (discovery(request)) {
                    respond(socket, wire(200, "application/json", firstLeader.get() ? LEADER.replace("leader\"}", "follower\"}") : LEADER));
                } else { retry.set(request); respond(socket, success(method)); }
            })) {
                operation(client(first, second), method, null);
                check(lost.get() != null && retry.get() != null, method + " did not fail over");
                check(text(lost.get()).replaceAll("Host: [^\\r]+", "Host: seed").equals(
                        text(retry.get()).replaceAll("Host: [^\\r]+", "Host: seed")), method + " changed request bytes/preconditions/ID");
                check(id(lost.get()).matches("[0-9a-f]{32}") && !id(lost.get()).equals("0".repeat(32)), "invalid generated ID");
                if (method.equals("PUT")) check(Arrays.equals(body(lost.get()), SOURCE), "YAML normalized");
            }
        }
    }

    static void ambiguousReceipts() throws Exception {
        for (String method : List.of("PUT", "PATCH", "DELETE", "TX", "CATALOG")) {
            if (!System.getProperty("yamora.test.operation", method).equals(method)) continue;
            for (String malformed : List.of(wire(500, "application/json", "private " + WRITE),
                    wire(202, "application/json", "{}"), wire(200, "application/json", "{}"),
                    "HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n{}",
                    wire(200, "application/json", "{broken"),
                    success(method).replace("X-YamlDB-Revision: " + REV, "X-YamlDB-Revision: bad-revision"))) {
                AtomicReference<String> receivedId = new AtomicReference<>();
                try (TlsPeer peer = new TlsPeer(socket -> {
                    byte[] request = request(socket);
                    if (discovery(request)) respond(socket, wire(200, "application/json", LEADER));
                    else { receivedId.set(id(request)); respond(socket, malformed); }
                })) {
                    try { operation(client(peer), method, null); throw new AssertionError("malformed receipt accepted: " + method); }
                    catch (YamoraException failure) {
                        check(failure.outcomeUncertain() && failure.requestId() != null
                                && failure.requestId().equals(receivedId.get()), method + " ambiguous outcome lost generated ID");
                        check(!failure.toString().contains(WRITE), "diagnostic leaked body/credential");
                        if (malformed.startsWith("HTTP/1.1 500")) check(failure.status() == 500, "500 status lost");
                    }
                }
            }
        }
        for (int status : new int[]{400, 401, 403, 409, 412, 413, 415, 422}) {
            try (TlsPeer peer = new TlsPeer(socket -> {
                byte[] request = request(socket);
                respond(socket, discovery(request) ? wire(200, "application/json", LEADER) : wire(status, "application/json", "{}"));
            })) { status(() -> operation(client(peer), "PATCH", null), status); }
        }
        AtomicBoolean lost = new AtomicBoolean();
        try (TlsPeer peer = new TlsPeer(socket -> {
            byte[] request = request(socket);
            if (discovery(request)) respond(socket, wire(200, "application/json", LEADER));
            else if (lost.getAndSet(true)) respond(socket, wire(412, "application/json", "{}"));
        })) {
            YamoraException failure = failure(() -> operation(client(peer), "PATCH", "2".repeat(32)), YamoraException.Kind.HTTP);
            check(failure.status() == 412 && failure.outcomeUncertain() && failure.requestId().equals("2".repeat(32)),
                    "conflict after lost ack erased uncertainty");
        }
    }

    private record ReceiptFault(String name, String operation, int status, String json) {}

    /** Corrupt JSON before framing so each case reaches its one intended receipt validator. */
    static void semanticReceipts() throws Exception {
        List<ReceiptFault> faults = new ArrayList<>();
        for (String method : List.of("PUT", "PATCH", "DELETE", "TX", "CATALOG")) {
            String json = successBody(method);
            int status = successStatus(method);
            faults.add(new ReceiptFault("http-status", method, 202, json));
            if (method.equals("DELETE")) continue;
            boolean committed = method.equals("TX") || method.equals("CATALOG");
            faults.add(new ReceiptFault("status", method, status,
                    json.replace(committed ? "\"committed\"" : "\"stored\"", "\"unexpected\"")));
            if (committed) {
                faults.add(new ReceiptFault("count", method, status, json.replace("\"operations\":1", "\"operations\":99")));
            } else {
                faults.add(new ReceiptFault("collection", method, status, json.replace("\"examples\"", "\"wrong\"")));
                faults.add(new ReceiptFault("document", method, status, json.replace("\"one\"", "\"other\"")));
                faults.add(new ReceiptFault("etag", method, status,
                        json.replace("\"etag\":\"" + REV + "\"", "\"etag\":\"bad\"")));
            }
        }
        for (ReceiptFault fault : faults) {
            if (!System.getProperty("yamora.test.operation", fault.operation()).equals(fault.operation())
                    || !System.getProperty("yamora.test.receipt", fault.name()).equals(fault.name())) continue;
            String label = fault.operation() + "/" + fault.name();
            String response = wire(fault.status(), "application/json", fault.json());
            AtomicReference<String> originalId = new AtomicReference<>();
            try (TlsPeer peer = new TlsPeer(socket -> {
                byte[] request = request(socket);
                if (discovery(request)) respond(socket, wire(200, "application/json", LEADER));
                else { originalId.set(id(request)); respond(socket, response); }
            })) {
                try { operation(client(peer), fault.operation(), null); throw new AssertionError("accepted invalid " + label + " receipt"); }
                catch (YamoraException failure) {
                    check(failure.kind() == YamoraException.Kind.PROTOCOL && failure.status() == fault.status(),
                            label + " lost typed response failure");
                    check(failure.outcomeUncertain() && originalId.get() != null
                                    && originalId.get().matches("[0-9a-f]{32}") && !originalId.get().equals("0".repeat(32))
                                    && originalId.get().equals(failure.requestId()),
                            label + " lost uncertainty or original generated ID");
                }
            }
        }
    }

    static void routingAndBudgets() throws Exception {
        try (TlsPeer trap = new TlsPeer(socket -> { request(socket); throw new AssertionError("untrusted endpoint contacted"); })) {
            for (String metadata : List.of(LEADER.substring(0, LEADER.length() - 1) + ",\"url\":\"https://127.0.0.1:"
                    + trap.seed().port() + "\"}", LEADER.replace("\"node\":1", "\"node\":true"),
                    LEADER.replace("\"term\":1", "\"term\":18446744073709551616"),
                    LEADER.replace("\"term\":1", "\"term\":1.0"), LEADER.replace("\"leader\":1", "\"leader\":2"))) {
                try (TlsPeer peer = new TlsPeer(socket -> {
                    byte[] request = request(socket);
                    check(discovery(request), "untrusted metadata selected for dispatch");
                    respond(socket, wire(200, "application/json", metadata));
                })) {
                    YamoraException failed = failure(() -> operation(client(List.of(peer.seed()), Duration.ofMillis(200),
                            Duration.ofMillis(80), 1024), "PUT", null), YamoraException.Kind.HTTP);
                    check(failed.outcomeUncertain() && failed.requestId() != null, "discovery exhaustion lost ID");
                }
            }
            try (TlsPeer peer = new TlsPeer(socket -> {
                request(socket);
                respond(socket, "HTTP/1.1 307 Redirect\r\nLocation: https://127.0.0.1:" + trap.seed().port()
                        + "/steal\r\nContent-Length: 0\r\n\r\n");
            })) { failure(() -> client(List.of(peer.seed()), Duration.ofMillis(200), Duration.ofMillis(80), 1024).ready(), YamoraException.Kind.HTTP); }
            check(trap.accepted.get() == 0, "credential endpoint escape");
        }
        for (String duplicate : List.of("Cache-Control: no-store\r\nCache-Control: public", "X-YamlDB-Revision: " + REV)) {
            try (TlsPeer peer = new TlsPeer(socket -> {
                request(socket);
                respond(socket, wire(200, "application/json", LEADER).replace("\r\n\r\n", "\r\n" + duplicate + "\r\n\r\n"));
            })) {
                failure(() -> client(List.of(peer.seed()), Duration.ofMillis(220), Duration.ofMillis(100), 1024).ready(), YamoraException.Kind.HTTP);
            }
        }
        try (TlsPeer peer = new TlsPeer(socket -> { throw new AssertionError("oversize request reached discovery"); })) {
            YamoraClient small = YamoraClient.replicaSet(new ClusterConfig(List.of(peer.seed()), trusted,
                    Duration.ofSeconds(1), Duration.ofMillis(200), 8, 1024), READ, WRITE);
            invalid(() -> operation(small, "PUT", null));
            check(peer.accepted.get() == 0, "request byte cap failed before discovery");
        }
        CountDownLatch release = new CountDownLatch(1);
        try (TlsPeer slow = new TlsPeer(socket -> { request(socket); release.await(3, TimeUnit.SECONDS); });
             TlsPeer fast = new TlsPeer(socket -> { request(socket); respond(socket, wire(200, "application/json", LEADER)); })) {
            try {
                long start = System.nanoTime();
                client(List.of(slow.seed(), fast.seed()), Duration.ofMillis(1500), Duration.ofSeconds(2), 1024).ready();
                check(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 1400, "first seed consumed overall deadline");
            } finally { release.countDown(); }
        }
        CountDownLatch dispatchRelease = new CountDownLatch(1);
        AtomicBoolean dispatchStall = new AtomicBoolean();
        try (TlsPeer old = new TlsPeer(socket -> {
            byte[] request = request(socket);
            if (discovery(request) || !dispatchStall.get()) respond(socket, wire(200, "application/json", LEADER));
            else dispatchRelease.await(3, TimeUnit.SECONDS);
        }); TlsPeer replacement = new TlsPeer(socket -> { request(socket); respond(socket, wire(200, "application/json", LEADER)); })) {
            try {
                YamoraClient routed = client(List.of(old.seed(), replacement.seed()), Duration.ofMillis(1800), Duration.ofSeconds(3), 1024);
                routed.ready();
                dispatchStall.set(true);
                long start = System.nanoTime();
                routed.ready();
                check(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 1800, "cached leader left no failover opportunity");
                check(replacement.accepted.get() >= 2, "cached leader was not replaced");
            } finally { dispatchRelease.countDown(); }
        }
        try (TlsPeer peer = new TlsPeer(socket -> { request(socket); respond(socket, wire(503, "application/json", "{}")); })) {
            long start = System.nanoTime();
            YamoraException failure = failure(() -> operation(client(List.of(peer.seed()), Duration.ofMillis(250),
                    Duration.ofMillis(100), 1024), "PATCH", null), YamoraException.Kind.HTTP);
            check(failure.requestId() != null && failure.outcomeUncertain(), "backoff exhaustion lost ID");
            check(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 1000, "backoff restarted total deadline");
        }
        AtomicBoolean stall = new AtomicBoolean(false);
        CountDownLatch blocked = new CountDownLatch(1), finish = new CountDownLatch(1);
        try (TlsPeer peer = new TlsPeer(socket -> {
            byte[] request = request(socket);
            if (!stall.get() || discovery(request)) respond(socket, wire(200, "application/json", LEADER));
            else { blocked.countDown(); finish.await(3, TimeUnit.SECONDS); }
        })) {
            YamoraClient client = client(peer);
            client.ready(); stall.set(true);
            AtomicReference<YamoraException> result = new AtomicReference<>();
            Thread thread = new Thread(() -> {
                try { operation(client, "PATCH", null); }
                catch (YamoraException failure) { result.set(failure); }
            });
            thread.start();
            try {
                check(blocked.await(2, TimeUnit.SECONDS), "call not dispatched");
                thread.interrupt(); thread.join(1000);
                check(!thread.isAlive() && result.get() != null && result.get().outcomeUncertain()
                        && result.get().requestId() != null, "cancellation escaped or lost ID");
            } finally { finish.countDown(); thread.join(3000); }
        }
        try (TlsPeer peer = new TlsPeer(socket -> { request(socket); respond(socket, wire(200, "application/json", LEADER)); })) {
            long start = System.nanoTime();
            failure(() -> client(List.of(peer.seed()), Duration.ofMillis(220), Duration.ofMillis(100), 32).ready(), YamoraException.Kind.HTTP);
            check(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 1000, "discovery cap/deadline failed");
        }
        CountDownLatch capRelease = new CountDownLatch(1);
        try (TlsPeer peer = new TlsPeer(socket -> {
            byte[] request = request(socket);
            if (discovery(request)) respond(socket, wire(200, "application/json", LEADER));
            else {
                respond(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2048\r\n\r\n");
                socket.getOutputStream().flush();
                capRelease.await(3, TimeUnit.SECONDS);
            }
        })) {
            try {
                failure(() -> client(List.of(peer.seed()), Duration.ofSeconds(1), Duration.ofMillis(200), 1024).ready(), YamoraException.Kind.PROTOCOL);
            } finally { capRelease.countDown(); }
        }
    }

    static void concurrentCalls() throws Exception {
        Set<String> ids = ConcurrentHashMap.newKeySet();
        try (TlsPeer peer = new TlsPeer(socket -> {
            byte[] request = request(socket);
            if (discovery(request)) respond(socket, wire(200, "application/json", LEADER));
            else { check(ids.add(id(request)), "generated ID reused across calls"); respond(socket, success("PATCH")); }
        })) {
            YamoraClient client = client(peer);
            ExecutorService callers = Executors.newFixedThreadPool(6);
            try {
                List<CompletableFuture<Void>> work = new ArrayList<>();
                for (int i = 0; i < 18; i++) work.add(CompletableFuture.runAsync(() -> {
                    try { operation(client, "PATCH", null); }
                    catch (YamoraException failure) { throw new java.io.UncheckedIOException(failure); }
                }, callers));
                CompletableFuture.allOf(work.toArray(CompletableFuture<?>[]::new)).get(10, TimeUnit.SECONDS);
                check(ids.size() == 18, "concurrent calls missing");
            } finally { callers.shutdownNow(); check(callers.awaitTermination(3, TimeUnit.SECONDS), "callers leaked"); }
        }
    }

    static void staleFailureDoesNotEvictNewLeader() throws Exception {
        AtomicBoolean failing = new AtomicBoolean();
        AtomicInteger oldCalls = new AtomicInteger(), discoveries = new AtomicInteger();
        CountDownLatch firstBlocked = new CountDownLatch(1), releaseFirst = new CountDownLatch(1);
        try (TlsPeer old = new TlsPeer(socket -> {
            byte[] request = request(socket);
            if (discovery(request) || !failing.get()) respond(socket, wire(200, "application/json", LEADER));
            else {
                if (oldCalls.incrementAndGet() == 1) {
                    firstBlocked.countDown();
                    releaseFirst.await(3, TimeUnit.SECONDS);
                }
                respond(socket, wire(503, "application/json", "{}"));
            }
        }); TlsPeer replacement = new TlsPeer(socket -> {
            byte[] request = request(socket);
            if (discovery(request)) discoveries.incrementAndGet();
            respond(socket, wire(200, "application/json", LEADER));
        })) {
            YamoraClient client = client(old, replacement);
            client.ready(); failing.set(true);
            CompletableFuture<Void> earlier = CompletableFuture.runAsync(() -> {
                try { client.ready(); }
                catch (YamoraException failure) { throw new java.io.UncheckedIOException(failure); }
            });
            try {
                check(firstBlocked.await(2, TimeUnit.SECONDS), "earlier call did not block");
                client.ready(); // later failure discovers and caches the replacement first
                check(discoveries.get() == 1, "replacement not cached");
                releaseFirst.countDown();
                earlier.get(5, TimeUnit.SECONDS);
                check(discoveries.get() == 1, "stale failure evicted a newer leader");
            } finally {
                releaseFirst.countDown();
                earlier.get(5, TimeUnit.SECONDS);
            }
        }
    }

    public static void main(String[] args) throws Exception {
        Path scratch = Files.createTempDirectory(Path.of(System.getProperty("java.io.tmpdir")), "cluster-");
        try {
            NativeTests.certificates(scratch);
            trusted = Tls.trustPem(scratch.resolve("ca.pem"), null, null);
            server = Tls.trustPem(scratch.resolve("ca.pem"), scratch.resolve("server.p12"), "test-only-password".toCharArray());
            ProxySelector previous = ProxySelector.getDefault();
            ProxySelector.setDefault(new ProxySelector() {
                @Override public List<java.net.Proxy> select(java.net.URI uri) { throw new AssertionError("proxy selected"); }
                @Override public void connectFailed(java.net.URI uri, java.net.SocketAddress address, IOException failure) {
                    throw new AssertionError("proxy used");
                }
            });
            try {
                switch (System.getProperty("yamora.test.group", "all")) {
                    case "native" -> { /* native-only diagnostic/qualification entrypoint */ }
                    case "retry" -> exactRetries();
                    case "receipts" -> { ambiguousReceipts(); semanticReceipts(); }
                    case "semantic-receipts" -> semanticReceipts();
                    case "routing" -> routingAndBudgets();
                    case "concurrency" -> { concurrentCalls(); staleFailureDoesNotEvictNewLeader(); }
                    case "all" -> { configuration(); exactRetries(); ambiguousReceipts(); semanticReceipts(); routingAndBudgets(); concurrentCalls(); staleFailureDoesNotEvictNewLeader(); }
                    default -> throw new IllegalArgumentException("unknown cluster group");
                }
            }
            finally { ProxySelector.setDefault(previous); }
            if (args.length == 1) ClusterNativeTests.run(Path.of(args[0]), scratch);
        } finally {
            try (var paths = Files.walk(scratch)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
        System.out.println("Java HTTPS replica-set tests passed: " + assertions + " assertions");
    }
}
