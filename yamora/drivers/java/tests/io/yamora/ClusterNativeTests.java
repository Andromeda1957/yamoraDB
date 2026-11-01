package io.yamora;

import static io.yamora.DriverTests.*;
import static io.yamora.ClusterTests.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Actual immutable ASAN daemon: three native-disk members, peer TLS and client mTLS. */
final class ClusterNativeTests implements AutoCloseable {
    final Path binary, root;
    final Process[] processes = new Process[3];
    final int[] ports = new int[3];
    final YamoraClient[] direct = new YamoraClient[3];
    final Tls mutual;

    ClusterNativeTests(Path binary, Path root) throws Exception {
        this.binary = binary;
        this.root = root;
        mutual = Tls.trustPem(root.resolve("ca.pem"), root.resolve("client.p12"), "test-only-password".toCharArray());
        NativeTests.command(root, "openssl", "req", "-new", "-newkey", "rsa:2048", "-noenc", "-subj", "/CN=Cluster Peer",
                "-keyout", "peer.key", "-out", "peer.csr");
        Files.writeString(root.resolve("peer.ext"), "extendedKeyUsage=serverAuth,clientAuth\n"
                + "subjectAltName=DNS:node1.test,DNS:node2.test,DNS:node3.test,IP:127.0.0.1\n");
        NativeTests.command(root, "openssl", "x509", "-req", "-in", "peer.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                "-set_serial", "5", "-days", "1", "-extfile", "peer.ext", "-out", "peer.pem");
        Path read = write("read.token", READ), writable = write("write.token", WRITE);
        List<ServerSocket> reservations = new ArrayList<>();
        try {
            List<Map<String, Object>> peers = new ArrayList<>();
            for (int i = 0; i < 3; i++) {
                ServerSocket listener = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
                reservations.add(listener);
                check(listener.getLocalPort() != 8000, "owner port allocated");
                peers.add(Map.of("id", i + 1, "name", "node" + (i + 1) + ".test", "address", "127.0.0.1", "port", listener.getLocalPort()));
            }
            List<List<String>> arguments = new ArrayList<>();
            for (int i = 0; i < 3; i++) {
                Path data = Files.createDirectory(root.resolve("data" + i));
                Path journal = Files.createDirectory(root.resolve("journal" + i));
                String spec = Json.stringify(Map.of("cluster", "01020304000000000000000000000000", "node", i + 1,
                        "journal_dir", journal.toString(), "peer_tls", Map.of("cert_file", root.resolve("peer.pem").toString(),
                        "key_file", root.resolve("peer.key").toString(), "ca_file", root.resolve("ca.pem").toString()),
                        "peers", peers, "request_timeout_ms", 3000, "journal_cache_bytes", 1048576));
                Path config = write("config" + i + ".json", spec);
                arguments.add(List.of(binary.toString(), "--data-dir", data.toString(), "--port", "0", "--workers", "4",
                        "--cluster-config-file", config.toString(), "--auth-token-file", read.toString(),
                        "--write-auth-token-file", writable.toString(), "--cache-bytes", "1048576", "--tls-cert-file",
                        root.resolve("server.pem").toString(), "--tls-key-file", root.resolve("server.key").toString(),
                        "--tls-client-ca-file", root.resolve("ca.pem").toString(), "--io-timeout-ms", "3000"));
            }
            for (ServerSocket listener : reservations) listener.close();
            for (int i = 0; i < 3; i++) start(i, arguments.get(i));
        } catch (Exception | AssertionError failure) { close(); throw failure; }
        finally { for (ServerSocket listener : reservations) listener.close(); }
    }
    Path write(String name, String value) throws IOException {
        Path file = root.resolve(name);
        Files.writeString(file, value);
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        return file;
    }
    void start(int index, List<String> arguments) throws Exception {
        Process process = new ProcessBuilder(arguments).directory(root.toFile())
                .redirectError(root.resolve("node" + index + ".log").toFile()).start();
        processes[index] = process;
        CompletableFuture<String> banner = CompletableFuture.supplyAsync(() -> {
            try { return new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8)).readLine(); }
            catch (IOException failure) { throw new java.io.UncheckedIOException(failure); }
        });
        String line = banner.get(10, TimeUnit.SECONDS);
        Matcher match = Pattern.compile("^yamora listening on 127\\.0\\.0\\.1:([0-9]+) .*$").matcher(line == null ? "" : line);
        check(match.matches(), "native startup: " + Files.readString(root.resolve("node" + index + ".log")));
        ports[index] = Integer.parseInt(match.group(1));
        check(ports[index] != 8000, "owner port allocated");
        direct[index] = new YamoraClient("127.0.0.1", ports[index], READ, WRITE, mutual,
                Duration.ofMillis(800), YamoraClient.MAX_REQUEST_BYTES, YamoraClient.MAX_RESPONSE_BYTES);
    }
    List<ClusterConfig.Seed> seeds() {
        List<ClusterConfig.Seed> seeds = new ArrayList<>();
        for (int port : ports) seeds.add(new ClusterConfig.Seed("127.0.0.1", port));
        return seeds;
    }
    YamoraClient routed(List<ClusterConfig.Seed> seeds) {
        return YamoraClient.replicaSet(new ClusterConfig(seeds, mutual, Duration.ofSeconds(20), Duration.ofSeconds(3),
                YamoraClient.MAX_REQUEST_BYTES, YamoraClient.MAX_RESPONSE_BYTES), READ, WRITE);
    }
    int leader() throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
        while (System.nanoTime() < deadline) {
            for (int i = 0; i < 3; i++) {
                if (processes[i] == null || !processes[i].isAlive()) continue;
                try { HttpTransport.Response response = new HttpTransport("127.0.0.1", ports[i], mutual, Duration.ofMillis(800))
                            .exchange("GET", "/v1/cluster/leader", new byte[0], null, READ, Map.of(), 512, false, 200);
                    if ("leader".equals(YamoraClient.clusterLeaderValue(response).get("role"))) return i; }
                catch (YamoraException expected) { /* election */ }
            }
            TimeUnit.MILLISECONDS.sleep(50);
        }
        List<String> status = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            try { status.add(direct[i].clusterLeader().json()); }
            catch (YamoraException error) { status.add(error.toString() + ": status=" + error.status() + " kind=" + error.kind() + ": " + error.getCause()); }
            status.add(Files.readString(root.resolve("node" + i + ".log")));
        }
        throw new AssertionError("native cluster did not elect leader: " + status);
    }
    void crash(int index) throws Exception {
        processes[index].destroyForcibly();
        check(processes[index].waitFor(5, TimeUnit.SECONDS), "owned child did not stop");
        processes[index] = null;
    }
    @Override public void close() throws IOException {
        IOException error = null;
        for (Process process : processes) {
            if (process != null) {
                try { NativeTests.stop(process); }
                catch (IOException failure) { error = failure; }
            }
        }
        for (int i = 0; i < 3; i++) {
            Path path = root.resolve("node" + i + ".log");
            if (!Files.exists(path)) continue;
            String log = Files.readString(path);
            check(!log.contains("ERROR: AddressSanitizer") && !log.contains("runtime error:")
                    && !log.contains("LeakSanitizer:"), "sanitizer failure: " + log);
        }
        if (error != null) throw error;
    }

    static void run(Path binary, Path root) throws Exception {
        try (ClusterNativeTests cluster = new ClusterNativeTests(binary, root)) {
            YamoraClient client = cluster.routed(cluster.seeds());
            cluster.leader();
            byte[] source = SOURCE;
            client.put("examples", "one", source, new YamoraClient.WriteOptions(null, true, "1".repeat(32)));
            check(Arrays.equals(source, client.get("examples", "one", null).source()), "cluster YAML bytes changed");
            status(() -> client.put("examples", "one", source, new YamoraClient.WriteOptions(null, true, null)), 412);
            status(() -> client.patch("examples", "one", "{\"$unknown\":{}}", YamoraClient.WriteOptions.NONE), 400);
            status(() -> client.startIndexBuild(CATALOG, null), 405);
            status(() -> client.replication(YamoraClient.ReplicationOperation.BEGIN, "{}"), 405);
            String before = client.changes(null, 100).json();
            int originalLeader = cluster.leader();
            AtomicReference<String> dropped = new AtomicReference<>();
            HttpTransport forwarding = new HttpTransport("127.0.0.1", cluster.ports[originalLeader], cluster.mutual, Duration.ofSeconds(5));
            try (TlsPeer relay = new TlsPeer(socket -> {
                byte[] received = request(socket);
                String[] target = first(received).split(" ");
                boolean mutation = target[0].equals("PATCH");
                Map<String, String> headers = mutation ? Map.of("X-Yamora-Request-Id", id(received)) : Map.of();
                HttpTransport.Response response;
                try {
                    response = forwarding.exchange(target[0], target[1], body(received), mutation ? "application/json" : null,
                            mutation ? WRITE : READ, headers, 1 << 20, mutation, 200);
                } catch (YamoraException unavailable) { respond(socket, wire(503, "application/json", "{}")); return; }
                if (mutation && dropped.compareAndSet(null, id(received))) {
                    cluster.crash(originalLeader); // acknowledged by quorum, never delivered to caller
                    return;
                }
                StringBuilder wire = new StringBuilder("HTTP/1.1 " + response.status() + " OK\r\n");
                response.headers().forEach((key, value) -> wire.append(key).append(": ").append(value).append("\r\n"));
                wire.append("\r\n");
                socket.getOutputStream().write(bytes(wire.toString()));
                socket.getOutputStream().write(response.body());
            })) {
                List<ClusterConfig.Seed> seeds = new ArrayList<>(List.of(relay.seed())); seeds.addAll(cluster.seeds());
                YamoraClient throughRelay = cluster.routed(seeds);
                throughRelay.patch("examples", "one", "{\"$inc\":{\"count\":1}}", YamoraClient.WriteOptions.NONE);
                check(dropped.get() != null && dropped.get().matches("[0-9a-f]{32}"), "native committed ack not dropped");
                check(text(client.get("examples", "one", null).source()).equals(text(source).replace("count: 0", "count: 1")),
                        "lost-ack failover applied PATCH more than once");
                status(() -> client.patch("examples", "one", "{\"$inc\":{\"count\":2}}",
                        new YamoraClient.WriteOptions(null, false, dropped.get())), 409);
                client.patch("examples", "one", "{\"$inc\":{\"count\":1}}", new YamoraClient.WriteOptions(null, false, dropped.get()));
                check(text(client.get("examples", "one", null).source()).contains("count: 1"), "explicit replay applied twice");
            }
            YamoraClient.JsonReply transaction = client.transaction(TX, "3".repeat(32));
            check(client.transaction(TX, "3".repeat(32)).json().equals(transaction.json()), "transaction replay receipt changed");
            check(text(client.get("examples", "one", null).source()).contains("count: 2"), "transaction replay applied twice");
            YamoraClient.JsonReply catalog = client.setIndexes(CATALOG, null, "4".repeat(32));
            check(client.setIndexes(CATALOG, null, "4".repeat(32)).json().equals(catalog.json()), "catalog replay changed");
            client.indexes(); client.collections(null); client.documentPage("examples", 10, null, null);
            YamoraClient.JsonReply query = client.query("examples", "{\"filter\":{\"n\":9223372036854775807}}");
            Map<?, ?> row = (Map<?, ?>) ((List<?>) query.value().get("documents")).get(0);
            check(((Json.NumberValue) ((Map<?, ?>) row.get("value")).get("n")).longValueExact() == Long.MAX_VALUE,
                    "cluster int64 rounded");
            client.aggregate("examples", "{\"pipeline\":[{\"$count\":\"n\"}]}");
            check(!client.changes(null, 100).json().equals(before), "mutations absent from feed");
            client.delete("examples", "one", new YamoraClient.WriteOptions(null, false, "5".repeat(32)));
            client.put("examples", "one", source, YamoraClient.WriteOptions.NONE);
            client.delete("examples", "one", new YamoraClient.WriteOptions(null, false, "5".repeat(32)));
            check(Arrays.equals(client.get("examples", "one", null).source(), source), "replayed delete removed replacement");
            List<CompletableFuture<Void>> writes = new ArrayList<>();
            for (int i = 0; i < 8; i++) writes.add(CompletableFuture.runAsync(() -> {
                try { client.patch("examples", "one", "{\"$inc\":{\"count\":1}}", YamoraClient.WriteOptions.NONE); }
                catch (YamoraException failure) { throw new java.io.UncheckedIOException(failure); }
            }));
            CompletableFuture.allOf(writes.toArray(CompletableFuture<?>[]::new)).get(25, TimeUnit.SECONDS);
            check(text(client.get("examples", "one", null).source()).equals(text(source).replace("count: 0", "count: 8")), "concurrent native writes lost/replayed");
            int leader = cluster.leader();
            YamoraClient noIdentity = YamoraClient.replicaSet(new ClusterConfig(List.of(cluster.seeds().get(leader)), trusted,
                    Duration.ofMillis(300), Duration.ofMillis(100), 1024, 1024), READ, WRITE);
            failure(noIdentity::ready, YamoraException.Kind.HTTP);
            for (int i = 0; i < 3; i++) if (i != leader && cluster.processes[i] != null) cluster.crash(i);
            YamoraClient isolated = YamoraClient.replicaSet(new ClusterConfig(List.of(cluster.seeds().get(leader)), cluster.mutual,
                    Duration.ofMillis(450), Duration.ofMillis(200), 1024, 1024), READ, WRITE);
            long start = System.nanoTime();
            try { isolated.get("examples", "one", null); throw new AssertionError("isolated leader served quorum read"); }
            catch (YamoraException expected) { check(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 1500, "quorum read exceeded budget"); }
        }
    }
}
