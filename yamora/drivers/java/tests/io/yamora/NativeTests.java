package io.yamora;

import static io.yamora.DriverTests.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

/** Starts only task-owned daemons, ephemeral databases and test certificates. */
public final class NativeTests {
    private NativeTests() {}
    private static Path binary;
    private static Path scratch;

    static void command(Path directory, String... args) throws Exception {
        Path log = directory.resolve("command.log");
        Process process = new ProcessBuilder(args).directory(directory.toFile()).redirectErrorStream(true)
                .redirectOutput(log.toFile()).start();
        try {
            check(process.waitFor(20, TimeUnit.SECONDS), "subprocess timed out");
            check(process.exitValue() == 0, "test setup failed: " + Files.readString(log));
        } finally {
            if (process.isAlive()) process.destroyForcibly().waitFor(5, TimeUnit.SECONDS);
        }
    }

    static final class Daemon implements AutoCloseable {
        final Path root;
        final Process process;
        final int port;
        final YamoraClient client;
        Daemon(Tls tls, String... options) throws Exception {
            root = Files.createTempDirectory(scratch, "daemon-");
            Path data = Files.createDirectory(root.resolve("data"));
            Path read = root.resolve("read.token"), write = root.resolve("write.token");
            for (Path path : List.of(read, write)) {
                Files.writeString(path, path.equals(read) ? READ : WRITE);
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
            }
            command(root, binary.toString(), "--data-dir", data.toString(), "--init-disk", "--validate-only");
            List<String> args = new ArrayList<>(List.of(binary.toString(), "--data-dir", data.toString(), "--port", "0",
                    "--auth-token-file", read.toString(), "--write-auth-token-file", write.toString()));
            args.addAll(List.of(options));
            process = new ProcessBuilder(args).directory(root.toFile()).redirectError(root.resolve("daemon.log").toFile()).start();
            try {
                CompletableFuture<String> banner = CompletableFuture.supplyAsync(() -> {
                    try { return new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8)).readLine(); }
                    catch (IOException failure) { throw new java.io.UncheckedIOException(failure); }
                });
                String line = banner.get(10, TimeUnit.SECONDS);
                // Match the stable address prefix; the remaining banner is not part of the SDK contract.
                Matcher match = Pattern.compile("^yamora listening on 127\\.0\\.0\\.1:([0-9]+) .*$").matcher(line == null ? "" : line);
                check(match.matches(), "native startup failed: " + Files.readString(root.resolve("daemon.log")));
                port = Integer.parseInt(match.group(1));
                check(port != 8000, "reserved owner port allocated");
                client = new YamoraClient("127.0.0.1", port, READ, WRITE, tls, Duration.ofSeconds(5),
                        YamoraClient.MAX_REQUEST_BYTES, YamoraClient.MAX_RESPONSE_BYTES);
            } catch (Exception | AssertionError failure) {
                stop(process);
                throw failure;
            }
        }
        @Override public void close() throws IOException {
            stop(process);
            String log = Files.readString(root.resolve("daemon.log"));
            check(!log.contains("ERROR: AddressSanitizer") && !log.contains("runtime error:"), "native sanitizer failure");
        }
    }

    static void stop(Process process) throws IOException {
        process.destroy();
        try {
            if (!process.waitFor(5, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                check(process.waitFor(5, TimeUnit.SECONDS), "daemon failed to stop");
            }
        } catch (InterruptedException failure) { Thread.currentThread().interrupt(); throw new IOException(failure); }
    }

    static void http() throws Exception {
        try (Daemon daemon = new Daemon(null)) {
            YamoraClient client = daemon.client;
            check(client.health().value().get("status").equals("ok"), "health");
            check(client.ready().value().get("storage").equals("native-disk-v2"), "wrong storage target");
            client.stats();
            check(client.metrics().contains("yamldb_uptime_seconds"), "metrics");
            String checkpoint = (String) client.changes(null, 100).value().get("next_after");
            byte[] source = bytes("# exact café\r\nname: Alpha\r\nn: 9007199254740993 # keep\r\n");
            YamoraClient.JsonReply stored = client.put("examples", "one", source,
                    new YamoraClient.WriteOptions(null, true, null));
            YamoraClient.Document document = client.get("examples", "one", stored.revision());
            check(Arrays.equals(source, document.source()), "native authored bytes changed");
            byte[] copy = document.source(); copy[0] = 0;
            check(Arrays.equals(source, document.source()), "document source is mutable");
            for (Action rejected : List.<Action>of(
                    () -> client.put("examples", "one", bytes("changed: true\n"), new YamoraClient.WriteOptions(null, true, null)),
                    () -> client.put("examples", "one", bytes("changed: true\n"), new YamoraClient.WriteOptions("0".repeat(16), false, null)),
                    () -> client.patch("examples", "one", "{\"$inc\":{\"n\":1}}", new YamoraClient.WriteOptions("0".repeat(16), false, null)),
                    () -> client.delete("examples", "one", new YamoraClient.WriteOptions("0".repeat(16), false, null)))) status(rejected, 412);
            check(Arrays.equals(source, client.get("examples", "one", null).source()), "rejected writes changed bytes");
            YamoraClient noAuth = new YamoraClient("127.0.0.1", daemon.port, "", "", null);
            noAuth.health();
            status(noAuth::ready, 401);
            status(() -> noAuth.put("examples", "other", source, YamoraClient.WriteOptions.NONE), 401);
            YamoraClient readOnly = new YamoraClient("127.0.0.1", daemon.port, READ, READ, null);
            status(() -> readOnly.put("examples", "other", source, YamoraClient.WriteOptions.NONE), 401);
            client.patch("examples", "one", "{\"$inc\":{\"n\":1}}", new YamoraClient.WriteOptions(document.etag(), false, null));
            check(new String(client.get("examples", "one", null).source(), StandardCharsets.UTF_8)
                    .equals(new String(source, StandardCharsets.UTF_8).replace("9007199254740993", "9007199254740994")), "PATCH lost comments or CRLF");
            String transaction = "{\"operations\":[{\"collection\":\"examples\",\"document\":\"two\",\"put\":\"name: Beta\\nn: 9223372036854775807\\n\",\"create_only\":true},"
                    + "{\"collection\":\"examples\",\"document\":\"one\",\"patch\":{\"$set\":{\"name\":\"Omega\"}}}]}";
            YamoraClient.JsonReply committed = client.transaction(transaction, "1".repeat(32));
            check(committed.value().get("status").equals("committed"), "transaction");
            status(() -> client.transaction(transaction.replace("{\"operations\"", "{\"revision\":\"" + stored.revision() + "\",\"operations\""), null), 412);
            YamoraClient.JsonReply query = client.query("examples", "{\"filter\":{\"name\":\"Beta\"},\"explain\":true}");
            Map<?, ?> row = (Map<?, ?>) ((List<?>) query.value().get("documents")).get(0);
            check(((Json.NumberValue) ((Map<?, ?>) row.get("value")).get("n")).longValueExact() == Long.MAX_VALUE,
                    "native JSON integer precision lost");
            check(query.value().get("explain") instanceof Map<?, ?>, "explain missing");
            YamoraClient.JsonReply first = client.documentPage("examples", 1, null, committed.revision());
            check(first.value().get("documents").equals(List.of("one")), "page one");
            YamoraClient.JsonReply second = client.documentPage("examples", 1, (String) first.value().get("next_after"), first.revision());
            check(second.value().get("documents").equals(List.of("two")), "page two");
            check(((List<?>) client.collections(first.revision()).value().get("collections")).contains("examples"), "collection list");
            client.aggregate("examples", "{\"pipeline\":[{\"$count\":\"total\"}]}");
            String definitions = "{\"indexes\":[{\"collection\":\"examples\",\"name\":\"words\",\"fields\":[\"$source\"],\"type\":\"text\",\"unique\":false}]}";
            String before = client.indexes().revision();
            client.setIndexes(definitions, before, null);
            status(() -> client.setIndexes("{\"indexes\":[]}", before, null), 412);
            check(((List<?>) client.search("examples", "{\"index\":\"words\",\"text\":\"keep\"}").value().get("documents")).size() == 1,
                    "comment full-text search");
            String jobId = (String) client.startIndexBuild("{\"indexes\":[]}", client.ready().revision()).value().get("id");
            long stop = System.nanoTime() + TimeUnit.SECONDS.toNanos(8);
            YamoraClient.JsonReply job = client.indexBuild(jobId);
            while (job.value().get("status").equals("running") && System.nanoTime() < stop) {
                Thread.sleep(20);
                job = client.indexBuild(jobId);
            }
            check(job.value().get("status").equals("succeeded"), "online build did not succeed");
            client.put("examples", "later", bytes("name: later\n"), YamoraClient.WriteOptions.NONE);
            check(client.indexBuild(jobId).value().get("revision").equals(job.value().get("revision")), "job publication revision was overwritten");
            check(!client.indexBuild(jobId).revision().equals(job.value().get("revision")), "job/head revision test did not diverge");
            status(() -> client.cancelIndexBuild(jobId), 409);
            client.indexBuild(null);
            check(client.changes(checkpoint, 100).value().get("transactions") instanceof List<?>, "finite feed");
            status(() -> client.query("examples", "{\"revision\":\"" + stored.revision() + "\"}"), 412);
            YamoraClient.Document current = client.get("examples", "two", null);
            client.delete("examples", "two", new YamoraClient.WriteOptions(current.etag(), false, null));
            status(() -> client.get("examples", "two", null), 404);
            List<CompletableFuture<Void>> reads = new ArrayList<>();
            for (int i = 0; i < 4; i++) reads.add(CompletableFuture.runAsync(() -> {
                try { client.get("examples", "one", null); }
                catch (YamoraException failure) { throw new java.io.UncheckedIOException(failure); }
            }));
            CompletableFuture.allOf(reads.toArray(CompletableFuture[]::new)).get(10, TimeUnit.SECONDS);
            // A source well beyond the old 256 KiB profile, including multibyte UTF-8.
            byte[] large = bytes("# large exact\r\ntext: " + "é".repeat(200_000) + "\r\n");
            client.put("examples", "large", large, YamoraClient.WriteOptions.NONE);
            check(Arrays.equals(large, client.get("examples", "large", null).source()), "large native source");
        }
    }

    static void replication() throws Exception {
        try (Daemon source = new Daemon(null); Daemon replica = new Daemon(null, "--replica")) {
            byte[] authored = bytes("# exact replica\r\nname: mirrored\r\n");
            source.client.put("mirror", "one", authored, YamoraClient.WriteOptions.NONE);
            String revision = source.client.ready().revision();
            String begin = "{\"revision\":\"" + revision + "\",\"collections\":[\"mirror\"],\"full\":true,\"revision_scheme\":\"xor-fnv-v2\"}";
            String session = (String) replica.client.replication(YamoraClient.ReplicationOperation.BEGIN, begin).value().get("session");
            replica.client.replication(YamoraClient.ReplicationOperation.ABORT, Json.stringify(Map.of("session", session)));
            session = (String) replica.client.replication(YamoraClient.ReplicationOperation.BEGIN, begin).value().get("session");
            replica.client.replication(YamoraClient.ReplicationOperation.APPLY, Json.stringify(Map.of("session", session,
                    "operations", List.of(Map.of("collection", "mirror", "document", "one", "put", new String(authored, StandardCharsets.UTF_8))))));
            status(() -> replica.client.get("mirror", "one", null), 404);
            replica.client.replication(YamoraClient.ReplicationOperation.COMMIT, Json.stringify(Map.of("session", session, "revision", revision)));
            check(Arrays.equals(authored, replica.client.get("mirror", "one", revision).source()), "replication primitive bytes");
            replica.client.replicationStatus();
        }
    }

    static void certificates(Path root) throws Exception {
        command(root, "openssl", "req", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1", "-subj", "/CN=Java Driver Test CA",
                "-keyout", "ca.key", "-out", "ca.pem");
        for (String name : List.of("server", "wrong-host", "client")) {
            command(root, "openssl", "req", "-new", "-newkey", "rsa:2048", "-noenc", "-subj", "/CN=" + name,
                    "-keyout", name + ".key", "-out", name + ".csr");
            Files.writeString(root.resolve(name + ".ext"), "extendedKeyUsage=" + (name.equals("client") ? "clientAuth" : "serverAuth")
                    + "\nsubjectAltName=IP:" + (name.equals("wrong-host") ? "127.0.0.2" : "127.0.0.1") + "\n");
            command(root, "openssl", "x509", "-req", "-in", name + ".csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                    "-set_serial", name.equals("server") ? "2" : name.equals("wrong-host") ? "3" : "4",
                    "-days", "1", "-extfile", name + ".ext", "-out", name + ".pem");
            command(root, "openssl", "pkcs12", "-export", "-inkey", name + ".key", "-in", name + ".pem", "-certfile", "ca.pem",
                    "-passout", "pass:test-only-password", "-out", name + ".p12");
        }
    }

    static void tls() throws Exception {
        Path certs = Files.createDirectory(scratch.resolve("certs"));
        certificates(certs);
        Tls trusted = Tls.trustPem(certs.resolve("ca.pem"), null, null);
        Tls mutual = Tls.trustPem(certs.resolve("ca.pem"), certs.resolve("client.p12"), "test-only-password".toCharArray());
        try (Daemon server = new Daemon(trusted, "--tls-cert-file", certs.resolve("server.pem").toString(),
                "--tls-key-file", certs.resolve("server.key").toString())) {
            server.client.ready();
            YamoraClient untrusted = new YamoraClient("127.0.0.1", server.port, READ, WRITE, Tls.systemTrust());
            check(failure(untrusted::ready, YamoraException.Kind.TRANSPORT).getCause() instanceof javax.net.ssl.SSLHandshakeException,
                    "untrusted chain did not fail verification");
        }
        try (Daemon server = new Daemon(trusted, "--tls-cert-file", certs.resolve("wrong-host.pem").toString(),
                "--tls-key-file", certs.resolve("wrong-host.key").toString())) {
            check(failure(server.client::ready, YamoraException.Kind.TRANSPORT).getCause() instanceof javax.net.ssl.SSLHandshakeException,
                    "wrong IP certificate did not fail verification");
        }
        try (Daemon server = new Daemon(mutual, "--tls-cert-file", certs.resolve("server.pem").toString(),
                "--tls-key-file", certs.resolve("server.key").toString(), "--tls-client-ca-file", certs.resolve("ca.pem").toString())) {
            byte[] authored = bytes("# TLS source\r\nname: mutual\r\nn: 9223372036854775807\r\n");
            server.client.put("secure", "one", authored, YamoraClient.WriteOptions.NONE);
            check(Arrays.equals(authored, server.client.get("secure", "one", null).source()), "mTLS source changed");
            YamoraClient missingIdentity = new YamoraClient("127.0.0.1", server.port, READ, WRITE, trusted);
            failure(missingIdentity::ready, YamoraException.Kind.TRANSPORT);
            YamoraClient missingBearer = new YamoraClient("127.0.0.1", server.port, "", "", mutual);
            status(missingBearer::ready, 401);
        }
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(certs.resolve("server.p12"))) { keys.load(input, "test-only-password".toCharArray()); }
        KeyManagerFactory manager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        manager.init(keys, "test-only-password".toCharArray());
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(manager.getKeyManagers(), null, null);
        try (SSLServerSocket listener = (SSLServerSocket) context.getServerSocketFactory()
                .createServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"))) {
            listener.setEnabledProtocols(new String[]{"TLSv1.2"});
            listener.setSoTimeout(3000);
            CompletableFuture<Void> handshake = CompletableFuture.runAsync(() -> {
                try (SSLSocket socket = (SSLSocket) listener.accept()) {
                    socket.setSoTimeout(3000);
                    try { socket.startHandshake(); throw new AssertionError("TLS1.2 negotiated"); }
                    catch (javax.net.ssl.SSLHandshakeException expected) { /* version mismatch */ }
                } catch (IOException failure) { throw new java.io.UncheckedIOException(failure); }
            });
            YamoraClient client = new YamoraClient("127.0.0.1", listener.getLocalPort(), READ, WRITE, trusted);
            failure(client::health, YamoraException.Kind.TRANSPORT);
            handshake.get(4, TimeUnit.SECONDS);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1 || args.length > 2 || !Path.of(args[0]).isAbsolute() || !Files.isExecutable(Path.of(args[0]))) {
            throw new IllegalArgumentException("absolute executable native daemon path required");
        }
        binary = Path.of(args[0]);
        Path base = Path.of(System.getProperty("java.io.tmpdir")).toRealPath();
        String configured = System.getenv("TMPDIR");
        if (configured == null || !base.equals(Path.of(configured).toRealPath())) {
            throw new IllegalArgumentException("runner-owned TMPDIR and java.io.tmpdir must agree");
        }
        scratch = Files.createTempDirectory(base, "native-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        try {
            switch (args.length == 1 ? "all" : args[1]) {
                case "http" -> http();
                case "replication" -> replication();
                case "tls" -> tls();
                case "all" -> { http(); replication(); tls(); }
                default -> throw new IllegalArgumentException("unknown native test group");
            }
        }
        finally {
            try (var paths = Files.walk(scratch)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
        System.out.println("Java native HTTP/TLS tests passed: " + assertions + " assertions");
    }
}
