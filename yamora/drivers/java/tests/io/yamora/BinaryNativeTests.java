package io.yamora;

import static io.yamora.DriverTests.*;
import static io.yamora.BinaryFrameCodec.*;
import static io.yamora.BinaryEnvelope.Method.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import javax.net.ssl.SSLSocket;

/** Required actual ASan/UBSan native binary mTLS and HTTP interoperability. */
public final class BinaryNativeTests {
    private BinaryNativeTests() {}
    static Path root, certs, binary;
    static Tls mutual;
    static int cases;
    static final String ID = BinaryTests.ID;
    static final class Daemon implements AutoCloseable {
        final Process process;
        final Path directory, stderr;
        final int port, httpPort;
        final YamoraClient http;
        Daemon(boolean legacy, boolean mtls, String certificate, String... extra) throws Exception {
            directory = Files.createTempDirectory(root, "binary-native-");
            stderr = directory.resolve("stderr");
            Path data = Files.createDirectory(directory.resolve("data"));
            NativeTests.command(directory, binary.toString(), "--data-dir", data.toString(), "--init-disk", "--validate-only");
            if (legacy) {
                Path image = data.resolve(".yamora-disk"); byte[] bytes = Files.readAllBytes(image);
                for (int base : new int[]{0, 4096}) {
                    System.arraycopy("YAMDIS04".getBytes(java.nio.charset.StandardCharsets.US_ASCII), 0, bytes, base, 8);
                    int crc = crc32c(bytes, base, 4092);
                    java.nio.ByteBuffer.wrap(bytes, base + 4092, 4).order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(crc);
                }
                Files.write(image, bytes);
            }
            Path read = token(directory.resolve("read.token"), READ), write = token(directory.resolve("write.token"), WRITE);
            Path policy = token(directory.resolve("policy.json"), Json.stringify(java.util.Map.of("version", 1,
                    "roles", java.util.Map.of("one", java.util.Map.of("read", List.of("allowed"), "write", List.of("allowed"))),
                    "principals", java.util.Map.of("one", java.util.Map.of("token_file", token(directory.resolve("scoped.token"), "s".repeat(32)).toString(), "roles", List.of("one"))))));
            List<String> args = new ArrayList<>(List.of(binary.toString(), "--data-dir", data.toString(), "--port", "0", "--binary-port", "0",
                    "--auth-token-file", read.toString(), "--write-auth-token-file", write.toString(), "--access-policy-file", policy.toString(),
                    "--tls-cert-file", certs.resolve(certificate + ".pem").toString(), "--tls-key-file", certs.resolve(certificate + ".key").toString(),
                    "--io-timeout-ms", "10000", "--cache-bytes", "1048576", "--workers", "2"));
            if (mtls) args.addAll(List.of("--tls-client-ca-file", certs.resolve("ca.pem").toString()));
            args.addAll(List.of(extra));
            Path stdout = directory.resolve("stdout");
            process = new ProcessBuilder(args).directory(directory.toFile()).redirectError(stderr.toFile()).redirectOutput(stdout.toFile()).start();
            int foundHttp = 0, foundBinary = 0;
            try {
                long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(12);
                while (System.nanoTime() < until && process.isAlive()) {
                    String output = Files.readString(stdout);
                    check(output.length() <= 8192, "unbounded readiness output");
                    var httpMatch = Pattern.compile("(?m)^yamora listening on 127\\.0\\.0\\.1:([0-9]+)").matcher(output);
                    var binMatch = Pattern.compile("(?m)^binary listening on 127\\.0\\.0\\.1:([0-9]+)").matcher(output);
                    if (httpMatch.find()) foundHttp = Integer.parseInt(httpMatch.group(1));
                    if (binMatch.find()) foundBinary = Integer.parseInt(binMatch.group(1));
                    if (foundHttp != 0 && foundBinary != 0) break;
                    Thread.sleep(10);
                }
                check(foundHttp != 0 && foundBinary != 0, "required native binary listener absent: " + Files.readString(stderr));
                check(foundHttp != 8000 && foundBinary != 8000, "owner port allocated");
                port = foundBinary; httpPort = foundHttp;
                http = new YamoraClient("127.0.0.1", httpPort, READ, WRITE, mutual, Duration.ofSeconds(30), YamoraClient.MAX_REQUEST_BYTES, YamoraClient.MAX_RESPONSE_BYTES);
            } catch (Exception | AssertionError error) { NativeTests.stop(process); throw error; }
        }
        BinaryClient client(boolean identity, int frame) throws Exception {
            return new BinaryClient(config(port, identity, frame, "127.0.0.1", "ca.pem"));
        }
        @Override public void close() throws IOException {
            NativeTests.stop(process);
            String log = Files.readString(stderr);
            check(process.exitValue() == 0 && !log.contains("Sanitizer") && !log.contains("runtime error:"), "fatal native diagnostics: " + log);
        }
    }
    static Path token(Path file, String value) throws IOException {
        Files.writeString(file, value); Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------")); return file;
    }
    static int crc32c(byte[] bytes, int offset, int length) {
        int crc = -1;
        for (int i = offset; i < offset + length; i++) {
            crc ^= bytes[i] & 255;
            for (int bit = 0; bit < 8; bit++) crc = crc >>> 1 ^ ((crc & 1) == 0 ? 0 : 0x82f63b78);
        }
        return ~crc;
    }
    static BinaryConfig config(int port, boolean identity, int frame, String serverName, String ca) throws Exception {
        byte[] anchors = Files.readAllBytes(certs.resolve(ca));
        byte[] key = identity ? Files.readAllBytes(certs.resolve("client.p12")) : null;
        char[] password = identity ? "test-only-password".toCharArray() : null;
        BinaryConfig config = new BinaryConfig("127.0.0.1", port, serverName, anchors, key, password, Duration.ofSeconds(30), 2, frame);
        // The config owns independent material; callers may erase their inputs.
        Arrays.fill(anchors, (byte) 0); if (key != null) Arrays.fill(key, (byte) 0); if (password != null) Arrays.fill(password, 'x');
        return config;
    }
    static void rejected(Action action, int wanted) throws Exception {
        BinaryException failure = BinaryTests.fails(action, BinaryException.Kind.STATUS, false);
        check(failure.status() == wanted, "wrong native binary status: " + failure.status()); cases++;
    }
    static void crud() throws Exception {
        try (Daemon daemon = new Daemon(false, true, "server")) {
            BinaryClient client = daemon.client(true, 4096);
            byte[] source = bytes("# café λ\r\nvalue: 01 # preserve\r\ntext: '雪'\r\n");
            BinaryResponse stored = client.put("config", "one", source, WRITE, null, "*", ID, new BinaryCancellation());
            check(stored.status() == 201, "native creation status");
            check(Arrays.equals(source, daemon.http.get("config", "one", null).source()), "binary PUT to HTTP lost exact bytes");
            BinaryResponse get = client.get("config", "one", READ);
            check(Arrays.equals(source, get.body()), "binary GET lost exact bytes");
            byte[] mutable = get.body(); mutable[0] = 0;
            check(Arrays.equals(source, get.body()), "binary response body mutable");
            check(get.metadata().revision().equals(stored.metadata().revision()) && get.metadata().etag().equals(stored.metadata().etag()), "native receipt mismatch");
            BinaryResponse head = client.head("config", "one", READ);
            check(head.body().length == 0 && head.metadata().representationLength() == source.length && head.metadata().etag().equals(get.metadata().etag()), "HEAD representation contract");
            rejected(() -> client.put("config", "one", source, WRITE, null, "*", null, new BinaryCancellation()), 412);
            rejected(() -> client.put("config", "one", source, WRITE, "\"" + "0".repeat(16) + "\"", null, null, new BinaryCancellation()), 412);
            rejected(() -> client.put("config", "one", source, WRITE, "", null, null, new BinaryCancellation()), 400);
            rejected(() -> client.put("config", "one", source, WRITE, get.metadata().etag(), "*", null, new BinaryCancellation()), 400);
            rejected(() -> client.get("config", "one", null), 401);
            rejected(() -> client.put("config", "one", source, READ, null, null, null, new BinaryCancellation()), 401);
            rejected(() -> client.get("config", "one", "s".repeat(32)), 403);
            client.put("allowed", "one", source, "s".repeat(32), null, "*", null, new BinaryCancellation());
            check(Arrays.equals(source, client.get("allowed", "one", "s".repeat(32)).body()), "scoped bearer grants");
            byte[] replacement = bytes("# HTTP source\r\nvalue: 2\r\n");
            daemon.http.put("config", "one", replacement, YamoraClient.WriteOptions.NONE);
            check(Arrays.equals(replacement, client.get("config", "one", READ).body()), "HTTP PUT to binary lost bytes");
            rejected(() -> client.delete("config", "one", WRITE, get.metadata().etag(), null, new BinaryCancellation()), 412);
            BinaryResponse deleted = client.delete("config", "one", WRITE, client.get("config", "one", READ).metadata().etag(), null, new BinaryCancellation());
            check(deleted.status() == 204 && deleted.body().length == 0 && deleted.metadata().representationLength() == 0, "DELETE 204 contract");
            rejected(() -> client.head("config", "one", READ), 404);
            DriverTests.status(() -> daemon.http.get("config", "one", null), 404);
            BinaryTests.fails(() -> daemon.client(false, 4096).get("config", "one", READ), BinaryException.Kind.TRANSPORT, false);
            BinaryTests.fails(() -> new BinaryClient(config(daemon.port, true, 4096, "wrong.test", "ca.pem")).get("config", "one", READ), BinaryException.Kind.TRANSPORT, false);
            // Trust only a different, valid certificate; never a trust-all switch.
            BinaryTests.fails(() -> new BinaryClient(config(daemon.port, true, 4096, "127.0.0.1", "wrong-host.pem")).get("config", "one", READ), BinaryException.Kind.TRANSPORT, false);
            cases++;
        }
        // The route is numeric, but the certificate/SNI identity is an unrelated
        // DNS name. No name resolution is needed or allowed to choose a route.
        NativeTests.command(certs, "openssl", "req", "-new", "-newkey", "rsa:2048", "-noenc", "-subj", "/CN=binary.invalid",
                "-keyout", "named.key", "-out", "named.csr");
        Files.writeString(certs.resolve("named.ext"), "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:binary.invalid,IP:127.0.0.1\n");
        NativeTests.command(certs, "openssl", "x509", "-req", "-in", "named.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-set_serial", "8",
                "-days", "1", "-extfile", "named.ext", "-out", "named.pem");
        try (Daemon named = new Daemon(false, true, "named")) {
            byte[] der;
            try (var input = Files.newInputStream(certs.resolve("ca.pem"))) {
                der = java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(input).getEncoded();
            }
            BinaryConfig config = new BinaryConfig("127.0.0.1", named.port, "binary.invalid", der,
                    Files.readAllBytes(certs.resolve("client.p12")), "test-only-password".toCharArray(), Duration.ofSeconds(5), 1, 65536);
            Arrays.fill(der, (byte) 0);
            BinaryClient client = new BinaryClient(config);
            byte[] source = bytes("# DER and explicit DNS identity\r\nvalue: 2\r\n");
            client.put("config", "named", source, WRITE, null, null, null, new BinaryCancellation());
            check(Arrays.equals(source, client.get("config", "named", READ).body()), "owned DER trust / explicit serverName routing"); cases++;
        }
    }
    static void large() throws Exception {
        try (Daemon daemon = new Daemon(false, true, "server")) {
            BinaryClient client = daemon.client(true, 4096);
            byte[] source = new byte[BinaryClient.MAX_SOURCE]; Arrays.fill(source, (byte) 'x');
            byte[] prefix = bytes("# exact café CRLF\r\nvalue: 01\r\n# ");
            System.arraycopy(prefix, 0, source, 0, prefix.length); source[source.length - 2] = '\r'; source[source.length - 1] = '\n';
            check(client.put("config", "large", source, WRITE, null, "*", null, new BinaryCancellation()).status() == 201, "16 MiB PUT");
            check(Arrays.equals(source, client.get("config", "large", READ).body()), "16 MiB 4 KiB fragmentation bytes");
            check(client.head("config", "large", READ).metadata().representationLength() == source.length, "16 MiB HEAD");
            check(Arrays.equals(source, daemon.http.get("config", "large", null).source()), "16 MiB HTTP interoperability"); cases++;
        }
        try (Daemon daemon = new Daemon(true, true, "server")) {
            BinaryClient client = daemon.client(true, 4096);
            byte[] source = new byte[256 * 1024 + 1]; Arrays.fill(source, (byte) 'x');
            rejected(() -> client.put("config", "legacy", source, WRITE, null, null, null, new BinaryCancellation()), 413);
            rejected(() -> client.get("config", "legacy", READ), 404);
            client.put("config", "legacy", bytes("value: 2\n"), WRITE, null, null, null, new BinaryCancellation());
            check(Arrays.equals(bytes("value: 2\n"), daemon.http.get("config", "legacy", null).source()), "legacy profile damaged"); cases++;
        }
    }
    static void committedPartial() throws Exception {
        try (Daemon daemon = new Daemon(false, true, "server")) {
            BinaryTests.server = Tls.trustPem(certs.resolve("ca.pem"), certs.resolve("server.p12"), "test-only-password".toCharArray());
            try (BinaryTests.Peer proxy = new BinaryTests.Peer((socket, index) -> {
                socket.startHandshake();
                try (SSLSocket upstream = (SSLSocket) mutual.context().getSocketFactory().createSocket("127.0.0.1", daemon.port)) {
                    var parameters = upstream.getSSLParameters(); parameters.setProtocols(new String[]{"TLSv1.3"});
                    parameters.setEndpointIdentificationAlgorithm("HTTPS"); parameters.setApplicationProtocols(new String[]{"yamora-binary/1"});
                    upstream.setSSLParameters(parameters); upstream.setSoTimeout(10000); upstream.startHandshake();
                    check(upstream.getApplicationProtocol().equals("yamora-binary/1"), "proxy native ALPN");
                    Frame hello = BinaryFrameCodec.read(socket.getInputStream(), 4096);
                    BinaryFrameCodec.write(upstream.getOutputStream(), hello.type(), hello.stream(), hello.payload(), 4096);
                    Frame nativeHello = BinaryFrameCodec.read(upstream.getInputStream(), 4096);
                    BinaryFrameCodec.write(socket.getOutputStream(), nativeHello.type(), nativeHello.stream(), nativeHello.payload(), 4096);
                    while (true) {
                        Frame next = BinaryFrameCodec.read(socket.getInputStream(), 4096);
                        BinaryFrameCodec.write(upstream.getOutputStream(), next.type(), next.stream(), next.payload(), 4096);
                        if (next.type() == END) break;
                    }
                    Frame response = BinaryFrameCodec.read(upstream.getInputStream(), 4096);
                    check(response.type() == RESPONSE, "native committed response missing");
                    Frame data = BinaryFrameCodec.read(upstream.getInputStream(), 4096);
                    check(data.type() == DATA, "native committed receipt DATA missing");
                    Frame end = BinaryFrameCodec.read(upstream.getInputStream(), 4096);
                    check(end.type() == END, "native receipt END missing");
                    BinaryFrameCodec.write(socket.getOutputStream(), RESPONSE, 1, response.payload(), 4096);
                    byte[] partial = BinaryTests.raw(DATA, 1, data.payload()); socket.getOutputStream().write(partial, 0, partial.length - 1);
                }
            })) {
                byte[] source = bytes("# committed BEFORE receipt truncation\r\nvalue: '雪'\r\n");
                BinaryClient client = new BinaryClient(config(proxy.listener.getLocalPort(), true, 4096, "127.0.0.1", "ca.pem"));
                BinaryUncertainException uncertain = (BinaryUncertainException) BinaryTests.fails(() ->
                        client.put("config", "one", source, WRITE, null, "*", ID, new BinaryCancellation()), BinaryException.Kind.TRANSPORT, true);
                // Mandatory evidence BEFORE any explicit resend/recovery: source exists
                // through independent HTTP on the real native disk, no replay occurred.
                check(Arrays.equals(source, daemon.http.get("config", "one", null).source()), "known committed source absent BEFORE recovery");
                check(proxy.accepted.get() == 1, "ambiguous native write replayed");
                BinaryEnvelope envelope = uncertain.envelope();
                check(Arrays.equals(source, envelope.source()) && envelope.ifNoneMatch().equals("*") && envelope.target().equals("/v1/collections/config/documents/one"), "original committed envelope lost");
                // Standalone IDs do not deduplicate. Explicit repetition with create-only
                // is rejected as 412, demonstrating why automatic recovery is excluded.
                rejected(() -> daemon.client(true, 4096).put(envelope.collection(), envelope.document(), envelope.source(), WRITE,
                        envelope.ifMatch(), envelope.ifNoneMatch(), envelope.requestId(), new BinaryCancellation()), 412);
                cases++;
            }
        }
    }
    static String digest(Path path) throws Exception {
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        try (var input = Files.newInputStream(path)) { byte[] bytes = new byte[65536]; int n; while ((n = input.read(bytes)) >= 0) hash.update(bytes, 0, n); }
        return HexFormat.of().formatHex(hash.digest());
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 1 || !Path.of(args[0]).isAbsolute() || !Files.isExecutable(Path.of(args[0]))) throw new IllegalArgumentException("required absolute native daemon configuration missing");
        binary = Path.of(args[0]); String before = digest(binary);
        root = Files.createTempDirectory(Path.of(System.getProperty("java.io.tmpdir")), "binary-native-suite-"); certs = root.resolve("certs");
        try {
            Files.createDirectory(certs); NativeTests.certificates(certs);
            mutual = Tls.trustPem(certs.resolve("ca.pem"), certs.resolve("client.p12"), "test-only-password".toCharArray());
            switch (System.getProperty("yamora.binary.native", "all")) {
                case "crud" -> crud(); case "large" -> large(); case "partial" -> committedPartial();
                case "all" -> { crud(); large(); committedPartial(); }
                default -> throw new IllegalArgumentException("unknown native binary group");
            }
        } finally {
            try (var paths = Files.walk(root)) { for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path); }
            check(before.equals(digest(binary)), "read-only native daemon digest changed");
        }
        System.out.println("Java binary native tests passed: " + cases + " cases, " + assertions + " assertions; immutable daemon " + before);
    }
}
