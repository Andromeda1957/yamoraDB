import io.yamora.Json;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.TrustManagerFactory;

/** Negative/control peers exercise the adapter, never native replica receipt qualification. */
public final class HttpReplicaAdapterTests {
    private static final String SCHEMA = "yamora-http-replica-command/2";
    private static final String REV = "0123456789abcdef";
    private static final String ID = "1".repeat(32);
    private static final String READ = "r".repeat(32), WRITE = "w".repeat(32);
    private static final byte[] YAML = bytes("# receipt café\r\nn: 0 # keep\r\n");
    private static final String PATCH = "{ \"$inc\" : { \"n\" : 1 } }\n";
    private static final String RECEIPT = "{ \"status\":\"stored\", \"collection\":\"manifests\","
            + "\"document\":\"counter\",\"etag\":\"" + REV + "\",\"revision\":\"" + REV + "\" }\n";
    private static int assertions;
    private static Path scratch, certs;
    private static SSLContext server;

    private HttpReplicaAdapterTests() {}
    @FunctionalInterface private interface Action { void run() throws Exception; }
    @FunctionalInterface private interface Responder { void respond(Socket socket, byte[] request) throws Exception; }

    private static void check(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }
    private static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static String string(byte[] value) { return new String(value, StandardCharsets.UTF_8); }
    private static Map<String, Object> object(Object... fields) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int i = 0; i < fields.length; i += 2) result.put((String) fields[i], fields[i + 1]);
        return result;
    }
    private static void remove(Path path) throws IOException {
        try (var paths = Files.walk(path)) {
            for (Path item : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(item);
        }
    }
    private static void command(String... args) throws Exception {
        Process child = new ProcessBuilder(args).directory(certs.toFile()).redirectErrorStream(true)
                .redirectOutput(certs.resolve("setup.log").toFile()).start();
        try {
            check(child.waitFor(20, TimeUnit.SECONDS), "certificate setup timed out (infrastructure)");
            check(child.exitValue() == 0, "certificate setup failed (infrastructure)");
        } finally {
            if (child.isAlive()) {
                child.destroyForcibly();
                check(child.waitFor(5, TimeUnit.SECONDS), "owned certificate process leaked");
            }
        }
    }
    private static void certificates() throws Exception {
        command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1",
                "-subj", "/CN=Adapter control CA", "-keyout", "ca.key", "-out", "ca.pem");
        for (String name : List.of("server", "client")) {
            command("openssl", "req", "-new", "-newkey", "rsa:2048", "-noenc", "-subj", "/CN=" + name,
                    "-keyout", name + ".key", "-out", name + ".csr");
            Files.writeString(certs.resolve(name + ".ext"), "extendedKeyUsage="
                    + (name.equals("client") ? "clientAuth" : "serverAuth") + "\nsubjectAltName=IP:127.0.0.1\n");
            command("openssl", "x509", "-req", "-in", name + ".csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                    "-set_serial", name.equals("server") ? "2" : "3", "-days", "1", "-extfile", name + ".ext", "-out", name + ".pem");
        }
        command("openssl", "pkcs12", "-export", "-inkey", "server.key", "-in", "server.pem", "-certfile", "ca.pem",
                "-passout", "pass:control-only", "-out", "server.p12");
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (InputStream input = Files.newInputStream(certs.resolve("server.p12"))) { keys.load(input, "control-only".toCharArray()); }
        KeyManagerFactory km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        km.init(keys, "control-only".toCharArray());
        KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
        trust.load(null, null);
        try (InputStream input = Files.newInputStream(certs.resolve("ca.pem"))) {
            trust.setCertificateEntry("ca", CertificateFactory.getInstance("X.509").generateCertificate(input));
        }
        TrustManagerFactory tm = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tm.init(trust);
        server = SSLContext.getInstance("TLSv1.3");
        server.init(km.getKeyManagers(), tm.getTrustManagers(), null);
    }

    private static String header(byte[] request, String name) {
        for (String line : string(request).split("\r\n")) {
            if (line.startsWith(name + ": ")) return line.substring(name.length() + 2);
        }
        return null;
    }
    private static byte[] body(byte[] request) {
        return Arrays.copyOfRange(request, string(request).indexOf("\r\n\r\n") + 4, request.length);
    }
    private static byte[] request(Socket socket) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int state = 0;
        InputStream input = socket.getInputStream();
        while (state < 4) {
            int next = input.read();
            if (next < 0 || buffer.size() > 16384) throw new IOException("bad control request");
            buffer.write(next);
            state = next == (state % 2 == 0 ? '\r' : '\n') ? state + 1 : (next == '\r' ? 1 : 0);
        }
        int length = Integer.parseInt(header(buffer.toByteArray(), "Content-Length"));
        if (length < 0 || length > 131072) throw new IOException("bad control request size");
        byte[] content = input.readNBytes(length);
        if (content.length != length) throw new IOException("short control request");
        buffer.write(content);
        return buffer.toByteArray();
    }
    private static void reply(Socket socket, int status, String media, byte[] body) throws IOException {
        socket.getOutputStream().write(bytes("HTTP/1.1 " + status + " Control\r\nContent-Length: " + body.length
                + "\r\nContent-Type: " + media + "\r\nX-YamlDB-Revision: " + REV + "\r\n\r\n"));
        socket.getOutputStream().write(body);
    }

    private static final class Peer implements AutoCloseable {
        final SSLServerSocket listener;
        final Thread thread;
        final List<byte[]> mutations = new ArrayList<>();
        final AtomicReference<Throwable> error = new AtomicReference<>();
        volatile boolean closed;
        volatile Socket active;
        Peer(int node, Responder responder) throws IOException {
            listener = (SSLServerSocket) server.getServerSocketFactory().createServerSocket(0, 16, InetAddress.getByName("127.0.0.1"));
            check(listener.getLocalPort() != 8000, "owner port allocated (infrastructure)");
            listener.setEnabledProtocols(new String[]{"TLSv1.3"});
            listener.setNeedClientAuth(true);
            thread = new Thread(() -> {
                try {
                    while (!closed) {
                        try (Socket socket = listener.accept()) {
                            active = socket;
                            socket.setSoTimeout(4000);
                            byte[] received = request(socket);
                            if (string(received).startsWith("GET /v1/cluster/leader ")) {
                                check(("Bearer " + READ).equals(header(received, "Authorization")), "discovery used wrong token");
                                reply(socket, 200, "application/json", bytes("{\"node\":" + node + ",\"leader\":" + node
                                        + ",\"term\":1,\"role\":\"leader\"}"));
                            } else {
                                mutations.add(received);
                                responder.respond(socket, received);
                            }
                        } finally { active = null; }
                    }
                } catch (Throwable failure) { if (!closed) error.set(failure); }
            }, "http-adapter-control-peer");
            thread.start();
        }
        @Override public void close() throws IOException {
            closed = true;
            listener.close();
            Socket socket = active;
            if (socket != null) socket.close();
            try { thread.join(5000); }
            catch (InterruptedException failure) { Thread.currentThread().interrupt(); throw new IOException(failure); }
            check(!thread.isAlive(), "owned control peer leaked (infrastructure)");
            if (error.get() != null) throw new AssertionError("control peer failed (infrastructure)", error.get());
        }
    }

    private static final class Fixture implements AutoCloseable {
        final Path root;
        final List<Peer> peers = new ArrayList<>();
        Map<String, Object> config;
        Fixture(Responder responder) throws Exception {
            root = Files.createTempDirectory(scratch, "session-");
            try {
                Files.createDirectory(root.resolve("input"));
                for (int i = 1; i <= 64; i++) Files.createDirectory(root.resolve(String.format(java.util.Locale.ROOT, "call-%06d", i)));
                for (String name : List.of("ca.pem", "client.pem", "client.key")) Files.copy(certs.resolve(name), root.resolve(name));
                Files.writeString(root.resolve("read.token"), READ);
                Files.writeString(root.resolve("write.token"), WRITE);
                Files.write(root.resolve("input/value.bin"), YAML);
                Files.writeString(root.resolve("input/patch.bin"), PATCH);
                List<Object> seeds = new ArrayList<>();
                for (int node = 1; node <= 3; node++) {
                    Peer peer = new Peer(node, responder);
                    peers.add(peer);
                    seeds.add(object("host", "127.0.0.1", "port", peer.listener.getLocalPort(), "node", node));
                }
                config = object("schema", "yamora-http-replica-config/2", "cluster_id", "01020304000000000000000000000000",
                        "voters", 3, "seeds", seeds, "tls", object("ca_file", "ca.pem", "cert_file", "client.pem", "key_file", "client.key"),
                        "tokens", object("read_file", "read.token", "write_file", "write.token"), "timeout_ms", 15000, "attempt_timeout_ms", 3000);
                saveConfig();
            } catch (Exception | AssertionError failure) { close(); throw failure; }
        }
        void saveConfig() throws IOException { Files.writeString(root.resolve("config.json"), Json.stringify(config)); }
        String[] argv() { return new String[]{"--config", root.resolve("config.json").toString(), "--root", root.toString()}; }
        int dispatched() { return peers.stream().mapToInt(p -> p.mutations.size()).sum(); }
        void noTemporaryIdentity() throws IOException {
            try (var files = Files.list(root)) { check(files.noneMatch(p -> p.getFileName().toString().startsWith(".java-tls-")), "TLS temporary files leaked"); }
        }
        @Override public void close() throws IOException {
            Throwable pending = null;
            try {
                for (Peer peer : peers) {
                    try { peer.close(); }
                    catch (IOException | RuntimeException | AssertionError failure) { pending = failure; }
                }
            } finally { remove(root); }
            if (pending instanceof IOException failure) throw failure;
            if (pending instanceof RuntimeException failure) throw failure;
            if (pending instanceof AssertionError failure) throw failure;
        }
    }

    private record Result(int exit, List<Map<String, Object>> observations, String diagnostics) {}
    private static Result run(Fixture fixture, InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream(), diagnostics = new ByteArrayOutputStream();
        int result = HttpReplicaAdapter.run(fixture.argv(), input, output, diagnostics);
        fixture.noTemporaryIdentity();
        List<Map<String, Object>> observations = new ArrayList<>();
        for (String line : output.toString(StandardCharsets.UTF_8).split("\n")) {
            if (line.isEmpty()) continue;
            check(bytes(line).length + 1 <= 16384, "observation exceeds line limit");
            Map<String, Object> value = Json.object(line);
            check(value.keySet().equals(Set.of("schema", "seq", "action", "outcome", "error_kind", "elapsed_ns", "api",
                    "sdk_request_id", "envelope", "recovery_mode", "recovery_handle")), "observation schema drift");
            check("yamora-http-replica-observation/2".equals(value.get("schema")), "observation version drift");
            check(api(value).keySet().equals(Set.of("status", "body_file", "etag", "revision", "receipt")), "API schema drift");
            observations.add(value);
        }
        check(diagnostics.size() <= 16384 && !diagnostics.toString(StandardCharsets.UTF_8).contains(WRITE)
                && !diagnostics.toString(StandardCharsets.UTF_8).contains("private-control"), "diagnostics leak/unbounded");
        return new Result(result, observations, diagnostics.toString(StandardCharsets.UTF_8));
    }
    private static Result run(Fixture fixture, String source) throws IOException { return run(fixture, new ByteArrayInputStream(bytes(source))); }
    private static String json(Map<String, Object> value) { return Json.stringify(value) + "\n"; }
    private static Map<String, Object> call(int seq, String method, String id, String match, String none) {
        return object("schema", SCHEMA, "seq", seq, "action", "call", "method", method, "collection", "manifests",
                "document", "counter", "source_file", method.equals("PUT") ? "input/value.bin" : method.equals("PATCH") ? "input/patch.bin" : null,
                "request_id", id, "if_match", match, "if_none_match", none);
    }
    private static String close(int seq) { return json(object("schema", SCHEMA, "seq", seq, "action", "close")); }
    private static String recover(int seq, String handle) { return json(object("schema", SCHEMA, "seq", seq, "action", "recover", "handle", handle)); }
    @SuppressWarnings("unchecked") private static Map<String, Object> api(Map<String, Object> observation) { return (Map<String, Object>) observation.get("api"); }
    private static long number(Object value) { return ((Json.NumberValue) value).longValueExact(); }
    private static void noRecovery(Map<String, Object> value) {
        for (String field : List.of("sdk_request_id", "envelope", "recovery_mode", "recovery_handle")) check(value.get(field) == null, "unexposed recovery field was invented: " + field);
    }

    private static void rejection() throws Exception {
        try (Fixture fixture = new Fixture((socket, request) -> reply(socket, 409, "application/json", bytes("private-control " + WRITE)))) {
            StringBuilder commands = new StringBuilder();
            List<Map<String, Object>> calls = List.of(call(1, "PUT", ID, null, "*"), call(2, "PUT", ID, '"' + REV + '"', null),
                    call(3, "PUT", null, null, null), call(4, "PATCH", ID, '"' + REV + '"', null),
                    call(5, "DELETE", ID, null, null), call(6, "GET", null, null, null));
            for (Map<String, Object> call : calls) commands.append(json(call));
            commands.append(close(7));
            Result result = run(fixture, commands.toString());
            check(result.exit() == 0 && result.observations().size() == 7, "handled rejection ended session");
            for (int i = 0; i < calls.size(); i++) {
                Map<String, Object> observed = result.observations().get(i);
                check("status".equals(observed.get("outcome")) && "status".equals(observed.get("error_kind"))
                        && number(api(observed).get("status")) == 409, "409 misclassified as infrastructure/uncertainty");
                noRecovery(observed);
                check(api(observed).get("body_file") == null && api(observed).get("receipt") == null, "private error body exposed");
                byte[] request = fixture.peers.get(0).mutations.get(i);
                check(java.util.Objects.equals(calls.get(i).get("if_match"), header(request, "If-Match")), "present/absent If-Match changed");
                check(java.util.Objects.equals(calls.get(i).get("if_none_match"), header(request, "If-None-Match")), "present/absent If-None-Match changed");
                if (i != 5) check(header(request, "X-Yamora-Request-Id").matches("[0-9a-f]{32}"), "SDK request ID missing");
                check(("Bearer " + (i == 5 ? READ : WRITE)).equals(header(request, "Authorization")), "public call used wrong token");
                if (i < 3) check(Arrays.equals(body(request), YAML), "PUT changed source bytes");
            }
            Map<String, Object> closed = result.observations().get(6);
            check("closed".equals(closed.get("outcome")) && number(closed.get("elapsed_ns")) == 0, "close semantics changed");
            noRecovery(closed);
            check(api(closed).values().stream().allMatch(java.util.Objects::isNull), "close invented API fields");
        }
    }

    private static void exposure() throws Exception {
        try (Fixture fixture = new Fixture((socket, request) -> {
            String first = string(request).split(" ", 2)[0];
            if (first.equals("GET")) {
                byte[] header = bytes("HTTP/1.1 200 Control\r\nContent-Length: " + YAML.length + "\r\nContent-Type: application/yaml\r\n"
                        + "X-YamlDB-Revision: " + REV + "\r\nETag: \"" + REV + "\"\r\n\r\n");
                socket.getOutputStream().write(header);
                socket.getOutputStream().write(YAML);
            } else reply(socket, first.equals("DELETE") ? 204 : first.equals("PUT") ? 201 : 200,
                    "application/json", first.equals("DELETE") ? new byte[0] : bytes(RECEIPT));
        })) {
            Result result = run(fixture, json(call(1, "PUT", ID, null, "*")) + json(call(2, "PATCH", ID, null, null))
                    + json(call(3, "GET", null, null, null)) + json(call(4, "DELETE", ID, null, null)) + close(5));
            check(result.exit() == 0 && result.observations().size() == 5, "control API exposure failed");
            for (int i = 0; i < 4; i++) {
                Map<String, Object> value = result.observations().get(i), api = api(value);
                check("success".equals(value.get("outcome")) && value.get("error_kind") == null, "successful public result lost");
                check(REV.equals(api.get("revision")), "public revision lost");
                noRecovery(value);
                if (i < 2) {
                    check(number(api.get("status")) == (i == 0 ? 201 : 200), "actual JSON reply status lost");
                    check(RECEIPT.equals(Files.readString(fixture.root.resolve((String) api.get("body_file")))), "original JSON reply text reconstructed");
                    check(Json.object(RECEIPT).equals(api.get("receipt")) && REV.equals(api.get("etag")), "public receipt fields lost");
                } else {
                    check(api.get("status") == null && api.get("receipt") == null, "unexposed success status/receipt invented");
                    if (i == 2) check(Arrays.equals(YAML, Files.readAllBytes(fixture.root.resolve((String) api.get("body_file"))))
                            && REV.equals(api.get("etag")), "GET changed exact source/ETag");
                    else check(api.get("body_file") == null && api.get("etag") == null, "DELETE invented body/ETag");
                }
            }
        }
    }

    private static void recovery(boolean generated) throws Exception {
        for (String method : List.of("PUT", "PATCH", "DELETE")) {
            List<byte[]> received = new ArrayList<>();
            try (Fixture fixture = new Fixture((socket, request) -> {
                received.add(request);
                int index = received.size();
                reply(socket, index == 1 ? 500 : index == 2 ? 409 : method.equals("DELETE") ? 204 : 200,
                        "application/json", index <= 2 ? bytes("private-control " + WRITE) : method.equals("DELETE") ? new byte[0] : bytes(RECEIPT));
            })) {
                String initial = json(call(1, method, generated ? null : ID, method.equals("PUT") ? null : '"' + REV + '"', method.equals("PUT") ? "*" : null));
                byte[] stream = bytes(initial + recover(2, "h1") + recover(3, "h1") + recover(4, "h1") + close(5));
                InputStream input = new ByteArrayInputStream(stream) {
                    @Override public synchronized int read() {
                        if (pos == bytes(initial).length) {
                            try {
                                Files.writeString(fixture.root.resolve("input/value.bin"), "changed: true\n");
                                Files.writeString(fixture.root.resolve("input/patch.bin"), "{\"$inc\":{\"n\":99}}");
                            } catch (IOException failure) { throw new java.io.UncheckedIOException(failure); }
                        }
                        return super.read();
                    }
                };
                Result result = run(fixture, input);
                check(result.exit() == 0 && result.observations().size() == 5, "same-session recovery failed");
                Map<String, Object> uncertain = result.observations().get(0);
                String actual = header(received.get(0), "X-Yamora-Request-Id");
                check("uncertain".equals(uncertain.get("outcome")) && actual.equals(uncertain.get("sdk_request_id"))
                        && "h1".equals(uncertain.get("recovery_handle")), "uncertainty lost actual exception ID/handle");
                check(generated ? actual.matches("[0-9a-f]{32}") && !actual.equals("0".repeat(32)) : ID.equals(actual), "supplied/generated request ID mapping changed");
                for (int i = 1; i < 4; i++) {
                    Map<String, Object> value = result.observations().get(i);
                    check("h1".equals(value.get("recovery_handle")) && "caller-reissue".equals(value.get("recovery_mode"))
                            && value.get("sdk_request_id") == null && value.get("envelope") == null, "recovery lifetime/null exposure changed");
                    check(actual.equals(header(received.get(i), "X-Yamora-Request-Id")), "recovery changed actual SDK request ID");
                    check(Arrays.equals(received.get(0), received.get(i)), "recovery changed primitive/source/preconditions");
                    check((i == 1 ? "status" : "success").equals(value.get("outcome")), "recovery rejection/success misclassified");
                }
                if (method.equals("PATCH")) check(Json.object(string(body(received.get(0)))).equals(Json.object(PATCH)), "typed PATCH semantics changed");
            }
        }
    }

    private static void invalidInputs() throws Exception {
        try (Fixture fixture = new Fixture((socket, request) -> reply(socket, 409, "application/json", bytes("{}")))) {
            List<String> commands = new ArrayList<>(List.of("", "{", close(2), recover(1, "h1"),
                    close(1).replace("\"seq\":1", "\"seq\":1,\"seq\":1"), close(1).replace("\"seq\":1", "\"seq\":1.0"),
                    close(1).replace("\"action\":\"close\"", "\"action\":\"close\",\"extra\":true"),
                    "{\"nest\":" + "[".repeat(13) + "0" + "]".repeat(13) + "}\n", " ".repeat(16384) + "\n"));
            for (String key : List.of("request_id", "if_match", "if_none_match", "source_file")) {
                Map<String, Object> omitted = call(1, "PUT", null, null, null);
                omitted.remove(key);
                commands.add(json(omitted));
            }
            for (Object[] bad : List.of(new Object[]{"request_id", "0".repeat(32)}, new Object[]{"request_id", true},
                    new Object[]{"if_match", REV}, new Object[]{"if_match", ""}, new Object[]{"if_none_match", ""},
                    new Object[]{"source_file", "../escape.bin"}, new Object[]{"source_file", "/input/value.bin"},
                    new Object[]{"source_file", "input/../value.bin"}, new Object[]{"collection", "yamldb-system"},
                    new Object[]{"document", "../counter"}, new Object[]{"method", "POST"})) {
                Map<String, Object> value = call(1, "PUT", ID, null, null);
                value.put((String) bad[0], bad[1]);
                commands.add(json(value));
            }
            commands.add(json(call(1, "PUT", ID, '"' + REV + '"', "*")));
            commands.add(json(call(1, "GET", ID, null, null)));
            commands.add(json(call(1, "DELETE", ID, null, "*")));
            for (String command : commands) {
                Result result = run(fixture, command);
                check(result.exit() != 0 && result.observations().isEmpty(), "invalid command accepted");
            }
            check(run(fixture, new ByteArrayInputStream(new byte[]{(byte) 0xc0, (byte) 0x80, '\n'})).exit() != 0, "invalid UTF-8 accepted");
            check(fixture.dispatched() == 0, "invalid input dispatched a public call");
            Result boundary = run(fixture, close(1).stripTrailing() + " ".repeat(16384 - bytes(close(1)).length) + "\n");
            check(boundary.exit() == 0, "legal 16 KiB command rejected");
            Result incomplete = run(fixture, json(call(1, "GET", null, null, null)));
            check(incomplete.exit() != 0 && incomplete.observations().size() == 1, "EOF without close accepted");
            Result interrupted = run(fixture, new InputStream() {
                @Override public int read() throws IOException { throw new InterruptedIOException("private-control " + WRITE); }
            });
            check(interrupted.exit() != 0 && interrupted.observations().isEmpty(), "interrupted input accepted");
            Result unexpected = run(fixture, new InputStream() {
                @Override public int read() { throw new IllegalStateException("private-control " + WRITE); }
            });
            check(unexpected.exit() != 0 && unexpected.observations().isEmpty(), "unexpected failure exited zero");
        }
    }

    private static void pathsAndFiles() throws Exception {
        try (Fixture fixture = new Fixture((socket, request) -> reply(socket, 201, "application/json", bytes(RECEIPT)))) {
            Path original = fixture.root.resolve("input/value.bin"), preserved = fixture.root.resolve("preserved.bin");
            Files.move(original, preserved);
            Files.createSymbolicLink(original, preserved);
            check(run(fixture, json(call(1, "PUT", ID, null, null))).exit() != 0 && fixture.dispatched() == 0, "source symlink followed");
            Files.delete(original);
            Files.move(preserved, original);
            Files.move(fixture.root.resolve("input"), fixture.root.resolve("saved-input"));
            Files.createSymbolicLink(fixture.root.resolve("input"), fixture.root.resolve("saved-input"));
            check(run(fixture, json(call(1, "PUT", ID, null, null))).exit() != 0 && fixture.dispatched() == 0, "source directory symlink followed");
            Files.delete(fixture.root.resolve("input"));
            Files.move(fixture.root.resolve("saved-input"), fixture.root.resolve("input"));
            for (byte[] bad : List.of(new byte[0], new byte[131073], new byte[]{(byte) 0xc0, (byte) 0x80})) {
                Files.write(original, bad);
                check(run(fixture, json(call(1, "PUT", ID, null, null))).exit() != 0 && fixture.dispatched() == 0, "invalid source dispatched");
            }
            Files.write(original, YAML);
            for (String bad : List.of("{}", "{\"$inc\":{\"n\":2}}", "{\"$inc\":{\"n\":1,\"n\":1}}", "{\"$inc\":{\"n\":1.0}}")) {
                Files.writeString(fixture.root.resolve("input/patch.bin"), bad);
                check(run(fixture, json(call(1, "PATCH", ID, null, null))).exit() != 0 && fixture.dispatched() == 0, "invalid PATCH dispatched");
            }
            Files.writeString(preserved, "preserve");
            Files.createSymbolicLink(fixture.root.resolve("call-000001/body.bin"), preserved);
            Result output = run(fixture, json(call(1, "PUT", ID, null, null)) + close(2));
            check(output.exit() != 0 && Files.readString(preserved).equals("preserve"), "output symlink overwritten");
            Files.delete(fixture.root.resolve("call-000001/body.bin"));
            Files.delete(fixture.root.resolve("call-000001"));
            Files.createSymbolicLink(fixture.root.resolve("call-000001"), fixture.root.resolve("call-000002"));
            check(run(fixture, json(call(1, "PUT", ID, null, null))).exit() != 0
                    && !Files.exists(fixture.root.resolve("call-000002/body.bin")), "output directory symlink followed");
            Map<String, Object> saved = new LinkedHashMap<>(fixture.config);
            for (Map<String, Object> bad : List.of(object("voters", 2), object("timeout_ms", 15001), object("attempt_timeout_ms", 3001),
                    object("cluster_id", "0".repeat(32)), object("tls", object("ca_file", "../ca.pem", "cert_file", "client.pem", "key_file", "client.key")),
                    object("seeds", List.of(object("host", "localhost", "port", 8000, "node", 1))))) {
                fixture.config = new LinkedHashMap<>(saved);
                fixture.config.putAll(bad);
                fixture.saveConfig();
                check(run(fixture, close(1)).exit() != 0, "invalid config accepted");
            }
            fixture.config = saved;
            fixture.saveConfig();
            Files.writeString(fixture.root.resolve("client.key"), "malformed private-control");
            check(run(fixture, close(1)).exit() != 0, "invalid TLS key accepted");
        }
    }

    private static void bounds() throws Exception {
        try (Fixture fixture = new Fixture((socket, request) -> reply(socket, 500, "application/json", bytes("{}")))) {
            StringBuilder stream = new StringBuilder();
            for (int i = 1; i <= 17; i++) stream.append(json(call(i, "PATCH", null, null, null)));
            Result result = run(fixture, stream.toString());
            check(result.exit() != 0 && result.observations().size() == 16 && fixture.dispatched() == 16, "recovery handle bound did not reject before dispatch");
            for (int i = 1; i <= 16; i++) check(("h" + i).equals(result.observations().get(i - 1).get("recovery_handle")), "handle order changed");
        }
        try (Fixture fixture = new Fixture((socket, request) -> reply(socket, 409, "application/json", bytes("{}")))) {
            StringBuilder stream = new StringBuilder();
            for (int i = 1; i <= 64; i++) stream.append(json(call(i, "GET", null, null, null)));
            stream.append(close(65));
            Result result = run(fixture, stream.toString());
            check(result.exit() != 0 && result.observations().size() == 64 && fixture.dispatched() == 64, "64-command bound changed");
        }
    }

    private static void process() throws Exception {
        try (Fixture fixture = new Fixture((socket, request) -> reply(socket, 409, "application/json", bytes("{}")))) {
            for (String stdin : List.of(close(1), "", close(1).stripTrailing())) {
                List<String> args = new ArrayList<>(List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                        "-Djava.io.tmpdir=" + System.getenv("TMPDIR"), "-cp", System.getProperty("java.class.path"), "HttpReplicaAdapter"));
                args.addAll(List.of(fixture.argv()));
                Process child = new ProcessBuilder(args).redirectOutput(fixture.root.resolve("stdout.log").toFile())
                        .redirectError(fixture.root.resolve("stderr.log").toFile()).start();
                try {
                    child.getOutputStream().write(bytes(stdin));
                    child.getOutputStream().close();
                    check(child.waitFor(25, TimeUnit.SECONDS), "adapter watchdog expired (infrastructure)");
                    check((child.exitValue() == 0) == stdin.endsWith("\n"), "process EOF/close exit status changed");
                    fixture.noTemporaryIdentity();
                } finally {
                    if (child.isAlive()) {
                        child.destroyForcibly();
                        check(child.waitFor(5, TimeUnit.SECONDS), "owned adapter process leaked");
                    }
                }
            }
        }
    }

    private static void frozenFrame() throws Exception {
        try (Fixture fixture = new Fixture((socket, request) -> reply(socket, 409, "application/json", bytes("{}")))) {
            Result result = run(fixture, close(1).replace("\n", "\r\n"));
            check(result.exit() != 0 && result.observations().isEmpty() && fixture.dispatched() == 0,
                    "literal CR command framing accepted");
        }
    }

    private static void frozenConfigBudget() throws Exception {
        try (Fixture fixture = new Fixture((socket, request) -> reply(socket, 409, "application/json", bytes("{}")))) {
            Files.writeString(fixture.root.resolve("config.json"), Json.stringify(fixture.config) + " ".repeat(16384));
            Result result = run(fixture, close(1));
            check(result.exit() != 0 && result.observations().isEmpty() && fixture.dispatched() == 0,
                    "over-16-KiB config accepted");
        }
    }

    private static void frozenTlsBudget(String name) throws Exception {
        try (Fixture fixture = new Fixture((socket, request) -> reply(socket, 409, "application/json", bytes("{}")))) {
            Path path = fixture.root.resolve(name);
            Files.writeString(path, Files.readString(path) + " ".repeat(16384));
            Result result = run(fixture, close(1));
            check(result.exit() != 0 && result.observations().isEmpty() && fixture.dispatched() == 0,
                    "over-16-KiB TLS file accepted: " + name);
        }
    }

    private static void invalidOutputBeforeDispatch(String method, String problem) throws Exception {
        try (Fixture fixture = new Fixture((socket, request) -> reply(socket, method.equals("PUT") ? 201 : 200,
                "application/json", bytes(RECEIPT)))) {
            Path directory = fixture.root.resolve("call-000001"), preserved = fixture.root.resolve("preserved.bin");
            Files.writeString(preserved, "preserve");
            switch (problem) {
                case "directory-symlink" -> {
                    Files.delete(directory);
                    Files.createSymbolicLink(directory, fixture.root.resolve("call-000002"));
                }
                case "missing-directory" -> Files.delete(directory);
                case "existing-body" -> Files.writeString(directory.resolve("body.bin"), "preserve");
                case "body-symlink" -> Files.createSymbolicLink(directory.resolve("body.bin"), preserved);
                default -> throw new IllegalArgumentException();
            }
            Result result = run(fixture, json(call(1, method, ID, null, null)) + close(2));
            check(result.exit() != 0 && result.observations().isEmpty(), "invalid output was accepted: " + method + "/" + problem);
            check(fixture.dispatched() == 0, "invalid output dispatched: " + method + "/" + problem);
            check(Files.readString(preserved).equals("preserve"), "output reservation changed sentinel");
            if (problem.equals("existing-body")) check(Files.readString(directory.resolve("body.bin")).equals("preserve"), "existing body overwritten");
            if (problem.equals("directory-symlink")) check(!Files.exists(fixture.root.resolve("call-000002/body.bin")), "output escaped through symlink");
        }
    }

    private static void recoveryOutputBeforeDispatch() throws Exception {
        try (Fixture fixture = new Fixture((socket, request) -> reply(socket, 500, "application/json", bytes("{}")))) {
            Files.delete(fixture.root.resolve("call-000002"));
            Files.createSymbolicLink(fixture.root.resolve("call-000002"), fixture.root.resolve("call-000003"));
            Result result = run(fixture, json(call(1, "PATCH", ID, null, null)) + recover(2, "h1") + close(3));
            check(fixture.dispatched() == 1, "invalid recovery output dispatched");
            check(result.exit() != 0 && result.observations().size() == 1
                    && "uncertain".equals(result.observations().get(0).get("outcome")), "invalid recovery output lost initial observation");
            check(!Files.exists(fixture.root.resolve("call-000001/body.bin")), "uncertain call retained unused body reservation");
        }
    }

    private static void emptyToken(String name) throws Exception {
        try (Fixture fixture = new Fixture((socket, request) -> reply(socket, 409, "application/json", bytes("{}")))) {
            Files.write(fixture.root.resolve(name), new byte[0]);
            Result result = run(fixture, close(1));
            check(result.exit() != 0 && result.observations().isEmpty(), "empty token accepted: " + name);
            check(fixture.dispatched() == 0, "empty token dispatched");
        }
    }

    private static void exactAttemptBudget() throws Exception {
        try (Fixture fixture = new Fixture((socket, request) -> reply(socket, 409, "application/json", bytes("{}")))) {
            fixture.config.put("attempt_timeout_ms", 1000);
            fixture.saveConfig();
            Result result = run(fixture, close(1));
            check(result.exit() != 0 && result.observations().isEmpty(), "non-frozen attempt budget accepted");
            check(fixture.dispatched() == 0, "non-frozen attempt budget dispatched");
        }
    }

    public static void main(String[] args) throws Exception {
        Path base = Path.of(System.getenv("TMPDIR"));
        check(base.isAbsolute() && !Files.isSymbolicLink(base), "owned TMPDIR required (infrastructure)");
        scratch = Files.createTempDirectory(base, "java-adapter-tests-");
        try {
            certs = Files.createDirectory(scratch.resolve("certs"));
            certificates();
            Map<String, Action> tests = new LinkedHashMap<>();
            tests.put("rejection", HttpReplicaAdapterTests::rejection);
            tests.put("exposure", HttpReplicaAdapterTests::exposure);
            tests.put("recovery-supplied", () -> recovery(false));
            tests.put("recovery-generated", () -> recovery(true));
            tests.put("invalid-inputs", HttpReplicaAdapterTests::invalidInputs);
            tests.put("paths-files", HttpReplicaAdapterTests::pathsAndFiles);
            tests.put("bounds", HttpReplicaAdapterTests::bounds);
            tests.put("process", HttpReplicaAdapterTests::process);
            tests.put("frozen-frame", HttpReplicaAdapterTests::frozenFrame);
            tests.put("frozen-config-budget", HttpReplicaAdapterTests::frozenConfigBudget);
            tests.put("frozen-ca-budget", () -> frozenTlsBudget("ca.pem"));
            tests.put("frozen-cert-budget", () -> frozenTlsBudget("client.pem"));
            tests.put("frozen-key-budget", () -> frozenTlsBudget("client.key"));
            for (String method : List.of("PUT", "PATCH")) {
                for (String problem : List.of("directory-symlink", "missing-directory", "existing-body", "body-symlink")) {
                    tests.put("output-" + method.toLowerCase(java.util.Locale.ROOT) + "-" + problem,
                            () -> invalidOutputBeforeDispatch(method, problem));
                }
            }
            tests.put("recovery-output", HttpReplicaAdapterTests::recoveryOutputBeforeDispatch);
            tests.put("empty-read-token", () -> emptyToken("read.token"));
            tests.put("empty-write-token", () -> emptyToken("write.token"));
            tests.put("exact-attempt-budget", HttpReplicaAdapterTests::exactAttemptBudget);
            if (args.length > 1 || args.length == 1 && !tests.containsKey(args[0])) throw new IllegalArgumentException();
            for (var entry : tests.entrySet()) {
                if (args.length == 0 || args[0].equals(entry.getKey())) {
                    entry.getValue().run();
                    System.out.println("PASS control " + entry.getKey());
                }
            }
            System.out.println("HTTP replica adapter control assertions: " + assertions + "; native qualification not run");
        } finally { remove(scratch); }
    }
}
