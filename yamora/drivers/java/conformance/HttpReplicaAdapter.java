import io.yamora.ClusterConfig;
import io.yamora.Json;
import io.yamora.Tls;
import io.yamora.YamoraClient;
import io.yamora.YamoraException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SecureDirectoryStream;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Persistent v2 HTTP receipt adapter. Routing, encoding and retries belong to the public SDK. */
public final class HttpReplicaAdapter {
    private static final int LINE_LIMIT = 16384;
    private static final int FILE_LIMIT = 131072;
    private static final String COMMAND = "yamora-http-replica-command/2";
    private static final Set<String> CALL_KEYS = Set.of("schema", "seq", "action", "method", "collection",
            "document", "source_file", "request_id", "if_match", "if_none_match");

    private HttpReplicaAdapter() {}

    private static IllegalArgumentException invalid() { return new IllegalArgumentException("invalid adapter input"); }

    private static Map<String, Object> object(Object... pairs) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) result.put((String) pairs[i], pairs[i + 1]);
        return result;
    }

    private static void keys(Map<String, Object> value, Set<String> expected) {
        if (!value.keySet().equals(expected)) throw invalid();
    }

    private static String text(Object value) {
        if (!(value instanceof String result)) throw invalid();
        return result;
    }

    private static String nullableText(Object value) { return value == null ? null : text(value); }

    private static int integer(Object value) {
        if (!(value instanceof Json.NumberValue number) || !number.text().matches("[1-9][0-9]*")) throw invalid();
        return Math.toIntExact(number.longValueExact());
    }

    private static String utf8(byte[] value) throws IOException {
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(value)).toString();
    }

    private static Map<String, Object> parse(byte[] value) throws IOException {
        String source = utf8(value);
        int depth = 0;
        boolean quoted = false, escaped = false;
        for (int i = 0; i < source.length(); i++) {
            char ch = source.charAt(i);
            if (quoted) {
                if (escaped) escaped = false;
                else if (ch == '\\') escaped = true;
                else if (ch == '"') quoted = false;
            } else if (ch == '"') quoted = true;
            else if (ch == '{' || ch == '[') { if (++depth > 12) throw invalid(); }
            else if (ch == '}' || ch == ']') depth--;
        }
        return Json.object(source); // Public strict parser rejects duplicate keys and invalid number tokens.
    }

    private static byte[] line(InputStream input) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        while (true) {
            if (Thread.currentThread().isInterrupted()) throw new InterruptedIOException();
            int next = input.read();
            if (next < 0) throw new IOException("incomplete session");
            if (next == '\n') return result.toByteArray();
            if (next == '\r') throw invalid();
            if (result.size() >= LINE_LIMIT - 1) throw invalid();
            result.write(next);
        }
    }

    /** Descriptor-relative file operations reject symlinks in both source and output directories. */
    private static final class OwnedFiles implements AutoCloseable {
        final Path path;
        final SecureDirectoryStream<Path> root;

        @SuppressWarnings("unchecked")
        OwnedFiles(Path path) throws IOException {
            if (!path.isAbsolute() || !path.equals(path.normalize())) throw invalid();
            Path ancestor = path.getRoot();
            for (Path part : path) {
                ancestor = ancestor.resolve(part);
                if (Files.isSymbolicLink(ancestor)) throw invalid();
            }
            DirectoryStream<Path> stream = Files.newDirectoryStream(path);
            if (!(stream instanceof SecureDirectoryStream<?>)) {
                stream.close();
                throw new IOException("secure directory operations unavailable");
            }
            this.path = path;
            root = (SecureDirectoryStream<Path>) stream;
        }

        byte[] read(String name, int maximum) throws IOException {
            String[] parts = name.split("/", -1);
            if (parts.length > 2 || Arrays.stream(parts).anyMatch(p -> !p.matches("[a-z0-9.-]+")
                    || p.equals(".") || p.equals(".."))) throw invalid();
            if (parts.length == 1) return read(root, Path.of(parts[0]), maximum);
            try (var child = root.newDirectoryStream(Path.of(parts[0]), LinkOption.NOFOLLOW_LINKS)) {
                return read(child, Path.of(parts[1]), maximum);
            }
        }

        private static byte[] read(SecureDirectoryStream<Path> directory, Path name, int maximum) throws IOException {
            if (!directory.getFileAttributeView(name, BasicFileAttributeView.class, LinkOption.NOFOLLOW_LINKS)
                    .readAttributes().isRegularFile()) throw invalid();
            try (SeekableByteChannel input = directory.newByteChannel(name,
                    Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
                ByteBuffer bytes = ByteBuffer.allocate(maximum + 1);
                while (bytes.hasRemaining() && input.read(bytes) >= 0) { /* bounded, including growing files */ }
                if (bytes.position() > maximum) throw invalid();
                return Arrays.copyOf(bytes.array(), bytes.position());
            }
        }

        ReservedOutput reserveOutput(int seq, boolean bodyRequired) throws IOException {
            String directory = String.format(java.util.Locale.ROOT, "call-%06d", seq);
            var child = root.newDirectoryStream(Path.of(directory), LinkOption.NOFOLLOW_LINKS);
            try {
                SeekableByteChannel output = bodyRequired ? child.newByteChannel(Path.of("body.bin"),
                        Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) : null;
                return new ReservedOutput(child, output, directory + "/body.bin");
            } catch (IOException | RuntimeException error) {
                try { child.close(); } catch (IOException closeError) { error.addSuppressed(closeError); }
                throw error;
            }
        }

        @Override public void close() throws IOException { root.close(); }
    }

    /** Reserve the destination before dispatch and keep both handles pinned through observation. */
    private static final class ReservedOutput implements AutoCloseable {
        private final SecureDirectoryStream<Path> directory;
        private final SeekableByteChannel output;
        private final String name;
        private boolean written, retained;

        ReservedOutput(SecureDirectoryStream<Path> directory, SeekableByteChannel output, String name) {
            this.directory = directory;
            this.output = output;
            this.name = name;
        }

        String body(byte[] value) throws IOException {
            if (output == null || written || value.length > FILE_LIMIT) throw invalid();
            ByteBuffer bytes = ByteBuffer.wrap(value);
            while (bytes.hasRemaining()) output.write(bytes);
            written = true;
            return name;
        }

        void retain() { retained = written; }

        @Override public void close() throws IOException {
            try (var child = directory) {
                try { if (output != null) output.close(); }
                finally { if (output != null && !retained) child.deleteFile(Path.of("body.bin")); }
            }
        }
    }

    private static byte[] identity(byte[] cert, byte[] pem) throws Exception {
        String source = utf8(pem).strip();
        String begin = "-----BEGIN PRIVATE KEY-----", end = "-----END PRIVATE KEY-----";
        if (!source.startsWith(begin) || !source.endsWith(end)) throw invalid();
        byte[] der = Base64.getDecoder().decode(source.substring(begin.length(), source.length() - end.length())
                .replaceAll("[\\r\\n\\t ]", ""));
        try {
            PrivateKey key = null;
            for (String algorithm : List.of("RSA", "EC", "Ed25519", "Ed448", "DSA")) {
                try { key = KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der)); break; }
                catch (java.security.GeneralSecurityException ignored) { /* Next JDK key algorithm. */ }
            }
            if (key == null) throw invalid();
            Certificate[] chain = CertificateFactory.getInstance("X.509")
                    .generateCertificates(new ByteArrayInputStream(cert)).toArray(Certificate[]::new);
            if (chain.length < 1 || chain.length > 8) throw invalid();
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(null, new char[0]);
            store.setKeyEntry("adapter", key, new char[0], chain);
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            store.store(output, new char[0]);
            return output.toByteArray();
        } finally { Arrays.fill(der, (byte) 0); }
    }

    private static Map<String, Object> nested(Map<String, Object> value, String key, Set<String> fields) {
        Object entry = value.get(key);
        if (!(entry instanceof Map<?, ?>)) throw invalid();
        @SuppressWarnings("unchecked") Map<String, Object> result = (Map<String, Object>) entry;
        keys(result, fields);
        return result;
    }

    private static String slot(Map<String, Object> value, String key, String expected) {
        if (!expected.equals(value.get(key))) throw invalid();
        return expected;
    }

    private static YamoraClient client(OwnedFiles files) throws Exception {
        Map<String, Object> config = parse(files.read("config.json", LINE_LIMIT));
        keys(config, Set.of("schema", "cluster_id", "voters", "seeds", "tls", "tokens", "timeout_ms", "attempt_timeout_ms"));
        slot(config, "schema", "yamora-http-replica-config/2");
        String cluster = text(config.get("cluster_id"));
        if (!cluster.matches("[0-9a-f]{32}") || cluster.equals("0".repeat(32)) || integer(config.get("voters")) != 3
                || integer(config.get("timeout_ms")) != 15000) throw invalid();
        int attempt = integer(config.get("attempt_timeout_ms"));
        if (attempt != 3000) throw invalid();
        if (!(config.get("seeds") instanceof List<?> seeds) || seeds.size() != 3) throw invalid();
        List<ClusterConfig.Seed> endpoints = new ArrayList<>();
        Set<Integer> nodes = new HashSet<>(), ports = new HashSet<>();
        for (Object entry : seeds) {
            if (!(entry instanceof Map<?, ?> seed) || !seed.keySet().equals(Set.of("host", "port", "node"))
                    || !"127.0.0.1".equals(seed.get("host"))) throw invalid();
            int node = integer(seed.get("node")), port = integer(seed.get("port"));
            if (node > 3 || port > 65535 || port == 8000 || !nodes.add(node) || !ports.add(port)) throw invalid();
            endpoints.add(new ClusterConfig.Seed("127.0.0.1", port));
        }
        Map<String, Object> tls = nested(config, "tls", Set.of("ca_file", "cert_file", "key_file"));
        byte[] ca = files.read(slot(tls, "ca_file", "ca.pem"), LINE_LIMIT);
        byte[] cert = files.read(slot(tls, "cert_file", "client.pem"), LINE_LIMIT);
        byte[] key = files.read(slot(tls, "key_file", "client.key"), LINE_LIMIT);
        Map<String, Object> tokens = nested(config, "tokens", Set.of("read_file", "write_file"));
        String read = utf8(files.read(slot(tokens, "read_file", "read.token"), 512));
        String write = utf8(files.read(slot(tokens, "write_file", "write.token"), 512));
        if (read.isEmpty() || write.isEmpty()) throw invalid();
        // The public TLS constructor consumes a PKCS12 path. Temporary files contain only bounded
        // copies read through the owned directory, and disappear before the session reads commands.
        Path temporary = Files.createTempDirectory(files.path, ".java-tls-");
        byte[] pkcs12 = null;
        try {
            pkcs12 = identity(cert, key);
            Files.write(temporary.resolve("ca.pem"), ca, StandardOpenOption.CREATE_NEW);
            Files.write(temporary.resolve("identity.p12"), pkcs12, StandardOpenOption.CREATE_NEW);
            Tls verified = Tls.trustPem(temporary.resolve("ca.pem"), temporary.resolve("identity.p12"), new char[0]);
            // Cluster/node/voter labels are validated fixture metadata; the public SDK accepts seeds and TLS.
            return YamoraClient.replicaSet(new ClusterConfig(endpoints, verified, Duration.ofSeconds(15),
                    Duration.ofMillis(attempt), FILE_LIMIT, FILE_LIMIT), read, write);
        } finally {
            Arrays.fill(key, (byte) 0);
            if (pkcs12 != null) Arrays.fill(pkcs12, (byte) 0);
            Files.deleteIfExists(temporary.resolve("identity.p12"));
            Files.deleteIfExists(temporary.resolve("ca.pem"));
            Files.delete(temporary);
        }
    }

    /** Inputs are copied before dispatch, never reread from command files during caller reissue. */
    private record SavedCall(String method, String collection, String document, byte[] source,
                             String patch, String etag, boolean createOnly, String requestId) {
        SavedCall { source = source == null ? null : source.clone(); }
        @Override public byte[] source() { return source == null ? null : source.clone(); }

        PublicCall invocation(YamoraClient client, String id) {
            YamoraClient.WriteOptions options = new YamoraClient.WriteOptions(etag, createOnly, id);
            return switch (method) {
                case "GET" -> () -> client.get(collection, document, null);
                case "PUT" -> {
                    byte[] exact = source();
                    yield () -> client.put(collection, document, exact, options);
                }
                case "PATCH" -> () -> client.patch(collection, document, patch, options);
                case "DELETE" -> () -> client.delete(collection, document, options);
                default -> throw invalid();
            };
        }
    }

    @FunctionalInterface private interface PublicCall { Object invoke() throws YamoraException; }

    private record Recovery(SavedCall call, YamoraException error) {}

    private static SavedCall prepare(Map<String, Object> command, OwnedFiles files) throws IOException {
        keys(command, CALL_KEYS);
        String method = text(command.get("method")), collection = text(command.get("collection")),
                document = text(command.get("document"));
        if (!Set.of("GET", "PUT", "PATCH", "DELETE").contains(method)
                || !collection.matches("[a-z0-9-]{1,128}") || !document.matches("[a-z0-9-]{1,128}")
                || !method.equals("GET") && collection.equals("yamldb-system")) throw invalid();
        String id = nullableText(command.get("request_id")), match = nullableText(command.get("if_match")),
                none = nullableText(command.get("if_none_match")), name = nullableText(command.get("source_file"));
        if (id != null && (!id.matches("[0-9a-f]{32}") || id.equals("0".repeat(32)))) throw invalid();
        if (match != null && !match.matches("\"[0-9a-f]{16}\"")) throw invalid();
        if (none != null && (!none.equals("*") || !method.equals("PUT") || match != null)) throw invalid();
        if (method.equals("GET") && (id != null || match != null || none != null)) throw invalid();
        byte[] source = null;
        String patch = null;
        if (method.equals("PUT") || method.equals("PATCH")) {
            if (name == null || !name.matches("input/[a-z0-9-]{1,64}\\.bin")) throw invalid();
            source = files.read(name, FILE_LIMIT);
            if (source.length == 0) throw invalid();
            String decoded = utf8(source);
            if (method.equals("PATCH")) {
                Map<String, Object> operators = parse(source);
                keys(operators, Set.of("$inc"));
                Map<String, Object> increment = nested(operators, "$inc", Set.of("n"));
                if (!(increment.get("n") instanceof Json.NumberValue number) || !number.text().equals("1")) throw invalid();
                patch = decoded;
            }
        } else if (name != null) throw invalid();
        return new SavedCall(method, collection, document, source, patch,
                match == null ? null : match.substring(1, 17), none != null, id);
    }

    private static String kind(YamoraException failure) {
        return switch (failure.kind()) {
            case HTTP, SCHEMA_POLICY_REPLICATION_UNSUPPORTED -> "status";
            case TRANSPORT -> "transport";
            case PROTOCOL -> "protocol";
        };
    }

    private static Map<String, Object> observation(int seq, String action) {
        return object("schema", "yamora-http-replica-observation/2", "seq", seq, "action", action,
                "outcome", "closed", "error_kind", null, "elapsed_ns", 0,
                "api", object("status", null, "body_file", null, "etag", null, "revision", null, "receipt", null),
                "sdk_request_id", null, "envelope", null, "recovery_mode", null, "recovery_handle", null);
    }

    private static void emit(OutputStream output, Map<String, Object> observation) throws IOException {
        byte[] bytes = (Json.stringify(observation) + "\n").getBytes(StandardCharsets.UTF_8);
        if (bytes.length > LINE_LIMIT) throw invalid();
        output.write(bytes);
        output.flush();
    }

    private static void session(YamoraClient client, OwnedFiles files, InputStream input, OutputStream output) throws Exception {
        Map<String, Recovery> retained = new LinkedHashMap<>();
        for (int seq = 1; seq <= 64; seq++) {
            Map<String, Object> command = parse(line(input));
            if (!COMMAND.equals(command.get("schema")) || integer(command.get("seq")) != seq) throw invalid();
            String action = text(command.get("action"));
            Map<String, Object> observation = observation(seq, action);
            if (action.equals("close")) {
                keys(command, Set.of("schema", "seq", "action"));
                emit(output, observation);
                return;
            }
            SavedCall call;
            String handle = null, id;
            if (action.equals("call")) {
                call = prepare(command, files);
                if (!call.method().equals("GET") && retained.size() == 16) throw invalid();
                id = call.requestId();
            } else if (action.equals("recover")) {
                keys(command, Set.of("schema", "seq", "action", "handle"));
                handle = text(command.get("handle"));
                Recovery recovery = retained.get(handle);
                if (recovery == null) throw invalid();
                call = recovery.call();
                id = recovery.error().requestId();
                observation.put("recovery_handle", handle);
                observation.put("recovery_mode", "caller-reissue");
            } else throw invalid();
            try (ReservedOutput reserved = files.reserveOutput(seq, !call.method().equals("DELETE"))) {
                Object value = null;
                YamoraException failure = null;
                PublicCall invocation = call.invocation(client, id);
                long started = System.nanoTime();
                try { value = invocation.invoke(); }
                catch (YamoraException error) { failure = error; }
                finally { observation.put("elapsed_ns", Math.max(0, System.nanoTime() - started)); }
                @SuppressWarnings("unchecked") Map<String, Object> api = (Map<String, Object>) observation.get("api");
                if (failure != null) {
                    observation.put("error_kind", kind(failure));
                    observation.put("outcome", failure.outcomeUncertain() ? "uncertain" : kind(failure));
                    if (failure.status() != 0) api.put("status", failure.status());
                    if (failure.outcomeUncertain()) {
                        if (call.method().equals("GET") || failure.requestId() == null) throw invalid();
                        if (handle == null) handle = "h" + (retained.size() + 1);
                        retained.put(handle, new Recovery(call, failure));
                        observation.put("sdk_request_id", failure.requestId());
                        observation.put("recovery_mode", "caller-reissue");
                        observation.put("recovery_handle", handle);
                    }
                } else {
                    observation.put("outcome", "success");
                    if (value instanceof YamoraClient.Document document) {
                        api.put("body_file", reserved.body(document.source()));
                        api.put("etag", document.etag());
                        api.put("revision", document.revision());
                    } else if (value instanceof YamoraClient.JsonReply reply) {
                        api.put("status", reply.status());
                        api.put("body_file", reserved.body(reply.json().getBytes(StandardCharsets.UTF_8)));
                        api.put("etag", reply.value().get("etag"));
                        api.put("revision", reply.revision());
                        api.put("receipt", object("status", reply.value().get("status"), "collection", reply.value().get("collection"),
                                "document", reply.value().get("document"), "etag", reply.value().get("etag"), "revision", reply.value().get("revision")));
                    } else if (value instanceof String revision) api.put("revision", revision);
                    else throw invalid();
                }
                emit(output, observation);
                reserved.retain();
            }
        }
        throw invalid(); // A 64-command stream without close is incomplete.
    }

    static int run(String[] argv, InputStream input, OutputStream output, OutputStream diagnostics) {
        try {
            if (argv.length != 4) throw invalid();
            Map<String, String> args = new LinkedHashMap<>();
            for (int i = 0; i < argv.length; i += 2) {
                if (!Set.of("--config", "--root").contains(argv[i]) || args.putIfAbsent(argv[i], argv[i + 1]) != null) throw invalid();
            }
            if (args.size() != 2) throw invalid();
            Path root = Path.of(args.get("--root")), config = Path.of(args.get("--config"));
            if (!config.equals(root.resolve("config.json"))) throw invalid();
            try (OwnedFiles files = new OwnedFiles(root)) {
                session(client(files), files, input, output);
            }
            return 0;
        } catch (Exception error) {
            try { diagnostics.write("Java HTTP replica adapter failed\n".getBytes(StandardCharsets.US_ASCII)); diagnostics.flush(); }
            catch (IOException ignored) { /* Failure is still nonzero if the diagnostic sink is unavailable. */ }
            return 2;
        }
    }

    public static void main(String[] argv) { System.exit(run(argv, System.in, System.out, System.err)); }
}
