import io.yamora.BinaryCancellation;
import io.yamora.BinaryClient;
import io.yamora.BinaryConfig;
import io.yamora.BinaryEnvelope;
import io.yamora.BinaryException;
import io.yamora.BinaryResponse;
import io.yamora.BinaryOperation;
import io.yamora.BinaryOperationException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

/** Thin public SDK adapter. No daemon logic or conformance expectations. */
public final class OperationsAdapter {
    private static final List<String> REQUIRED = List.of("host", "port", "server-name", "ca-file", "cert-file", "key-file",
            "method", "target", "content-type", "feed", "source-file", "request-id", "timeout-ms", "max-frame-bytes", "cancel-mode", "output-dir");
    private static Map<String, String> arguments(String[] argv) {
        if (argv.length % 2 != 0) throw new IllegalArgumentException();
        Map<String, String> values = new LinkedHashMap<>();
        for (int i = 0; i < argv.length; i += 2) {
            if (!argv[i].startsWith("--")) throw new IllegalArgumentException();
            String key = argv[i].substring(2);
            if ((!REQUIRED.contains(key) && !Set.of("token-file", "if-match", "if-none-match").contains(key))
                    || values.putIfAbsent(key, argv[i + 1]) != null) throw new IllegalArgumentException();
        }
        if (!values.keySet().containsAll(REQUIRED) || !"127.0.0.1".equals(values.get("host"))
                || !"localhost".equals(values.get("server-name")) || !"4096".equals(values.get("max-frame-bytes"))
                || !Set.of("GET", "POST", "PATCH").contains(values.get("method"))
                || !Set.of("none", "pre", "external").contains(values.get("cancel-mode"))
                || !values.get("request-id").matches("[0-9a-f]{32}") || values.get("request-id").equals("0".repeat(32))) throw new IllegalArgumentException();
        for (String key : List.of("port", "timeout-ms")) {
            if (!values.get(key).matches("[1-9][0-9]*")) throw new IllegalArgumentException();
            int number = Integer.parseInt(values.get(key));
            if (number > (key.equals("port") ? 65535 : 30000)) throw new IllegalArgumentException();
        }
        if (Integer.parseInt(values.get("port")) == 8000) throw new IllegalArgumentException();
        return values;
    }
    private static byte[] read(String name, int limit) throws Exception {
        Path path = Path.of(name);
        if (!path.isAbsolute() || !Files.isRegularFile(path)) throw new IllegalArgumentException();
        try (var input = Files.newInputStream(path)) {
            byte[] bytes = input.readNBytes(limit + 1);
            if (bytes.length > limit) throw new IllegalArgumentException();
            return bytes;
        }
    }
    // The public SDK accepts an owned PKCS12 identity. Convert the supplied
    // PKCS8 PEM and certificate chain entirely in memory with JDK primitives.
    private static byte[] identity(byte[] cert, byte[] pem) throws Exception {
        String text = new String(pem, StandardCharsets.US_ASCII).strip();
        String begin = "-----BEGIN PRIVATE KEY-----", end = "-----END PRIVATE KEY-----";
        if (!text.startsWith(begin) || !text.endsWith(end)) throw new IllegalArgumentException();
        String base64 = text.substring(begin.length(), text.length() - end.length()).replaceAll("[\\r\\n\\t ]", "");
        byte[] der = Base64.getDecoder().decode(base64);
        try {
            PrivateKey key = null;
            for (String algorithm : List.of("RSA", "EC", "Ed25519", "Ed448", "DSA")) {
                try { key = KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der)); break; }
                catch (java.security.GeneralSecurityException ignored) { /* Try the next supported key algorithm. */ }
            }
            if (key == null) throw new IllegalArgumentException();
            Certificate[] chain = CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(cert)).toArray(Certificate[]::new);
            if (chain.length < 1 || chain.length > 8) throw new IllegalArgumentException();
            KeyStore store = KeyStore.getInstance("PKCS12");
            char[] password = new char[0];
            store.load(null, password);
            store.setKeyEntry("adapter", key, password, chain);
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            store.store(output, password);
            return output.toByteArray();
        } finally { Arrays.fill(der, (byte) 0); }
    }
    private static String kind(BinaryException error) {
        return switch (error.kind()) {
            case STATUS -> "status"; case TIMEOUT -> "deadline"; case CANCELLED -> "cancelled";
            case PROTOCOL -> "protocol"; case TRANSPORT -> "transport";
        };
    }
    private static Map<String, Object> object(Object... pairs) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) result.put((String) pairs[i], pairs[i + 1]);
        return result;
    }
    private static String file(Path root, String name, byte[] bytes) throws Exception {
        Files.write(root.resolve(name), bytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        return name;
    }
    private static final class Control implements AutoCloseable {
        final AtomicBoolean stop = new AtomicBoolean(), failed = new AtomicBoolean();
        final CountDownLatch entered = new CountDownLatch(1);
        final Thread thread;
        Control(String mode, BinaryCancellation cancellation) throws Exception {
            if (mode.equals("pre")) cancellation.cancel();
            if (!mode.equals("external")) { thread = null; return; }
            // A FileChannel read is interruptible, unlike a blocked System.in
            // reader. Interrupting this helper only stops control I/O; the SDK
            // itself is cancelled exclusively through BinaryCancellation.
            FileChannel input = FileChannel.open(Path.of("/proc/self/fd/0"), StandardOpenOption.READ);
            thread = new Thread(() -> {
                int used = 0;
                try (input) {
                    entered.countDown();
                    ByteBuffer bytes = ByteBuffer.allocate(3);
                    while (!stop.get()) {
                        bytes.clear();
                        int count = input.read(bytes);
                        if (count < 0) { if (used != 0) throw new IllegalArgumentException(); return; }
                        for (int i = 0; i < count; i++) {
                            byte value = bytes.get(i);
                            if ((used == 0 && value != 'C') || (used == 1 && value != '\n') || used >= 2) throw new IllegalArgumentException();
                            used++;
                        }
                        if (used == 2) { cancellation.cancel(); return; }
                    }
                    if (used != 0) failed.set(true);
                } catch (ClosedByInterruptException error) {
                    if (!stop.get() || used != 0) failed.set(true);
                } catch (Exception error) { failed.set(true); cancellation.cancel(); }
            }, "conformance-control");
            thread.start();
            if (!entered.await(1, java.util.concurrent.TimeUnit.SECONDS)) { close(); throw new IllegalStateException(); }
        }
        @Override public void close() {
            stop.set(true);
            if (thread != null) {
                thread.interrupt();
                try { thread.join(1000); }
                catch (InterruptedException error) { Thread.currentThread().interrupt(); throw new IllegalStateException(); }
                if (thread.isAlive()) throw new IllegalStateException();
            }
            if (failed.get()) throw new IllegalStateException();
        }
    }
    private static Map<String, Object> observe(String[] argv) throws Exception {
        Map<String, String> a = arguments(argv);
        byte[] source = read(a.get("source-file"), 16 * 1024 * 1024);
        if (a.get("method").equals("GET") && source.length != 0 || !Set.of("true", "false").contains(a.get("feed"))) throw new IllegalArgumentException();
        Path root = Path.of(a.get("output-dir"));
        if (!root.isAbsolute() || !Files.isDirectory(root)) throw new IllegalArgumentException();
        root = root.toRealPath();
        byte[] cert = read(a.get("cert-file"), 1024 * 1024), key = read(a.get("key-file"), 1024 * 1024);
        byte[] pkcs12 = identity(cert, key);
        BinaryConfig config;
        try {
            config = new BinaryConfig(a.get("host"), Integer.parseInt(a.get("port")), a.get("server-name"),
                    read(a.get("ca-file"), 1024 * 1024), pkcs12, new char[0],
                    Duration.ofMillis(Long.parseLong(a.get("timeout-ms"))), 1, Integer.parseInt(a.get("max-frame-bytes")));
        } finally { Arrays.fill(key, (byte) 0); Arrays.fill(pkcs12, (byte) 0); }
        BinaryClient client = new BinaryClient(config);
        BinaryCancellation cancellation = new BinaryCancellation();
        String token = a.containsKey("token-file") ? new String(read(a.get("token-file"), 512), StandardCharsets.US_ASCII) : null;
        Map<String, Object> api = object("status", null, "body_file", null, "etag", null, "revision", null,
                "representation_length", null, "request_id", null, "receipt", null);
        Map<String, Object> observation = object("schema", "yamora-operation-observation/3", "outcome", "success", "error_kind", null,
                "elapsed_ns", 0, "api", api, "envelope", null);
        BinaryResponse value = null;
        BinaryException failure = null;
        final Path output = root;
        final java.io.OutputStream[] feedOutput = {null};
        Control control = new Control(a.get("cancel-mode"), cancellation);
        try {
            long started = System.nanoTime();
            try {
                if (a.get("feed").equals("true")) {
                    value = client.feed(a.get("target"), token, a.get("if-match"), a.get("if-none-match"), a.get("request-id"), cancellation, page -> {
                        try {
                            if (feedOutput[0] == null) feedOutput[0] = Files.newOutputStream(output.resolve("body.bin"), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
                            feedOutput[0].write(page); feedOutput[0].flush();
                        } catch (java.io.IOException error) { throw new java.io.UncheckedIOException(error); }
                    }).response();
                } else value = client.operation(a.get("method"), a.get("target"), a.get("content-type"), source, token,
                        a.get("if-match"), a.get("if-none-match"), a.get("request-id"), cancellation);
            } catch (BinaryException error) { failure = error; }
            finally { observation.put("elapsed_ns", System.nanoTime() - started); }
        } finally { try { control.close(); } finally { if (feedOutput[0] != null) feedOutput[0].close(); } }
        if (failure != null) {
            observation.put("error_kind", kind(failure));
            observation.put("outcome", kind(failure));
            if (failure.status() != 0) api.put("status", failure.status());
            if (failure instanceof BinaryOperationException operation) value = operation.response();
            if (failure instanceof BinaryOperationException uncertain && uncertain.uncertain()) {
                BinaryOperation original = uncertain.envelope();
                observation.put("outcome", "uncertain");
                observation.put("envelope", object("method", original.method(), "target", original.target(), "content_type", original.contentType(),
                        "if_match", original.ifMatch(), "if_none_match", original.ifNoneMatch(), "request_id", original.requestId(),
                        "source_file", file(root, "envelope.bin", original.source())));
            }
        }
        if (value != null) {
            var metadata = value.metadata();
            api.put("status", value.status());
            api.put("body_file", feedOutput[0] == null ? file(root, "body.bin", value.body()) : "body.bin");
            api.put("etag", metadata.etag());
            api.put("revision", metadata.revision());
            api.put("representation_length", metadata.representationLength());
            api.put("request_id", metadata.requestId());
        }
        return observation;
    }
    private static String json(Object value) {
        if (value == null) return "null";
        if (value instanceof Number) return value.toString();
        if (value instanceof Map<?, ?> map) {
            StringBuilder out = new StringBuilder("{");
            for (var entry : map.entrySet()) {
                if (out.length() > 1) out.append(',');
                out.append(json(entry.getKey())).append(':').append(json(entry.getValue()));
            }
            return out.append('}').toString();
        }
        if (!(value instanceof String text)) throw new IllegalArgumentException();
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '\\' || c == '"') out.append('\\').append(c);
            else if (c < 32) out.append(String.format("\\u%04x", (int) c));
            else out.append(c);
        }
        return out.append('"').toString();
    }
    public static void main(String[] argv) {
        try {
            String output = json(observe(argv)) + "\n";
            if (output.getBytes(StandardCharsets.UTF_8).length > 16384) throw new IllegalArgumentException();
            System.out.print(output);
        } catch (Exception error) { System.err.println("Java conformance adapter failed"); System.exit(2); }
    }
}
