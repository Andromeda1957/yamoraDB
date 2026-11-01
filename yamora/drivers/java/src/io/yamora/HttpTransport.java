package io.yamora;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

/** The daemon's finite, identity-encoded HTTP/1.1 profile. Exactly one connection/attempt.
 * JDK HttpClient has no public per-client switch disabling all idempotent retries.
 * SocketChannel plus JSSE avoids global system-property changes and hidden replay. */
final class HttpTransport implements RequestBoundary {
    private static final ScheduledThreadPoolExecutor DEADLINES = deadlines();
    private static ScheduledThreadPoolExecutor deadlines() {
        ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(1, runnable -> {
            Thread thread = new Thread(runnable, "yamora-deadlines");
            thread.setDaemon(true);
            return thread;
        });
        executor.setRemoveOnCancelPolicy(true);
        return executor;
    }

    record Response(int status, Map<String, String> headers, byte[] body) {}
    private final String host;
    private final InetSocketAddress address;
    private final Tls tls;
    private final Duration timeout;

    HttpTransport(String host, int port, Tls tls, Duration timeout) {
        if (host == null) throw endpointError();
        this.host = host;
        byte[] bytes = new byte[4];
        String[] parts = host.split("\\.", -1);
        if (parts.length != 4 || port < 1 || port > 65535) throw endpointError();
        for (int i = 0; i < 4; i++) {
            if (!parts[i].matches("0|[1-9][0-9]{0,2}")) throw endpointError();
            int value = Integer.parseInt(parts[i]);
            if (value > 255) throw endpointError();
            bytes[i] = (byte) value;
        }
        int first = Byte.toUnsignedInt(bytes[0]), second = Byte.toUnsignedInt(bytes[1]);
        if (!(first == 127 || first == 10 || (first == 172 && second >= 16 && second <= 31)
                || (first == 192 && second == 168))) throw endpointError();
        try { address = new InetSocketAddress(InetAddress.getByAddress(bytes), port); }
        catch (IOException impossible) { throw new IllegalArgumentException(impossible); }
        if (timeout == null || timeout.compareTo(Duration.ofMillis(1)) < 0
                || timeout.compareTo(Duration.ofSeconds(30)) > 0) {
            throw new IllegalArgumentException("yamora: timeout must be 1ms..30s");
        }
        this.tls = tls;
        this.timeout = timeout;
    }

    private static IllegalArgumentException endpointError() {
        return new IllegalArgumentException("yamora: numeric IPv4 loopback or RFC1918 endpoint required");
    }

    @Override public Response exchange(String method, String path, byte[] body, String media, String token,
                      Map<String, String> conditions, int maximum, boolean mutation, int... statuses) throws YamoraException {
        return exchange(timeout, method, path, body, media, token, conditions, maximum, mutation, statuses);
    }

    Response exchange(Duration budget, String method, String path, byte[] body, String media, String token,
                      Map<String, String> conditions, int maximum, boolean mutation, int... statuses) throws YamoraException {
        boolean sent = false;
        int status = 0;
        // Channel-backed blocking I/O is interruptible, including when wrapped by JSSE.
        try (SocketChannel channel = SocketChannel.open()) {
            Socket socket = channel.socket();
            ScheduledFuture<?> deadline = DEADLINES.schedule(() -> closeAtDeadline(channel),
                    budget.toNanos(), TimeUnit.NANOSECONDS);
            try {
                int milliseconds = (int) Math.max(1, budget.toMillis());
                socket.connect(address, milliseconds);
                socket.setSoTimeout(milliseconds);
                if (tls != null) {
                    SSLSocket secure = (SSLSocket) tls.context().getSocketFactory()
                            .createSocket(socket, host, address.getPort(), true);
                    socket = secure;
                    SSLParameters parameters = new SSLParameters(new String[0], new String[]{"TLSv1.3"});
                    // Keep provider's safe cipher list; only the protocol and peer policy are narrowed.
                    parameters.setCipherSuites(secure.getEnabledCipherSuites());
                    parameters.setEndpointIdentificationAlgorithm("HTTPS");
                    parameters.setApplicationProtocols(new String[]{"http/1.1"});
                    secure.setSSLParameters(parameters);
                    secure.setSoTimeout(milliseconds);
                    secure.startHandshake();
                    if (!secure.getSession().getProtocol().equals("TLSv1.3")) throw new IOException("TLS version");
                }
                try (Socket connection = socket) {
                    StringBuilder request = new StringBuilder(method).append(' ').append(path)
                            .append(" HTTP/1.1\r\nHost: ").append(host).append(':').append(address.getPort())
                            .append("\r\nConnection: close\r\nAccept: application/json, application/yaml\r\n")
                            .append("Accept-Encoding: identity\r\n");
                    if (!token.isEmpty()) request.append("Authorization: Bearer ").append(token).append("\r\n");
                    if (media != null) request.append("Content-Type: ").append(media).append("\r\n");
                    for (Map.Entry<String, String> entry : conditions.entrySet()) {
                        request.append(entry.getKey()).append(": ").append(entry.getValue()).append("\r\n");
                    }
                    request.append("Content-Length: ").append(body.length).append("\r\n\r\n");
                    OutputStream output = connection.getOutputStream();
                    sent = true;
                    output.write(request.toString().getBytes(StandardCharsets.US_ASCII));
                    output.write(body);
                    output.flush();
                    InputStream input = new BufferedInputStream(connection.getInputStream(), 8192);
                    HeaderReader reader = new HeaderReader(input);
                    String statusLine = reader.line();
                    if (!statusLine.matches("HTTP/1\\.1 [1-5][0-9]{2}( [\\x20-\\x7e]*)?")) throw protocol(mutation, 0);
                    status = Integer.parseInt(statusLine.substring(9, 12));
                    Map<String, String> headers = reader.headers();
                    // Error bodies are deliberately not consumed or reflected to the application.
                    if (status < 200 || status >= 300) {
                        throw new YamoraException(YamoraException.Kind.HTTP, status,
                                mutation && (status < 400 || status == 408 || status >= 500), "HTTP " + status, null);
                    }
                    if (headers.containsKey("transfer-encoding") || headers.containsKey("content-encoding")) {
                        throw protocol(mutation, status);
                    }
                    String length = headers.get("content-length");
                    if (length == null || !length.matches("0|[1-9][0-9]{0,9}")) throw protocol(mutation, status);
                    long size = Long.parseLong(length);
                    if (size > maximum || (status == 204 && size != 0)) throw protocol(mutation, status);
                    byte[] payload = input.readNBytes((int) size);
                    if (payload.length != size) throw protocol(mutation, status);
                    // The protocol closes each connection. Reject bytes beyond declared length.
                    if (input.read() != -1) throw protocol(mutation, status);
                    boolean accepted = false;
                    for (int allowed : statuses) accepted |= status == allowed;
                    if (!accepted) throw protocol(mutation, status);
                    return new Response(status, Map.copyOf(headers), payload);
                }
            } finally { deadline.cancel(false); }
        } catch (YamoraException failure) {
            if (mutation && sent && failure.kind() == YamoraException.Kind.PROTOCOL) {
                throw protocol(true, failure.status() == 0 ? status : failure.status());
            }
            throw failure;
        }
        catch (IOException failure) {
            throw new YamoraException(YamoraException.Kind.TRANSPORT, status, mutation && sent,
                    "transport failed (no retry)", failure);
        }
    }

    private static void closeAtDeadline(SocketChannel channel) {
        try { channel.close(); } catch (IOException ignored) { /* already closed */ }
    }

    static YamoraException protocol(boolean mutation, int status) {
        return new YamoraException(YamoraException.Kind.PROTOCOL, status, mutation,
                "invalid or over-budget response", null);
    }

    private static final class HeaderReader {
        final InputStream input;
        int bytes;
        HeaderReader(InputStream input) { this.input = input; }
        String line() throws IOException {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            while (true) {
                int next = input.read();
                if (++bytes > 16 * 1024 || next < 0) throw protocol(false, 0);
                if (next == '\r') {
                    if (++bytes > 16 * 1024 || input.read() != '\n') throw protocol(false, 0);
                    return output.toString(StandardCharsets.US_ASCII);
                }
                if (next < 32 && next != '\t' || next > 126) throw protocol(false, 0);
                output.write(next);
            }
        }
        Map<String, String> headers() throws IOException {
            Map<String, String> result = new HashMap<>();
            String line;
            int count = 0;
            while (!(line = line()).isEmpty()) {
                if (++count > 64) throw protocol(false, 0);
                int colon = line.indexOf(':');
                if (colon < 1) throw protocol(false, 0);
                String name = line.substring(0, colon).toLowerCase(Locale.ROOT);
                String value = line.substring(colon + 1).trim();
                if (!name.matches("[!#$%&'*+.^_`|~0-9a-z-]+")) throw protocol(false, 0);
                if (result.containsKey(name)) {
                    // Native cluster metadata emits this harmless directive twice.
                    // Never relax uniqueness for framing, credentials or revision fields.
                    if (!name.equals("cache-control") || !value.equals("no-store")
                            || !value.equals(result.get(name))) throw protocol(false, 0);
                }
                result.put(name, value);
            }
            return result;
        }
    }
}
