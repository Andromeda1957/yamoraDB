package io.yamora;

import java.math.BigInteger;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Seed-only routing. No proxies, redirects, hostname resolution or advertised addresses. */
final class ClusterTransport implements RequestBoundary {
    private record Route(int leader, int cursor) {}
    private final AtomicReference<Route> route = new AtomicReference<>(new Route(-1, 0));
    private final List<HttpTransport> endpoints;
    private final ClusterConfig config;
    private final String readToken;

    ClusterTransport(ClusterConfig config, String readToken) {
        this.config = config;
        this.readToken = readToken;
        endpoints = config.seeds().stream().map(seed -> new HttpTransport(seed.host(), seed.port(),
                config.tls(), config.attemptTimeout())).toList();
    }

    private Duration budget(long deadline, int shares) {
        return Duration.ofNanos(Math.max(1, Math.min(config.attemptTimeout().toNanos(),
                Math.max(0, deadline - System.nanoTime()) / shares)));
    }

    private static boolean active(long deadline) {
        return !Thread.currentThread().isInterrupted() && deadline - System.nanoTime() > 0;
    }

    private Route discover(long deadline) throws YamoraException {
        Route observed = route.get();
        if (observed.leader() >= 0) return observed;
        for (int offset = 0; offset < endpoints.size() && active(deadline); offset++) {
            int index = (observed.cursor() + offset) % endpoints.size();
            try {
                // Reserve another share for dispatch even when the last seed stalls.
                HttpTransport.Response response = endpoints.get(index).exchange(
                        budget(deadline, endpoints.size() - offset + 1), "GET", "/v1/cluster/leader",
                        new byte[0], null, readToken, Map.of(), Math.min(512, config.responseLimit()), false, 200);
                if (leader(response)) {
                    Route found = new Route(index, observed.cursor());
                    // A stale discovery cannot overwrite a newer call's discovery/invalidation.
                    route.compareAndSet(observed, found);
                    return route.get();
                }
            } catch (YamoraException failure) {
                if (failure.status() == 401 || failure.status() == 403) throw failure;
            }
        }
        return route.get();
    }

    private static boolean leader(HttpTransport.Response response) {
        String media = response.headers().get("content-type");
        if (media == null || !media.split(";", 2)[0].trim().equalsIgnoreCase("application/json")) return false;
        try {
            // Parse through the SDK's strict UTF-8/JSON boundary, including duplicate-key checks.
            Map<String, Object> value = YamoraClient.clusterLeaderValue(response);
            if (!value.keySet().equals(Set.of("node", "leader", "term", "role"))) return false;
            BigInteger node = integer(value.get("node")), id = integer(value.get("leader")), term = integer(value.get("term"));
            return node.signum() > 0 && node.compareTo(BigInteger.valueOf(9)) <= 0 && id.equals(node)
                    && term.signum() > 0 && term.bitLength() <= 64 && "leader".equals(value.get("role"));
        } catch (IllegalArgumentException | ArithmeticException | YamoraException failure) { return false; }
    }

    private static BigInteger integer(Object value) {
        if (!(value instanceof Json.NumberValue number) || !number.text().matches("0|[1-9][0-9]*")) {
            throw new IllegalArgumentException("yamora: invalid leader metadata");
        }
        return number.bigIntegerExact();
    }

    private static boolean supportedWrite(String method, String path) {
        return path.equals("/v1/transactions") && method.equals("POST")
                || path.equals("/v1/indexes") && method.equals("PUT")
                || path.matches("/v1/collections/[a-z0-9-]{1,128}/documents/[a-z0-9-]{1,128}")
                && Set.of("PUT", "PATCH", "DELETE").contains(method);
    }

    @Override public HttpTransport.Response exchange(String method, String path, byte[] source, String media,
            String token, Map<String, String> headers, int maximum, boolean mutation, int... statuses) throws YamoraException {
        long deadline = System.nanoTime() + config.timeout().toNanos();
        if (mutation && !supportedWrite(method, path)) {
            throw new YamoraException(YamoraException.Kind.HTTP, 405, false, "unsupported cluster operation", null);
        }
        byte[] body = source.clone();
        Map<String, String> conditions = new HashMap<>(headers);
        String id = null;
        if (mutation) {
            id = conditions.getOrDefault("X-Yamora-Request-Id", UUID.randomUUID().toString().replace("-", ""));
            conditions.put("X-Yamora-Request-Id", id);
        }
        conditions = Map.copyOf(conditions);
        boolean uncertain = false;
        long delay = TimeUnit.MILLISECONDS.toNanos(50);
        YamoraException last = unavailable();
        for (int attempts = 0; attempts < 32 && active(deadline); attempts++) {
            Route selected;
            try { selected = discover(deadline); }
            catch (YamoraException failure) { throw mutation && uncertain ? failure.uncertain(id) : failure; }
            if (!active(deadline)) break;
            if (selected.leader() >= 0) {
                try {
                    HttpTransport.Response response = endpoints.get(selected.leader()).exchange(
                            budget(deadline, endpoints.size() > 1 ? 2 : 1), method, path, body, media,
                            token, conditions, maximum, mutation, statuses);
                    if (mutation) YamoraClient.validateClusterReceipt(method, path, body, response);
                    if (!active(deadline)) throw unavailable();
                    return response;
                } catch (YamoraException failure) {
                    last = failure;
                    boolean retry = failure.kind() == YamoraException.Kind.TRANSPORT || failure.status() == 503
                            || failure.kind() == YamoraException.Kind.PROTOCOL && failure.status() == 0;
                    if (!retry) {
                        boolean definitive = failure.kind() == YamoraException.Kind.HTTP && failure.status() >= 400
                                && failure.status() < 500 && failure.status() != 408;
                        throw mutation && (uncertain || !definitive) ? failure.uncertain(id) : failure;
                    }
                    uncertain |= mutation && (failure.outcomeUncertain() || failure.status() == 503);
                    route.compareAndSet(selected, new Route(-1, (selected.leader() + 1) % endpoints.size()));
                }
            }
            try { TimeUnit.NANOSECONDS.sleep(Math.min(delay, Math.max(0, deadline - System.nanoTime()))); }
            catch (InterruptedException failure) { Thread.currentThread().interrupt(); break; }
            delay = Math.min(TimeUnit.SECONDS.toNanos(1), delay * 2);
        }
        if (Thread.currentThread().isInterrupted()) {
            last = new YamoraException(YamoraException.Kind.TRANSPORT, 0, false, "request interrupted", null);
        }
        throw mutation ? last.uncertain(id) : last;
    }

    private static YamoraException unavailable() {
        return new YamoraException(YamoraException.Kind.HTTP, 503, false, "replica set unavailable within deadline", null);
    }
}
