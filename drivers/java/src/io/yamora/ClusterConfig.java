package io.yamora;

import java.time.Duration;
import java.util.HashSet;
import java.util.List;

/** Immutable, application-owned HTTPS trust set. No server response can extend it. */
public record ClusterConfig(List<Seed> seeds, Tls tls, Duration timeout, Duration attemptTimeout,
                            int requestLimit, int responseLimit) {
    public record Seed(String host, int port) {
        public Seed {
            // Reuse the standalone numeric private IPv4 validation; never resolve DNS.
            new HttpTransport(host, port, null, Duration.ofSeconds(1));
        }
    }

    public ClusterConfig(List<Seed> seeds, Tls tls) {
        this(seeds, tls, Duration.ofSeconds(30), Duration.ofSeconds(5),
                YamoraClient.MAX_REQUEST_BYTES, YamoraClient.MAX_RESPONSE_BYTES);
    }

    public ClusterConfig {
        if (seeds == null || seeds.isEmpty() || seeds.size() > 9 || tls == null) {
            throw new IllegalArgumentException("yamora: 1..9 verified HTTPS seeds required");
        }
        seeds = List.copyOf(seeds);
        if (new HashSet<>(seeds).size() != seeds.size()) {
            throw new IllegalArgumentException("yamora: duplicate seed");
        }
        duration(timeout);
        duration(attemptTimeout);
        if (requestLimit < 1 || requestLimit > YamoraClient.MAX_REQUEST_BYTES
                || responseLimit < 1 || responseLimit > YamoraClient.MAX_RESPONSE_BYTES) {
            throw new IllegalArgumentException("yamora: invalid byte limits");
        }
    }

    private static void duration(Duration value) {
        if (value == null || value.compareTo(Duration.ofMillis(1)) < 0
                || value.compareTo(Duration.ofSeconds(30)) > 0) {
            throw new IllegalArgumentException("yamora: timeout must be 1ms..30s");
        }
    }
}
