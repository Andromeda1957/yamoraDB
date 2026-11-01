package io.yamora;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Dependency-free HTTP driver. Safe for concurrent independent calls.
 * Raw JSON APIs deliberately leave query/operator semantics to the daemon. */
public final class YamoraClient {
    public static final int MAX_DOCUMENT_BYTES = 16 * 1024 * 1024;
    public static final int MAX_REQUEST_BYTES = 64 * 1024 * 1024;
    public static final int MAX_RESPONSE_BYTES = 64 * 1024 * 1024;
    private static final int SMALL_REQUEST_BYTES = 2 * 1024 * 1024;
    private final RequestBoundary transport;
    private final String readToken;
    private final String writeToken;
    private final int requestLimit;
    private final int responseLimit;

    /** A null TLS configuration selects plain HTTP for a protected network. Tokens may be empty. */
    public YamoraClient(String host, int port, String readToken, String writeToken, Tls tls) {
        this(host, port, readToken, writeToken, tls, Duration.ofSeconds(5), MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES);
    }

    /** Application budgets can narrow, never raise, the protocol's 64 MiB ceilings. */
    public YamoraClient(String host, int port, String readToken, String writeToken, Tls tls,
                        Duration timeout, int requestLimit, int responseLimit) {
        this(new HttpTransport(host, port, tls, timeout), readToken, writeToken, requestLimit, responseLimit);
    }

    /** Verified HTTPS discovery and exact-request retry policy; standalone constructors never retry. */
    public static YamoraClient replicaSet(ClusterConfig config, String readToken, String writeToken) {
        Objects.requireNonNull(config);
        return new YamoraClient(new ClusterTransport(config, readToken), readToken, writeToken,
                config.requestLimit(), config.responseLimit());
    }

    private YamoraClient(RequestBoundary transport, String readToken, String writeToken,
                         int requestLimit, int responseLimit) {
        validateToken(readToken);
        validateToken(writeToken);
        if (requestLimit < 1 || requestLimit > MAX_REQUEST_BYTES || responseLimit < 1
                || responseLimit > MAX_RESPONSE_BYTES) throw invalid("byte limits");
        this.transport = transport;
        this.readToken = readToken;
        this.writeToken = writeToken;
        this.requestLimit = requestLimit;
        this.responseLimit = responseLimit;
    }

    public record WriteOptions(String etag, boolean createOnly, String requestId) {
        public static final WriteOptions NONE = new WriteOptions(null, false, null);
        public WriteOptions {
            optionalHex(etag, 16);
            optionalHex(requestId, 32);
            if (createOnly && etag != null || requestId != null && requestId.equals("0".repeat(32))) {
                throw invalid("write preconditions");
            }
        }
        Map<String, String> headers() {
            Map<String, String> result = new HashMap<>();
            if (etag != null) result.put("If-Match", '"' + etag + '"');
            if (createOnly) result.put("If-None-Match", "*");
            if (requestId != null) result.put("X-Yamora-Request-Id", requestId);
            return result;
        }
    }

    public record Document(byte[] source, String etag, String revision) {
        public Document { source = source.clone(); }
        @Override public byte[] source() { return source.clone(); }
        @Override public String toString() { return "Document[etag=" + etag + ", revision=" + revision + "]"; }
    }

    /** Immutable parsed JSON object with exact NumberValue tokens and original response text. */
    public record JsonReply(int status, String revision, String json, Map<String, Object> value) {
        @Override public String toString() { return "JsonReply[status=" + status + ", revision=" + revision + "]"; }
    }

    public JsonReply health() throws YamoraException { return read("/healthz"); }
    public JsonReply ready() throws YamoraException { return read("/readyz"); }
    /** Advisory preflight before application-owned replica staging; native admission remains authoritative. */
    public JsonReply requireReplicationSource() throws YamoraException {
        JsonReply reply = ready();
        if (reply.value().containsKey("replication_policy_free")) {
            Object allowed = reply.value().get("replication_policy_free");
            if (!(allowed instanceof Boolean))
                throw new YamoraException(YamoraException.Kind.PROTOCOL, 0, false,
                        "invalid replication source capability", null);
            if (Boolean.FALSE.equals(allowed))
                throw new YamoraException(YamoraException.Kind.SCHEMA_POLICY_REPLICATION_UNSUPPORTED, 409, false,
                        "schema_policy_replication_unsupported", null);
        }
        return reply;
    }
    public JsonReply stats() throws YamoraException { return read("/v1/stats"); }
    public JsonReply clusterLeader() throws YamoraException { return read("/v1/cluster/leader"); }
    public JsonReply clusterStatus() throws YamoraException { return read("/v1/cluster/status"); }
    public JsonReply replicationStatus() throws YamoraException { return read("/v1/replication/status"); }

    public String metrics() throws YamoraException {
        HttpTransport.Response response = exchange("GET", "/metrics", new byte[0], null, Map.of(), false,
                MAX_DOCUMENT_BYTES, 200);
        revision(response, null, false);
        media(response, "text/plain", false);
        return responseText(response, false);
    }

    public JsonReply collections(String expectedRevision) throws YamoraException {
        optionalHex(expectedRevision, 16);
        JsonReply reply = read("/v1/collections");
        expected(reply, expectedRevision);
        names(reply, "collections");
        return reply;
    }

    /** One bounded ID page. Pin its revision on every later page and document read. */
    public JsonReply documentPage(String collection, int limit, String after, String expectedRevision)
            throws YamoraException {
        identifier(collection);
        optionalHex(expectedRevision, 16);
        if (limit < 1 || limit > 1000 || after != null && expectedRevision == null) throw invalid("page cursor");
        if (after != null) identifier(after);
        JsonReply reply = read("/v1/collections/" + collection + "/documents?limit=" + limit
                + (after == null ? "" : "&after=" + after));
        expected(reply, expectedRevision);
        List<?> ids = names(reply, "documents");
        Object next = reply.value().get("next_after");
        if (!reply.value().containsKey("next_after") || ids.size() > limit || next != null
                && (!(next instanceof String cursor) || !isIdentifier(cursor) || ids.isEmpty()
                || !next.equals(ids.get(ids.size() - 1)))) throw malformed(reply, false);
        if (!ids.isEmpty() && after != null && ((String) ids.get(0)).compareTo(after) <= 0) throw malformed(reply, false);
        return reply;
    }

    public Document get(String collection, String document, String expectedRevision) throws YamoraException {
        optionalHex(expectedRevision, 16);
        HttpTransport.Response response = exchange("GET", documentPath(collection, document), new byte[0], null,
                Map.of(), false, MAX_DOCUMENT_BYTES, 200);
        String revision = revision(response, expectedRevision, false);
        media(response, "application/yaml", false);
        String tag = response.headers().get("etag");
        if (tag == null || !tag.matches("\"[0-9a-f]{16}\"")) throw HttpTransport.protocol(false, response.status());
        responseText(response, false); // Fail closed on malformed UTF-8, without re-encoding the source.
        return new Document(response.body(), tag.substring(1, 17), revision);
    }

    public JsonReply put(String collection, String document, byte[] source, WriteOptions options)
            throws YamoraException {
        String path = writePath(collection, document);
        Objects.requireNonNull(options);
        validateSource(source);
        JsonReply reply = json(exchange("PUT", path, source.clone(), "application/yaml", options.headers(), true,
                MAX_DOCUMENT_BYTES, 200, 201), true, null, false);
        mutation(reply, collection, document);
        return reply;
    }

    public JsonReply patch(String collection, String document, String operatorsJson, WriteOptions options)
            throws YamoraException {
        String path = writePath(collection, document);
        requireReplacement(options);
        Map<String, Object> operators = Json.object(operatorsJson);
        if (operators.isEmpty()) throw invalid("empty patch");
        JsonReply reply = structured("PATCH", path, operators, options.headers(), true, MAX_REQUEST_BYTES,
                MAX_DOCUMENT_BYTES, null, false, 200);
        mutation(reply, collection, document);
        return reply;
    }

    /** Returns the deletion snapshot revision. */
    public String delete(String collection, String document, WriteOptions options) throws YamoraException {
        requireReplacement(options);
        HttpTransport.Response response = exchange("DELETE", writePath(collection, document), new byte[0], null,
                options.headers(), true, 0, 204);
        return revision(response, null, true);
    }

    public JsonReply query(String collection, String specificationJson) throws YamoraException {
        return collectionCall("query", collection, specificationJson);
    }
    public JsonReply aggregate(String collection, String specificationJson) throws YamoraException {
        return collectionCall("aggregate", collection, specificationJson);
    }
    public JsonReply search(String collection, String specificationJson) throws YamoraException {
        return collectionCall("search", collection, specificationJson);
    }

    public JsonReply indexes() throws YamoraException { return read("/v1/indexes"); }

    /** Replaces the entire catalog; If-Match is a database revision, not a document ETag. */
    public JsonReply setIndexes(String catalogJson, String expectedRevision, String requestId) throws YamoraException {
        Map<String, Object> catalog = Json.object(catalogJson);
        if (!(catalog.get("indexes") instanceof List<?> indexes) || indexes.size() > 64) throw invalid("index catalog");
        return structured("PUT", "/v1/indexes", catalog, revisionHeaders(expectedRevision, requestId), true,
                SMALL_REQUEST_BYTES, MAX_DOCUMENT_BYTES, null, false, 200);
    }

    public JsonReply startIndexBuild(String catalogJson, String expectedRevision) throws YamoraException {
        Map<String, Object> catalog = Json.object(catalogJson);
        if (!(catalog.get("indexes") instanceof List<?> indexes) || indexes.size() > 64) throw invalid("index catalog");
        return structured("POST", "/v1/index-builds", catalog, revisionHeaders(expectedRevision, null), true,
                SMALL_REQUEST_BYTES, MAX_DOCUMENT_BYTES, null, true, 202);
    }
    public JsonReply indexBuild(String jobId) throws YamoraException {
        if (jobId != null) hex(jobId, 32);
        return json(exchange("GET", "/v1/index-builds" + (jobId == null ? "" : "/" + jobId), new byte[0], null,
                Map.of(), false, MAX_DOCUMENT_BYTES, 200), false, null, true);
    }
    public JsonReply cancelIndexBuild(String jobId) throws YamoraException {
        hex(jobId, 32);
        return json(exchange("DELETE", "/v1/index-builds/" + jobId, new byte[0], null, Map.of(), true,
                MAX_DOCUMENT_BYTES, 202), true, null, true);
    }

    /** Complete transaction envelope: operations plus optional revision. */
    public JsonReply transaction(String envelopeJson, String requestId) throws YamoraException {
        Map<String, Object> envelope = Json.object(envelopeJson);
        validateOperations(envelope.get("operations"));
        optionalRevision(envelope);
        JsonReply reply = structured("POST", "/v1/transactions", envelope, revisionHeaders(null, requestId), true,
                MAX_REQUEST_BYTES, MAX_DOCUMENT_BYTES, null, false, 200);
        if (!"committed".equals(reply.value().get("status"))
                || !(reply.value().get("operations") instanceof Json.NumberValue number)
                || !number.text().equals(Integer.toString(((List<?>) envelope.get("operations")).size()))) {
            throw malformed(reply, true);
        }
        // Successful mutation advances the requested snapshot, so do not compare response to old revision.
        return reply;
    }

    /** A checkpoint when after is null; otherwise one finite page. No polling or progress management. */
    public JsonReply changes(String after, int limit) throws YamoraException {
        if (limit < 1 || limit > 100) throw invalid("change limit");
        if (after != null && !after.matches("v1\\.[0-9a-f]{32}\\.[0-9a-f]{16}")) throw invalid("change token");
        return read("/v1/changes" + (after == null ? "" : "?after=" + after + "&limit=" + limit));
    }

    /** Low-level finite replication primitives only. The application owns staging and recovery. */
    public enum ReplicationOperation {
        BEGIN("begin"), APPLY("apply"), COMMIT("commit"), ABORT("abort"),
        FOLLOW_BEGIN("follow/begin"), FOLLOW_APPLY("follow/apply"),
        FOLLOW_COMMIT("follow/commit"), FOLLOW_ABORT("follow/abort");
        private final String path;
        ReplicationOperation(String path) { this.path = path; }
    }
    public JsonReply replication(ReplicationOperation operation, String envelopeJson) throws YamoraException {
        Objects.requireNonNull(operation);
        return structured("POST", "/v1/replication/" + operation.path, Json.object(envelopeJson), Map.of(), true,
                operation == ReplicationOperation.APPLY || operation == ReplicationOperation.FOLLOW_APPLY
                        ? MAX_REQUEST_BYTES : SMALL_REQUEST_BYTES,
                MAX_DOCUMENT_BYTES, null, false, 200);
    }

    private JsonReply collectionCall(String operation, String collection, String specificationJson) throws YamoraException {
        identifier(collection);
        Map<String, Object> specification = Json.object(specificationJson);
        String expectedRevision = optionalRevision(specification);
        if (specification.containsKey("after")) {
            if (!(specification.get("after") instanceof String after) || !isIdentifier(after) || expectedRevision == null) {
                throw invalid("query cursor");
            }
        }
        return structured("POST", "/v1/" + operation + "/" + collection, specification, Map.of(), false,
                SMALL_REQUEST_BYTES, MAX_RESPONSE_BYTES, expectedRevision, false, 200);
    }

    private JsonReply read(String path) throws YamoraException {
        return json(exchange("GET", path, new byte[0], null, Map.of(), false, MAX_RESPONSE_BYTES, 200),
                false, null, false);
    }
    private JsonReply structured(String method, String path, Map<String, Object> value, Map<String, String> headers,
                                  boolean mutation, int requestMaximum, int responseMaximum,
                                  String expectedRevision, boolean jobRevision, int... statuses) throws YamoraException {
        byte[] body = utf8(Json.stringify(value));
        if (body.length > requestMaximum) throw invalid("request size");
        return json(exchange(method, path, body, "application/json", headers, mutation, responseMaximum, statuses),
                mutation, expectedRevision, jobRevision);
    }

    private HttpTransport.Response exchange(String method, String path, byte[] body, String media,
                                             Map<String, String> headers, boolean mutation, int maximum, int... statuses)
            throws YamoraException {
        if (body.length > requestLimit) throw invalid("request size");
        return transport.exchange(method, path, body, media,
                mutation ? writeToken : readToken, headers, Math.min(maximum, responseLimit), mutation, statuses);
    }
    private static JsonReply json(HttpTransport.Response response, boolean mutation, String expectedRevision, boolean jobRevision)
            throws YamoraException {
        String revision = revision(response, expectedRevision, mutation);
        media(response, "application/json", mutation);
        String text = responseText(response, mutation);
        Map<String, Object> value;
        try { value = Json.object(text); }
        catch (IllegalArgumentException failure) { throw HttpTransport.protocol(mutation, response.status()); }
        if (!jobRevision && value.containsKey("revision") && !revision.equals(value.get("revision"))) {
            throw HttpTransport.protocol(mutation, response.status());
        }
        return new JsonReply(response.status(), revision, text, value);
    }

    // All fallible mutation receipt checks run while the generated ID is still recoverable.
    static Map<String, Object> clusterLeaderValue(HttpTransport.Response response) throws YamoraException {
        return Json.object(responseText(response, false));
    }

    static void validateClusterReceipt(String method, String path, byte[] body, HttpTransport.Response response)
            throws YamoraException {
        if (method.equals("DELETE")) {
            revision(response, null, true);
            if (response.body().length != 0) throw HttpTransport.protocol(true, response.status());
            return;
        }
        JsonReply reply = json(response, true, null, false);
        if (path.startsWith("/v1/collections/")) {
            String[] parts = path.split("/");
            mutation(reply, parts[3], parts[5]);
        } else {
            int count = path.equals("/v1/indexes") ? 1
                    : ((List<?>) Json.object(decodeUtf8(body)).get("operations")).size();
            if (!"committed".equals(reply.value().get("status"))
                    || !(reply.value().get("operations") instanceof Json.NumberValue number)
                    || !number.text().equals(Integer.toString(count))
                    || !reply.revision().equals(reply.value().get("revision"))) throw malformed(reply, true);
        }
    }

    private static String revision(HttpTransport.Response response, String expected, boolean mutation) throws YamoraException {
        String actual = response.headers().get("x-yamldb-revision");
        if (!isHex(actual, 16) || expected != null && !actual.equals(expected)) {
            throw HttpTransport.protocol(mutation, response.status());
        }
        return actual;
    }
    private static void media(HttpTransport.Response response, String expected, boolean mutation) throws YamoraException {
        String actual = response.headers().get("content-type");
        if (actual == null || !actual.split(";", 2)[0].trim().equalsIgnoreCase(expected)) {
            throw HttpTransport.protocol(mutation, response.status());
        }
    }
    private static String responseText(HttpTransport.Response response, boolean mutation) throws YamoraException {
        try { return decodeUtf8(response.body()); }
        catch (IllegalArgumentException failure) { throw HttpTransport.protocol(mutation, response.status()); }
    }
    private static void mutation(JsonReply reply, String collection, String document) throws YamoraException {
        if (!"stored".equals(reply.value().get("status")) || !collection.equals(reply.value().get("collection"))
                || !document.equals(reply.value().get("document")) || !(reply.value().get("etag") instanceof String tag)
                || !isHex(tag, 16) || !reply.revision().equals(reply.value().get("revision"))) throw malformed(reply, true);
    }
    private static YamoraException malformed(JsonReply reply, boolean mutation) {
        return HttpTransport.protocol(mutation, reply.status());
    }
    private static void expected(JsonReply reply, String expectedRevision) throws YamoraException {
        if (expectedRevision != null && !expectedRevision.equals(reply.revision())) throw malformed(reply, false);
    }
    private static List<?> names(JsonReply reply, String key) throws YamoraException {
        if (!(reply.value().get(key) instanceof List<?> names) || names.size() > 65_536) throw malformed(reply, false);
        String previous = "";
        for (Object name : names) {
            if (!(name instanceof String id) || !isIdentifier(id) || id.compareTo(previous) <= 0) throw malformed(reply, false);
            previous = id;
        }
        return names;
    }
    private static Map<String, String> revisionHeaders(String revision, String requestId) {
        return new WriteOptions(revision, false, requestId).headers();
    }
    private static void requireReplacement(WriteOptions options) {
        if (options == null || options.createOnly()) throw invalid("replacement preconditions");
    }
    private static String optionalRevision(Map<String, Object> value) {
        if (!value.containsKey("revision")) return null;
        if (!(value.get("revision") instanceof String revision)) throw invalid("revision");
        hex(revision, 16);
        return revision;
    }
    private static void validateOperations(Object value) {
        if (!(value instanceof List<?> operations) || operations.isEmpty() || operations.size() > 128) {
            throw invalid("transaction operations");
        }
        Set<String> seen = new HashSet<>();
        for (Object entry : operations) {
            if (!(entry instanceof Map<?, ?> operation) || !(operation.get("collection") instanceof String collection)
                    || !(operation.get("document") instanceof String document)) throw invalid("transaction identity");
            String path = writePath(collection, document);
            if (!seen.add(path)) throw invalid("duplicate transaction identity");
            int modes = (operation.containsKey("put") ? 1 : 0) + (operation.containsKey("patch") ? 1 : 0)
                    + (operation.containsKey("delete") ? 1 : 0);
            if (modes != 1 || operation.containsKey("delete") && !Boolean.TRUE.equals(operation.get("delete"))) {
                throw invalid("transaction mode");
            }
            if (operation.containsKey("put")) {
                if (!(operation.get("put") instanceof String source)) throw invalid("transaction source");
                validateSource(utf8(source));
            }
            if (operation.containsKey("patch") && (!(operation.get("patch") instanceof Map<?, ?> patch) || patch.isEmpty())) {
                throw invalid("transaction patch");
            }
            if (operation.containsKey("etag") && (!(operation.get("etag") instanceof String tag) || !isHex(tag, 16))) {
                throw invalid("transaction ETag");
            }
            if (operation.containsKey("create_only") && (!(operation.get("create_only") instanceof Boolean create)
                    || create && (!operation.containsKey("put") || operation.containsKey("etag")))) {
                throw invalid("transaction preconditions");
            }
        }
    }
    private static String documentPath(String collection, String document) {
        identifier(collection);
        identifier(document);
        return "/v1/collections/" + collection + "/documents/" + document;
    }
    private static String writePath(String collection, String document) {
        String path = documentPath(collection, document);
        if (collection.equals("yamldb-system")) throw invalid("reserved collection");
        return path;
    }
    private static boolean isIdentifier(String value) { return value != null && value.matches("[a-z0-9-]{1,128}"); }
    private static void identifier(String value) { if (!isIdentifier(value)) throw invalid("identifier"); }
    private static boolean isHex(String value, int length) {
        return value != null && value.length() == length && value.matches("[0-9a-f]+");
    }
    private static void hex(String value, int length) { if (!isHex(value, length)) throw invalid("hex identifier"); }
    private static void optionalHex(String value, int length) { if (value != null) hex(value, length); }
    private static void validateToken(String token) {
        if (token == null || !token.isEmpty() && (token.length() < 32 || token.length() > 512)) throw invalid("credential");
        for (int i = 0; i < token.length(); i++) if (token.charAt(i) < 33 || token.charAt(i) > 126) throw invalid("credential");
    }
    private static void validateSource(byte[] source) {
        if (source == null || source.length == 0 || source.length > MAX_DOCUMENT_BYTES) throw invalid("YAML source size");
        decodeUtf8(source);
        // YAML grammar/profile validation belongs to the native daemon; no parsing or normalization here.
    }
    private static byte[] utf8(String value) {
        if (value.length() > MAX_REQUEST_BYTES) throw invalid("request size");
        try {
            ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(value));
            if (encoded.remaining() > MAX_REQUEST_BYTES) throw invalid("request size");
            byte[] result = new byte[encoded.remaining()];
            encoded.get(result);
            return result;
        } catch (CharacterCodingException failure) { throw invalid("UTF-8"); }
    }
    private static String decodeUtf8(byte[] bytes) {
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException failure) { throw invalid("UTF-8"); }
    }
    private static IllegalArgumentException invalid(String field) {
        return new IllegalArgumentException("yamora: invalid " + field);
    }
}
