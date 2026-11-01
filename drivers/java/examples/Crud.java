import io.yamora.Tls;
import io.yamora.YamoraClient;
import io.yamora.YamoraClient.WriteOptions;
import io.yamora.YamoraException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;

/** Run only against a disposable database; uncertain mutations stop without replay. */
public final class Crud {
    private Crud() {}

    public static void main(String[] args) throws Exception {
        var env = System.getenv();
        String identity = env.get("YAMORA_IDENTITY_FILE");
        char[] password = identity == null ? null : env.get("YAMORA_IDENTITY_PASSWORD").toCharArray();
        Tls tls;
        try {
            tls = Tls.trustPem(Path.of(env.get("YAMORA_CA_FILE")),
                    identity == null ? null : Path.of(identity), password);
        } finally {
            if (password != null) Arrays.fill(password, '\0');
        }
        var client = new YamoraClient(env.getOrDefault("YAMORA_HOST", "127.0.0.1"),
                Integer.parseInt(env.get("YAMORA_PORT")),
                env.getOrDefault("YAMORA_READ_TOKEN", ""), env.getOrDefault("YAMORA_WRITE_TOKEN", ""), tls);
        String collection = "examples", document = "java-package-crud";
        String authored = "# keep café\r\nname: Alpha\r\nn: 1 # keep inline\r\nwide: 9007199254740993\r\n";
        byte[] source = authored.getBytes(StandardCharsets.UTF_8);
        var stored = client.put(collection, document, source, new WriteOptions(null, true, null));
        var original = client.get(collection, document, stored.revision());
        check(Arrays.equals(source, original.source()), "GET changed authored bytes");
        client.patch(collection, document, "{\"$inc\":{\"n\":1}}", new WriteOptions(original.etag(), false, null));
        var updated = client.get(collection, document, null);
        check(Arrays.equals(authored.replace("n: 1 #", "n: 2 #").getBytes(StandardCharsets.UTF_8), updated.source()),
                "PATCH changed comments, CRLF, UTF-8 or int64 source");
        client.delete(collection, document, new WriteOptions(updated.etag(), false, null));
        try {
            client.get(collection, document, null);
            throw new AssertionError("deleted document remained readable");
        } catch (YamoraException expected) {
            check(expected.status() == 404, "DELETE verification did not return 404");
        }
        System.out.println("Yamora Java package CRUD passed: exact UTF-8, CRLF, comments and int64 source.");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
