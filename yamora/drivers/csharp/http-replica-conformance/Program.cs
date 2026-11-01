using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Yamora;
using static HttpReplica.Protocol;

namespace HttpReplica;

sealed class Api
{
    public int? status { get; set; }
    public string? body_file { get; set; }
    public string? etag { get; set; }
    public string? revision { get; set; }
    public object? receipt { get; set; }
}
sealed class Observation(int sequence, string command)
{
    public string schema => "yamora-http-replica-observation/2";
    public int seq => sequence;
    public string action => command;
    public string outcome { get; set; } = "success";
    public string? error_kind { get; set; }
    public long elapsed_ns { get; set; }
    public Api api { get; } = new();
    public string? sdk_request_id { get; set; }
    public object? envelope { get; set; }
    public string? recovery_mode { get; set; }
    public string? recovery_handle { get; set; }
}
sealed record Call(string Method, string Collection, string Document, byte[]? Source, JsonElement? Patch, WriteOptions Conditions);

static class Program
{
    private static readonly Dictionary<string, ClusterWrite> Recoveries = new(StringComparer.Ordinal);
    private static Call ParseCall(JsonElement command, Protocol protocol)
    {
        Keys(command, "schema","seq","action","method","collection","document","source_file","request_id","if_match","if_none_match");
        var method = Text(command.GetProperty("method")); Need(new[] { "GET","PUT","PATCH","DELETE" }.Contains(method));
        var collection = Text(command.GetProperty("collection")); var document = Text(command.GetProperty("document"));
        Need(Match(collection, "[a-z0-9-]{1,128}") && Match(document, "[a-z0-9-]{1,128}") && (method == "GET" || collection != "yamldb-system"));
        var id = NullableText(command.GetProperty("request_id")); Need(id is null || Match(id, "[0-9a-f]{32}") && id.Any(c => c != '0'));
        var match = NullableText(command.GetProperty("if_match")); Need(match is null || Match(match, "\"[0-9a-f]{16}\""));
        var none = NullableText(command.GetProperty("if_none_match")); Need(none is null || none == "*" && method == "PUT" && match is null);
        Need(method != "GET" || id is null && match is null && none is null);
        var source = NullableText(command.GetProperty("source_file")); byte[]? bytes = null; JsonElement? patch = null;
        if (method is "PUT" or "PATCH")
        {
            Need(source is not null && Match(source, "input/[a-z0-9-]{1,64}\\.bin"));
            bytes = protocol.Read(source!); Need(bytes.Length > 0); Utf8.GetCharCount(bytes);
            if (method == "PATCH")
            {
                using var json = Json(bytes); Keys(json.RootElement, "$inc");
                var inc = json.RootElement.GetProperty("$inc"); Keys(inc, "n"); Need(Integer(inc.GetProperty("n")) == 1);
                patch = json.RootElement.Clone();
            }
        }
        else Need(source is null);
        if (method != "GET") Need(Recoveries.Count < 16);
        return new Call(method, collection, document, bytes, patch, new WriteOptions(match is null ? null : match[1..^1], none == "*", id));
    }
    private static string? Kind(string type) => type switch
    {
        nameof(HttpError) => "status", nameof(TransportError) => "transport", nameof(RequestCanceled) => "cancelled",
        nameof(YamoraException) => "protocol", _ => null,
    };
    private static long Elapsed(long started) => (long)(Stopwatch.GetElapsedTime(started).TotalNanoseconds);
    private static async Task<Observation> Execute(JsonElement command, int seq, Protocol protocol, ClusterClient client)
    {
        Need(Text(command.GetProperty("schema")) == "yamora-http-replica-command/2" && Integer(command.GetProperty("seq")) == seq);
        var action = Text(command.GetProperty("action")); var observation = new Observation(seq, action);
        if (action == "close")
        {
            Keys(command, "schema","seq","action"); client.Dispose(); Recoveries.Clear(); observation.outcome = "closed"; return observation;
        }
        ClusterWrite? recovery = null; Call? call = null;
        if (action == "recover")
        {
            Keys(command, "schema","seq","action","handle"); var handle = Text(command.GetProperty("handle"));
            Need(Recoveries.TryGetValue(handle, out recovery)); observation.recovery_handle = handle; observation.recovery_mode = "sdk-envelope";
        }
        else { Need(action == "call"); call = ParseCall(command, protocol); }
        var started = Stopwatch.GetTimestamp();
        try
        {
            object result;
            if (recovery is not null) result = await client.RecoverAsync(recovery);
            else result = call!.Method switch
            {
                "GET" => await client.GetAsync(call.Collection, call.Document),
                "PUT" => await client.PutAsync(call.Collection, call.Document, call.Source!, call.Conditions),
                "PATCH" => await client.PatchAsync(call.Collection, call.Document, call.Patch!.Value, call.Conditions),
                "DELETE" => await client.DeleteAsync(call.Collection, call.Document, call.Conditions),
                _ => throw new InvalidInput(),
            };
            observation.elapsed_ns = Elapsed(started);
            switch (result)
            {
                case Document document:
                    observation.api.body_file = protocol.Write(seq, "body", document.Source);
                    observation.api.etag = document.ETag; observation.api.revision = document.Revision; break;
                case Mutation mutation:
                    observation.api.etag = mutation.ETag; observation.api.revision = mutation.Revision; break;
                case string revision: observation.api.revision = revision; break;
                case ClusterReceipt receipt:
                    observation.api.status = receipt.StatusCode; observation.api.body_file = protocol.Write(seq, "body", receipt.Body);
                    observation.api.etag = receipt.ETag; observation.api.revision = receipt.Revision; break;
                default: throw new InvalidInput();
            }
        }
        catch (UncertainWriteException error)
        {
            observation.elapsed_ns = Elapsed(started); observation.outcome = "uncertain"; observation.error_kind = Kind(error.FailureKind);
            observation.sdk_request_id = error.RequestId; observation.recovery_mode = "sdk-envelope";
            if (action == "call")
            {
                observation.recovery_handle = "h" + (Recoveries.Count + 1); Recoveries.Add(observation.recovery_handle, error.Recovery);
            }
            var write = error.Recovery; var body = write.Body;
            observation.envelope = new
            {
                method = write.Method, path = write.Path,
                if_match = write.Conditions.ETag is null ? null : '"' + write.Conditions.ETag + '"',
                if_none_match = write.Conditions.CreateOnly ? "*" : null,
                request_id = write.RequestId, body_file = body is null ? null : protocol.Write(seq, "envelope", body),
            };
        }
        catch (YamoraException error)
        {
            observation.elapsed_ns = Elapsed(started); observation.outcome = Kind(error.GetType().Name) ?? throw new InvalidInput();
            observation.error_kind = observation.outcome;
            if (error is HttpError http) observation.api.status = (int)http.StatusCode;
        }
        catch (RequestCanceled)
        { observation.elapsed_ns = Elapsed(started); observation.outcome = "cancelled"; observation.error_kind = "cancelled"; }
        return observation;
    }
    private static async Task<int> Run(string[] args)
    {
        Need(args.Length == 4 && args[0] == "--config" && args[2] == "--root");
        var root = args[3]; NoLinks(root, true); Need(args[1] == root + "/config.json"); var protocol = new Protocol(root);
        using var document = Json(protocol.Read("config.json", LineLimit)); var config = document.RootElement;
        Keys(config, "schema","cluster_id","voters","seeds","tls","tokens","timeout_ms","attempt_timeout_ms");
        var cluster = Text(config.GetProperty("cluster_id"));
        Need(Text(config.GetProperty("schema")) == "yamora-http-replica-config/2" && Match(cluster, "[0-9a-f]{32}") && cluster.Any(c => c != '0') &&
            Integer(config.GetProperty("voters")) == 3 && Integer(config.GetProperty("timeout_ms")) == 15000 && Integer(config.GetProperty("attempt_timeout_ms")) == 3000);
        var seedValues = config.GetProperty("seeds"); Need(seedValues.ValueKind == JsonValueKind.Array && seedValues.GetArrayLength() == 3);
        var seeds = new List<ClusterSeed>(); var ports = new HashSet<int>(); var nodes = new HashSet<int>();
        foreach (var seed in seedValues.EnumerateArray())
        {
            Keys(seed, "host","port","node"); var port = Integer(seed.GetProperty("port")); var node = Integer(seed.GetProperty("node"));
            Need(Text(seed.GetProperty("host")) == "127.0.0.1" && port is >= 1 and <= 65535 && port != 8000 && node is >= 1 and <= 3 && ports.Add(port) && nodes.Add(node));
            seeds.Add(new ClusterSeed($"https://127.0.0.1:{port}", node));
        }
        var tls = config.GetProperty("tls"); Keys(tls, "ca_file","cert_file","key_file");
        Need(Text(tls.GetProperty("ca_file")) == "ca.pem" && Text(tls.GetProperty("cert_file")) == "client.pem" && Text(tls.GetProperty("key_file")) == "client.key");
        var tokens = config.GetProperty("tokens"); Keys(tokens, "read_file","write_file");
        Need(Text(tokens.GetProperty("read_file")) == "read.token" && Text(tokens.GetProperty("write_file")) == "write.token");
        var roots = new X509Certificate2Collection(); roots.ImportFromPem(Utf8.GetString(protocol.Read("ca.pem", LineLimit)));
        Need(roots.Count > 0);
        try
        {
            using var certificate = X509Certificate2.CreateFromPem(Utf8.GetString(protocol.Read("client.pem", LineLimit)), Utf8.GetString(protocol.Read("client.key", LineLimit)));
            string Token(string name) { var token = Utf8.GetString(protocol.Read(name, 512)).TrimEnd('\r','\n'); Need(Match(token, "[!-~]{32,512}")); return token; }
            using var client = new ClusterClient(new ClusterOptions
            {
                Seeds = seeds, ClusterId = cluster, Voters = 3, Timeout = TimeSpan.FromSeconds(15), AttemptTimeout = TimeSpan.FromSeconds(3),
                TrustedRoots = roots.Cast<X509Certificate2>().ToArray(), ClientCertificate = certificate,
                ReadToken = Token("read.token"), WriteToken = Token("write.token"), MaxRequestBytes = FileLimit, MaxResponseBytes = FileLimit,
            });
            using var input = Console.OpenStandardInput(); using var output = Console.OpenStandardOutput();
            for (var seq = 1; seq <= 64; seq++)
            {
                using var command = Json(Line(input)); var observation = await Execute(command.RootElement, seq, protocol, client);
                var bytes = JsonSerializer.SerializeToUtf8Bytes(observation); Need(bytes.Length + 1 <= LineLimit);
                output.Write(bytes); output.WriteByte(10); output.Flush();
                if (observation.outcome == "closed") return 0;
            }
            throw new InvalidInput();
        }
        finally { foreach (var certificate in roots) certificate.Dispose(); }
    }
    public static async Task<int> Main(string[] args)
    {
        try { return await Run(args); }
        catch (Exception)
        {
            // A fixed diagnostic also covers crypto/parser/IO failures safely.
            Console.Error.WriteLine("http replica adapter: invalid input or infrastructure failure"); return 2;
        }
    }
}
