using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Yamora;

static string Required(string name) => Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
    ? value : throw new ArgumentException("missing required example configuration");

try
{
    string? certificate = Environment.GetEnvironmentVariable("YAMORA_CLIENT_CERT_FILE");
    string? key = Environment.GetEnvironmentVariable("YAMORA_CLIENT_KEY_FILE");
    if ((certificate is null) != (key is null))
        throw new ArgumentException("supply both client identity files");
    using var ca = X509CertificateLoader.LoadCertificateFromFile(Required("YAMORA_CA_FILE"));
    using var identity = certificate is null ? null : X509Certificate2.CreateFromPemFile(certificate, key);
    string host = Environment.GetEnvironmentVariable("YAMORA_HOST") ?? "127.0.0.1";
    string port = Required("YAMORA_PORT");
    using var client = new Client(new ClientOptions {
        Endpoint = $"https://{host}:{port}", TrustedRoots = [ca], ClientCertificate = identity,
        ReadToken = Required("YAMORA_READ_TOKEN"), WriteToken = Required("YAMORA_WRITE_TOKEN"),
    });
    string collection = Environment.GetEnvironmentVariable("YAMORA_COLLECTION") ?? "package-demo";
    string document = Environment.GetEnvironmentVariable("YAMORA_DOCUMENT") ?? "csharp";
    byte[] original = Encoding.UTF8.GetBytes("# authored café\r\nname: Ada\r\nvisits: 1\r\n");
    byte[] updated = Encoding.UTF8.GetBytes("# edited café, still CRLF\r\nname: Ada Lovelace\r\nvisits: 2\r\n");
    await client.PutAsync(collection, document, original, new(CreateOnly: true));
    var read = await client.GetAsync(collection, document);
    if (!read.Source.AsSpan().SequenceEqual(original)) throw new Exception("source changed");
    await client.PutAsync(collection, document, updated, new(read.ETag));
    read = await client.GetAsync(collection, document);
    if (!read.Source.AsSpan().SequenceEqual(updated)) throw new Exception("updated source changed");
    await client.DeleteAsync(collection, document, new(read.ETag));
    try
    {
        await client.GetAsync(collection, document);
        throw new Exception("deleted document still exists");
    }
    catch (HttpError error) when (error.StatusCode == HttpStatusCode.NotFound) { }
    Console.WriteLine("CRUD_OK");
    return 0;
}
catch (Exception)
{
    Console.Error.WriteLine("CRUD failed; reconcile any uncertain write before retrying.");
    return 1;
}
