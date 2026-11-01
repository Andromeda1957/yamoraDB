using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Yamora;

namespace DriverTests;

// One owned loopback listener. No external services or global trust changes.
sealed class Server : IAsyncDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource stop = new(TimeSpan.FromSeconds(15));
    private readonly Task worker;
    public string Endpoint { get; }
    public int Connections;
    public string LastRequest = "";
    public byte[] LastBody = [];
    public SslProtocols Negotiated;
    public Server(Func<Stream, Task> reply, X509Certificate2? certificate = null, SslProtocols protocols = SslProtocols.Tls13,
        X509Certificate2? clientRoot = null)
    {
        listener.Start();
        Endpoint = $"{(certificate is null ? "http" : "https")}://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}";
        worker = Task.Run(async () =>
        {
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    using var socket = await listener.AcceptTcpClientAsync(stop.Token);
                    Interlocked.Increment(ref Connections);
                    await using Stream stream = certificate is null ? socket.GetStream() : new SslStream(socket.GetStream());
                    try
                    {
                        if (stream is SslStream ssl)
                        {
                            var options = new SslServerAuthenticationOptions { ServerCertificate = certificate, EnabledSslProtocols = protocols };
                            if (clientRoot is not null)
                            {
                                options.ClientCertificateRequired = true;
                                options.CertificateChainPolicy = new X509ChainPolicy
                                {
                                    TrustMode = X509ChainTrustMode.CustomRootTrust,
                                    RevocationMode = X509RevocationMode.NoCheck,
                                    DisableCertificateDownloads = true,
                                };
                                options.CertificateChainPolicy.CustomTrustStore.Add(clientRoot);
                                options.CertificateChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2"));
                            }
                            await ssl.AuthenticateAsServerAsync(options, stop.Token);
                            Negotiated = ssl.SslProtocol;
                        }
                        var (headers, body) = await ReadRequest(stream, stop.Token);
                        LastRequest = headers;
                        LastBody = body;
                        await reply(stream);
                    }
                    catch (Exception e) when (e is IOException or AuthenticationException or OperationCanceledException) { }
                }
            }
            catch (Exception e) when (e is OperationCanceledException or SocketException or ObjectDisposedException) { }
        });
    }
    public static async Task<(string, byte[])> ReadRequest(Stream stream, CancellationToken ct)
    {
        using var header = new MemoryStream();
        var next = new byte[1];
        while (header.Length < 16384)
        {
            if (await stream.ReadAsync(next, ct) != 1) throw new IOException("closed before request");
            header.WriteByte(next[0]);
            if (header.Length >= 4 && header.GetBuffer().AsSpan((int)header.Length - 4, 4).SequenceEqual("\r\n\r\n"u8)) break;
        }
        var headers = Encoding.ASCII.GetString(header.ToArray());
        var length = Regex.Match(headers, @"(?im)^Content-Length: ([0-9]+)\r$");
        var body = new byte[length.Success ? int.Parse(length.Groups[1].Value) : 0];
        await stream.ReadExactlyAsync(body, ct);
        return (headers, body);
    }
    public static Task Bytes(Stream stream, string text) => stream.WriteAsync(Encoding.UTF8.GetBytes(text)).AsTask();
    public static string Response(string body, string extra = "", string media = "application/json")
        => $"HTTP/1.1 200 OK\r\nConnection: close\r\nX-YamlDB-Revision: 0123456789abcdef\r\nContent-Type: {media}\r\n{extra}Content-Length: {Encoding.UTF8.GetByteCount(body)}\r\n\r\n{body}";
    public async ValueTask DisposeAsync()
    {
        stop.Cancel();
        listener.Stop();
        await worker;
        stop.Dispose();
    }
}

sealed class Certificates : IDisposable
{
    private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly X509Certificate2 ca;
    public X509Certificate2 Root => ca;
    public Certificates()
    {
        var request = new CertificateRequest("CN=Yamora driver test CA", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        ca = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddHours(1));
    }
    public X509Certificate2 Intermediate()
    {
        using var intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Yamora intermediate " + Guid.NewGuid().ToString("N"), intermediateKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        using var certificate = request.Create(ca, DateTimeOffset.UtcNow.AddMinutes(-30), DateTimeOffset.UtcNow.AddMinutes(45), RandomNumberGenerator.GetBytes(16));
        return certificate.CopyWithPrivateKey(intermediateKey);
    }
    public X509Certificate2 Issue(string ip = "127.0.0.1", bool client = false, bool expired = false,
        string? issuerUrl = null, X509Certificate2? issuer = null, string? peerName = null)
    {
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Yamora test", leafKey, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        var usages = new OidCollection { new(client ? "1.3.6.1.5.5.7.3.2" : "1.3.6.1.5.5.7.3.1") };
        if (peerName is not null) usages.Add(new Oid("1.3.6.1.5.5.7.3.2"));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, true));
        var san = new SubjectAlternativeNameBuilder();
        san.AddIpAddress(IPAddress.Parse(ip));
        if (peerName is not null) san.AddDnsName(peerName);
        req.CertificateExtensions.Add(san.Build());
        if (issuerUrl is not null)
            req.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension([], [issuerUrl]));
        using var leaf = req.Create(issuer ?? ca, DateTimeOffset.UtcNow.AddMinutes(-20), DateTimeOffset.UtcNow.AddMinutes(expired ? -1 : 30), RandomNumberGenerator.GetBytes(16));
        return leaf.CopyWithPrivateKey(leafKey);
    }
    public void Dispose() { ca.Dispose(); key.Dispose(); }
}

sealed class Native : IAsyncDisposable
{
    public const string ReadToken = "rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr";
    public const string WriteToken = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww";
    private readonly Process process;
    private readonly Task<string> stderr;
    private readonly string root;
    public string Endpoint { get; }
    private Native(Process process, Task<string> stderr, string root, string endpoint)
    { this.process = process; this.stderr = stderr; this.root = root; Endpoint = endpoint; }
    public Client Client(IReadOnlyList<X509Certificate2>? roots = null, X509Certificate2? cert = null)
        => new(new ClientOptions
        {
            Endpoint = Endpoint,
            ReadToken = ReadToken,
            WriteToken = WriteToken,
            Timeout = TimeSpan.FromSeconds(10),
            TrustedRoots = roots ?? [],
            ClientCertificate = cert
        });

    public static async Task<Native> Start(string binary, bool replica = false, Certificates? certificates = null)
    {
        var scratch = Environment.GetEnvironmentVariable("TMPDIR") ?? throw new Exception("TMPDIR required");
        var root = Directory.CreateDirectory(Path.Combine(scratch, "native-" + Guid.NewGuid().ToString("N"))).FullName;
        Process? process = null;
        try
        {
            var data = Directory.CreateDirectory(Path.Combine(root, "data")).FullName;
            foreach (var (name, token) in new[] { ("read", ReadToken), ("write", WriteToken) })
            {
                var path = Path.Combine(root, name);
                await File.WriteAllTextAsync(path, token);
                if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            using var init = StartProcess(binary, ["--data-dir", data, "--init-disk", "--validate-only"]);
            var initOutput = init.StandardError.ReadToEndAsync();
            try { await init.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(20)); }
            catch { if (!init.HasExited) init.Kill(true); await init.WaitForExitAsync(); throw; }
            if (init.ExitCode != 0) throw new Exception("native initialization: " + await initOutput);
            var arguments = new List<string> { "--data-dir", data, "--port", "0", "--auth-token-file", Path.Combine(root, "read"), "--write-auth-token-file", Path.Combine(root, "write") };
            if (replica) arguments.Add("--replica");
            if (certificates is not null)
            {
                using var server = certificates.Issue();
                var certPath = Path.Combine(root, "server.pem");
                var keyPath = Path.Combine(root, "server.key");
                var caPath = Path.Combine(root, "ca.pem");
                await File.WriteAllTextAsync(certPath, server.ExportCertificatePem());
                using var privateKey = server.GetECDsaPrivateKey()!;
                await File.WriteAllTextAsync(keyPath, privateKey.ExportECPrivateKeyPem());
                await File.WriteAllTextAsync(caPath, certificates.Root.ExportCertificatePem());
                if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                arguments.AddRange(["--tls-cert-file", certPath, "--tls-key-file", keyPath, "--tls-client-ca-file", caPath]);
            }
            process = StartProcess(binary, arguments);
            var stderr = process.StandardError.ReadToEndAsync();
            var banner = await process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(15));
            var match = Regex.Match(banner ?? "", @"^yamora listening on (127\.0\.0\.1:[0-9]+) ");
            if (!match.Success) throw new Exception("no native startup banner: " + (process.HasExited ? await stderr : "timeout"));
            return new Native(process, stderr, root, (certificates is null ? "http://" : "https://") + match.Groups[1].Value);
        }
        catch
        {
            if (process is not null) { if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync(); process.Dispose(); }
            Directory.Delete(root, true);
            throw;
        }
    }
    private static Process StartProcess(string binary, IEnumerable<string> arguments)
    {
        var info = new ProcessStartInfo(binary) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var arg in arguments) info.ArgumentList.Add(arg);
        return Process.Start(info) ?? throw new Exception("could not start native daemon");
    }
    public async ValueTask DisposeAsync()
    {
        if (!process.HasExited)
        {
            if (OperatingSystem.IsLinux())
            {
                using var signal = StartProcess("/usr/bin/kill", ["-TERM", process.Id.ToString()]);
                await signal.WaitForExitAsync();
            }
            else process.Kill(true);
        }
        try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (TimeoutException) { process.Kill(true); await process.WaitForExitAsync(); }
        var errors = await stderr;
        var exit = process.ExitCode;
        process.Dispose();
        Directory.Delete(root, true);
        if (exit != 0 || errors.Contains("ERROR: AddressSanitizer", StringComparison.Ordinal)
            || errors.Contains("runtime error:", StringComparison.Ordinal)) throw new Exception("native daemon exit/sanitizer: " + exit + " " + errors);
    }
}
