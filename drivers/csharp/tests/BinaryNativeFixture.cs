using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Yamora;

namespace DriverTests;

sealed class BinaryNative : IAsyncDisposable
{
    public const string ScopedToken = "ssssssssssssssssssssssssssssssss";
    private readonly string root;
    public readonly Certificates Ca = new();
    public readonly X509Certificate2 Identity;
    private Process? process;
    private Task<string>? stderr, stdout;
    public string HttpEndpoint { get; private set; } = "";
    public string Endpoint { get; private set; } = "";
    private readonly bool mtls;
    private BinaryNative(bool mtls)
    {
        this.mtls = mtls; Identity = Ca.Issue(client: true);
        root = Path.Combine(Environment.GetEnvironmentVariable("TMPDIR")!, "binary-native-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
    }
    private void Write(string name, string text)
    {
        var path = Path.Combine(root, name); File.WriteAllText(path, text);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
    public BinaryClient Client(int cap = 65536, TimeSpan? timeout = null, bool identity = true) => new(new BinaryClientOptions
    {
        Endpoint = Endpoint, ServerName = "127.0.0.1", TrustedRoots = [Ca.Root],
        ClientCertificate = identity ? Identity : null, MaxFrameBytes = cap, Timeout = timeout ?? TimeSpan.FromSeconds(30),
    });
    public Client Http() => new(new ClientOptions
    {
        Endpoint = HttpEndpoint, TrustedRoots = [Ca.Root], ClientCertificate = mtls ? Identity : null,
        ReadToken = Native.ReadToken, WriteToken = Native.WriteToken, Timeout = TimeSpan.FromSeconds(30),
    });
    public static async Task<BinaryNative> Start(string binary, bool mtls = true, bool legacy = false)
    {
        if (!Path.IsPathFullyQualified(binary) || !File.Exists(binary)) throw new Exception("native binary required");
        var fixture = new BinaryNative(mtls);
        try
        {
            string P(string name) => Path.Combine(fixture.root, name);
            fixture.Write("read", Native.ReadToken); fixture.Write("write", Native.WriteToken); fixture.Write("scoped", ScopedToken);
            fixture.Write("policy.json", JsonSerializer.Serialize(new
            {
                version = 1, roles = new { one = new { read = new[] { "allowed" }, write = new[] { "allowed" } } },
                principals = new { one = new { token_file = P("scoped"), roles = new[] { "one" } } },
            }));
            var data = Directory.CreateDirectory(P("data")).FullName;
            using (var init = StartProcess(binary, ["--data-dir", data, "--init-disk", "--validate-only"]))
            {
                var err = init.StandardError.ReadToEndAsync(); var output = init.StandardOutput.ReadToEndAsync();
                try { await init.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30)); }
                catch { if (!init.HasExited) init.Kill(true); await init.WaitForExitAsync(); throw; }
                var errors = await err; await output;
                if (init.ExitCode != 0 || Bad(errors)) throw new Exception("binary native init: " + errors);
            }
            if (legacy)
            {
                var path = Path.Combine(data, ".yamora-disk"); var bytes = await File.ReadAllBytesAsync(path);
                foreach (var offset in new[] { 0, 4096 })
                {
                    "YAMDIS04"u8.CopyTo(bytes.AsSpan(offset));
                    BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset + 4092), Crc32C(bytes.AsSpan(offset, 4092)));
                }
                await File.WriteAllBytesAsync(path, bytes);
            }
            using var certificate = fixture.Ca.Issue();
            fixture.Write("server.pem", certificate.ExportCertificatePem());
            using (var key = certificate.GetECDsaPrivateKey()!) fixture.Write("server.key", key.ExportECPrivateKeyPem());
            fixture.Write("ca.pem", fixture.Ca.Root.ExportCertificatePem());
            var args = new List<string> { "--data-dir", data, "--port", "0", "--binary-port", "0", "--io-timeout-ms", "15000",
                "--auth-token-file", P("read"), "--write-auth-token-file", P("write"), "--access-policy-file", P("policy.json"),
                "--tls-cert-file", P("server.pem"), "--tls-key-file", P("server.key") };
            if (mtls) args.AddRange(["--tls-client-ca-file", P("ca.pem")]);
            fixture.process = StartProcess(binary, args); fixture.stderr = fixture.process.StandardError.ReadToEndAsync();
            for (var i = 0; i < 2; i++)
            {
                var banner = await fixture.process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(20));
                var match = Regex.Match(banner ?? "", @"^(yamora|binary) listening on (127\.0\.0\.1:([0-9]+))");
                if (!match.Success || match.Groups[3].Value == "8000") throw new Exception("native binary startup: " + banner + (fixture.process.HasExited ? await fixture.stderr : ""));
                if (match.Groups[1].Value == "yamora") fixture.HttpEndpoint = "https://" + match.Groups[2].Value;
                else fixture.Endpoint = "https://" + match.Groups[2].Value;
            }
            fixture.stdout = fixture.process.StandardOutput.ReadToEndAsync();
            if (fixture.Endpoint.Length == 0 || fixture.HttpEndpoint.Length == 0) throw new Exception("both native listeners required");
            return fixture;
        }
        catch { await fixture.DisposeAsync(); throw; }
    }
    private static uint Crc32C(ReadOnlySpan<byte> bytes)
    {
        var crc = uint.MaxValue;
        foreach (var b in bytes)
        {
            crc ^= b; for (var i = 0; i < 8; i++) crc = (crc >> 1) ^ ((crc & 1) == 1 ? 0x82f63b78U : 0U);
        }
        return ~crc;
    }
    private static Process StartProcess(string binary, IEnumerable<string> args)
    {
        var info = new ProcessStartInfo(binary) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        info.Environment["ASAN_OPTIONS"] = "detect_leaks=1:halt_on_error=1:abort_on_error=1";
        info.Environment["UBSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:print_stacktrace=1";
        foreach (var arg in args) info.ArgumentList.Add(arg);
        return Process.Start(info) ?? throw new Exception("native process start failed");
    }
    private static bool Bad(string text) => text.Contains("Sanitizer", StringComparison.Ordinal) || text.Contains("runtime error:", StringComparison.Ordinal);

    // Proxy forwarding is independent of BinaryClient, so observation of exact
    // committed source precedes any explicitly requested retry under test.
    public async Task<byte[]> Forward(BinaryRequest request, CancellationToken ct)
    {
        using var socket = new TcpClient(AddressFamily.InterNetwork);
        await socket.ConnectAsync(IPAddress.Loopback, new Uri(Endpoint).Port, ct);
        using var stream = new SslStream(socket.GetStream());
        var policy = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.NoCheck, DisableCertificateDownloads = true };
        policy.CustomTrustStore.Add(Ca.Root); policy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
        await stream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = "127.0.0.1", EnabledSslProtocols = SslProtocols.Tls13,
            ApplicationProtocols = [new SslApplicationProtocol("yamora-binary/1")], CertificateChainPolicy = policy,
            ClientCertificateContext = mtls ? SslStreamCertificateContext.Create(Identity, null, offline: true) : null,
        }, ct);
        await stream.WriteAsync(BinaryFixtureWire.Frame(1, [0, 1, 0, 1, 0, 0, 16, 0, 0, 0, 0, 1], 0), ct);
        if ((await BinaryFixtureWire.Read(stream, ct)).Type != 1) throw new Exception("native HELLO missing");
        await stream.WriteAsync(BinaryFixtureWire.Frame(2, BinaryFixtureWire.Tlv(request.Fields.OrderBy(f => f.Key))), ct);
        for (var offset = 0; offset < request.Source.Length; offset += 4096)
            await stream.WriteAsync(BinaryFixtureWire.Frame(4, request.Source.AsSpan(offset, Math.Min(4096, request.Source.Length - offset)).ToArray()), ct);
        await stream.WriteAsync(BinaryFixtureWire.Frame(5), ct);
        using var reply = new MemoryStream();
        while (true)
        {
            var frame = await BinaryFixtureWire.Read(stream, ct); reply.Write(BinaryFixtureWire.Frame(frame.Type, frame.Payload));
            if (frame.Type == 5) break;
            if (frame.Type is not (3 or 4)) throw new Exception("native proxy response invalid");
        }
        return reply.ToArray();
    }
    public async ValueTask DisposeAsync()
    {
        var failures = new List<Exception>();
        if (process is { } child)
        {
            if (!child.HasExited)
            {
                try
                {
                    using var signal = StartProcess("/usr/bin/kill", ["-TERM", child.Id.ToString()]);
                    await signal.WaitForExitAsync(); if (signal.ExitCode != 0) throw new Exception("native termination failed");
                }
                catch (Exception e) { failures.Add(e); if (!child.HasExited) child.Kill(true); }
            }
            try { await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15)); }
            catch (Exception e) { failures.Add(e); if (!child.HasExited) child.Kill(true); await child.WaitForExitAsync(); }
            if (stdout is not null) await stdout;
            var errors = stderr is null ? "" : await stderr;
            if (child.ExitCode != 0 || Bad(errors)) failures.Add(new Exception("native exit/sanitizer: " + child.ExitCode + " " + errors));
            child.Dispose(); process = null;
        }
        // Every process and redirected stream is joined before removing owned files.
        Identity.Dispose(); Ca.Dispose(); Directory.Delete(root, true);
        if (failures.Count != 0) throw new AggregateException(failures);
    }
}
