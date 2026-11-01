using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Yamora;

namespace DriverTests;

sealed class NativeCluster : IAsyncDisposable
{
    public readonly Certificates Ca = new();
    public readonly X509Certificate2 Identity;
    public readonly X509Certificate2 ServerCertificate;
    public readonly ClusterSeed[] Seeds = new ClusterSeed[3];
    private readonly string binary, root;
    private readonly List<string>[] args = new List<string>[3];
    private readonly Process?[] processes = new Process?[3];
    private readonly Task<string>?[] errors = new Task<string>?[3];
    private NativeCluster(string binary)
    {
        this.binary = binary;
        root = Path.Combine(Environment.GetEnvironmentVariable("TMPDIR")!, "c" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);
        Identity = Ca.Issue(client: true); ServerCertificate = Ca.Issue();
    }
    private void Write(string name, string value)
    {
        var path = Path.Combine(root, name); File.WriteAllText(path, value);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
    private void Pair(string name, X509Certificate2 certificate)
    {
        Write(name + ".pem", certificate.ExportCertificatePem());
        using var key = certificate.GetECDsaPrivateKey()!; Write(name + ".key", key.ExportECPrivateKeyPem());
    }
    public static async Task<NativeCluster> Start(string binary)
    {
        if (!File.Exists(binary)) throw new Exception("missing native daemon");
        var cluster = new NativeCluster(binary);
        try
        {
            cluster.Pair("server", cluster.ServerCertificate); cluster.Write("ca.pem", cluster.Ca.Root.ExportCertificatePem());
            cluster.Write("read", Native.ReadToken); cluster.Write("write", Native.WriteToken);
            var reservations = new List<TcpListener>();
            try
            {
                int Port()
                {
                    var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); reservations.Add(listener);
                    var port = ((IPEndPoint)listener.LocalEndpoint).Port;
                    if (port == 8000) throw new Exception("owner port allocated"); return port;
                }
                var peers = Enumerable.Range(1, 3).Select(i => new { id = i, name = $"node{i}.test", address = "127.0.0.1", port = Port() }).ToArray();
                for (var i = 0; i < 3; i++) cluster.Seeds[i] = new($"https://127.0.0.1:{Port()}", i + 1);
                for (var i = 0; i < 3; i++)
                {
                    using var cert = cluster.Ca.Issue(peerName: $"node{i + 1}.test"); cluster.Pair($"node{i + 1}", cert);
                    var data = Directory.CreateDirectory(Path.Combine(cluster.root, $"d{i}")).FullName;
                    var journal = Directory.CreateDirectory(Path.Combine(cluster.root, $"j{i}")).FullName;
                    string P(string name) => Path.Combine(cluster.root, name);
                    var config = JsonSerializer.Serialize(new
                    {
                        cluster = Program.ClusterIdentityValue,
                        node = i + 1,
                        journal_dir = journal,
                        peers,
                        peer_tls = new { cert_file = P($"node{i + 1}.pem"), key_file = P($"node{i + 1}.key"), ca_file = P("ca.pem") },
                        request_timeout_ms = 3000,
                        journal_cache_bytes = 1048576
                    });
                    cluster.Write($"config{i}.json", config);
                    // Six partial requests must fit concurrently without exhausting native workers.
                    cluster.args[i] = ["--data-dir",data,"--port",new Uri(cluster.Seeds[i].Endpoint).Port.ToString(),"--workers","8",
                        "--cluster-config-file",P($"config{i}.json"),"--auth-token-file",P("read"),"--write-auth-token-file",P("write"),
                        "--cache-bytes","1048576","--tls-cert-file",P("server.pem"),"--tls-key-file",P("server.key"),"--tls-client-ca-file",P("ca.pem"),"--io-timeout-ms","3000"];
                }
            }
            finally { foreach (var listener in reservations) listener.Stop(); }
            for (var i = 0; i < 3; i++) await cluster.StartNode(i);
            await cluster.Leader(); return cluster;
        }
        catch { await cluster.DisposeAsync(); throw; }
    }
    public ClusterClient Client(IReadOnlyList<ClusterSeed>? seeds = null, TimeSpan? timeout = null) => new(new ClusterOptions
    {
        Seeds = seeds ?? Seeds,
        ClusterId = Program.ClusterIdentityValue,
        TrustedRoots = [Ca.Root],
        ClientCertificate = Identity,
        ReadToken = Native.ReadToken,
        WriteToken = Native.WriteToken,
        Timeout = timeout ?? TimeSpan.FromSeconds(20),
        AttemptTimeout = TimeSpan.FromSeconds(4),
    });
    public Client Direct(int i, bool identity = true) => new(new ClientOptions
    {
        Endpoint = Seeds[i].Endpoint,
        TrustedRoots = [Ca.Root],
        ClientCertificate = identity ? Identity : null,
        ReadToken = Native.ReadToken,
        WriteToken = Native.WriteToken,
        Timeout = TimeSpan.FromSeconds(1),
    });
    public async Task StartNode(int i)
    {
        if (processes[i] is not null) throw new Exception("member already running");
        var info = new ProcessStartInfo(binary) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var arg in args[i]) info.ArgumentList.Add(arg);
        var process = Process.Start(info)!; processes[i] = process; errors[i] = process.StandardError.ReadToEndAsync();
        var banner = await process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(15));
        if (banner is null || !banner.StartsWith("yamora listening on ", StringComparison.Ordinal)) throw new Exception("native cluster startup: " + banner + (process.HasExited ? await errors[i]! : ""));
    }
    public async Task StopNode(int i, bool crash = false)
    {
        if (processes[i] is not { } process) return;
        if (!process.HasExited)
        {
            if (crash) process.Kill();
            else
            {
                var signalInfo = new ProcessStartInfo("/usr/bin/kill") { UseShellExecute = false };
                signalInfo.ArgumentList.Add("-TERM"); signalInfo.ArgumentList.Add(process.Id.ToString());
                using var signal = Process.Start(signalInfo)!; await signal.WaitForExitAsync();
            }
        }
        try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(8)); }
        catch { if (!process.HasExited) process.Kill(); await process.WaitForExitAsync(); throw; }
        finally { processes[i] = null; }
        var stderr = await errors[i]!; var exit = process.ExitCode; process.Dispose();
        if ((!crash && exit != 0) || stderr.Contains("AddressSanitizer", StringComparison.Ordinal) || stderr.Contains("runtime error:", StringComparison.Ordinal) || stderr.Contains("LeakSanitizer", StringComparison.Ordinal))
            throw new Exception("native exit/sanitizer: " + exit + " " + stderr);
    }
    public async Task<int> Leader()
    {
        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < TimeSpan.FromSeconds(15))
        {
            for (var i = 0; i < 3; i++) if (processes[i] is not null)
            {
                try { using var client = Direct(i); if ((await client.ClusterStatusAsync()).Value.GetProperty("role").GetString() == "leader") return i; }
                catch (YamoraException) { }
            }
            await Task.Delay(25);
        }
        throw new Exception("native leader election timed out");
    }
    // Expose complete native sends independently of response consumption so
    // qualification can measure native exchange overlap, not just client tasks.
    public Task<NativeExchange> Send(int i, WireRequest request, CancellationToken ct, Func<CancellationToken, Task>? beforeFinalByte = null)
        => SendTo(Seeds[i].Endpoint, request, ct, beforeFinalByte);

    public async Task<NativeExchange> SendTo(string endpoint, WireRequest request, CancellationToken ct,
        Func<CancellationToken, Task>? beforeFinalByte = null)
    {
        var socket = new TcpClient(AddressFamily.InterNetwork);
        SslStream? ssl = null;
        try
        {
            await socket.ConnectAsync(IPAddress.Loopback, new Uri(endpoint).Port, ct);
            ssl = new SslStream(socket.GetStream());
            var policy = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust, DisableCertificateDownloads = true, RevocationMode = X509RevocationMode.NoCheck };
            policy.CustomTrustStore.Add(Ca.Root);
            policy.ApplicationPolicy.Add(new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1"));
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "127.0.0.1",
                EnabledSslProtocols = SslProtocols.Tls13,
                CertificateChainPolicy = policy,
                ClientCertificateContext = SslStreamCertificateContext.Create(Identity, null, offline: true)
            }, ct);
            await ssl.WriteAsync(Encoding.ASCII.GetBytes(request.Headers), ct);
            if (beforeFinalByte is null) await ssl.WriteAsync(request.Body, ct);
            else
            {
                if (request.Body.Length == 0) throw new Exception("native send barrier requires a body");
                await ssl.WriteAsync(request.Body.AsMemory(0, request.Body.Length - 1), ct);
                await beforeFinalByte(ct);
                await ssl.WriteAsync(request.Body.AsMemory(request.Body.Length - 1), ct);
            }
            await ssl.FlushAsync(ct);
            return new NativeExchange(socket, ssl, ct);
        }
        catch
        {
            if (ssl is not null) await ssl.DisposeAsync();
            socket.Dispose();
            throw;
        }
    }

    public async Task<byte[]> Forward(int i, WireRequest request, CancellationToken ct)
    {
        await using var exchange = await Send(i, request, ct);
        return await exchange.Read(ct);
    }

    public async Task<byte[]> ForwardTo(string endpoint, WireRequest request, CancellationToken ct)
    {
        await using var exchange = await SendTo(endpoint, request, ct);
        return await exchange.Read(ct);
    }

    public async ValueTask DisposeAsync()
    {
        var failures = new List<Exception>();
        for (var i = 0; i < 3; i++) try { await StopNode(i); } catch (Exception e) { failures.Add(e); }
        Identity.Dispose(); ServerCertificate.Dispose(); Ca.Dispose(); Directory.Delete(root, true);
        if (failures.Count > 0) throw new AggregateException(failures);
    }
}
