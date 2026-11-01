using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Yamora;

// One public SDK call; the parent owns protocol, fixtures and assertions.
internal static class Program
{
    private static readonly string[] Required = ["host", "port", "server-name", "ca-file", "cert-file", "key-file",
        "method", "target", "content-type", "feed", "source-file", "request-id", "timeout-ms", "max-frame-bytes", "cancel-mode", "output-dir"];
    private static void Require(bool condition)
    {
        if (!condition) throw new InvalidOperationException("adapter input or infrastructure");
    }
    private static Dictionary<string, string> Arguments(string[] argv)
    {
        Require(argv.Length % 2 == 0);
        var args = new Dictionary<string, string>();
        for (int i = 0; i < argv.Length; i += 2)
        {
            Require(argv[i].StartsWith("--", StringComparison.Ordinal));
            var name = argv[i][2..];
            Require((Required.Contains(name) || name is "token-file" or "if-match" or "if-none-match") && argv[i + 1].Length <= 4096);
            Require(args.TryAdd(name, argv[i + 1]));
        }
        Require(Required.All(args.ContainsKey));
        return args;
    }
    private static int Number(string value, int maximum)
    {
        Require(value.Length is > 0 and <= 5 && value.All(char.IsAsciiDigit));
        int n = int.Parse(value, CultureInfo.InvariantCulture);
        Require(n > 0 && n <= maximum);
        return n;
    }
    private static byte[] Read(string path, int cap)
    {
        Require(Path.IsPathFullyQualified(path));
        using var stream = File.OpenRead(path);
        Require(stream.Length <= cap);
        using var bytes = new MemoryStream();
        var buffer = new byte[8192];
        int count;
        while ((count = stream.Read(buffer, 0, Math.Min(buffer.Length, cap + 1 - (int)bytes.Length))) > 0)
        {
            bytes.Write(buffer, 0, count);
            Require(bytes.Length <= cap);
        }
        return bytes.ToArray();
    }
    private static void Write(string root, string name, byte[] bytes)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        using var file = new FileStream(Path.Combine(root, name), new FileStreamOptions
        {
            Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
        });
        file.Write(bytes);
    }
    private static string Kind(BinaryFailure kind) => kind switch
    {
        BinaryFailure.Status => "status", BinaryFailure.Deadline => "deadline", BinaryFailure.Canceled => "cancelled",
        BinaryFailure.Protocol => "protocol", BinaryFailure.Transport => "transport",
        _ => throw new InvalidOperationException("unexpected SDK error kind")
    };
    private static string MethodName(BinaryMethod method) => method switch
    {
        BinaryMethod.Get => "GET", BinaryMethod.Head => "HEAD", BinaryMethod.Put => "PUT", BinaryMethod.Delete => "DELETE",
        _ => throw new InvalidOperationException("unexpected envelope method")
    };
    private static async Task<object> Observe(string[] argv)
    {
        Require(OperatingSystem.IsLinux());
        var args = Arguments(argv);
        int port = Number(args["port"], 65535), timeout = Number(args["timeout-ms"], 30000);
        Require(args["host"] == "127.0.0.1" && args["server-name"] == "localhost" && port != 8000 && args["max-frame-bytes"] == "4096");
        Require(args["cancel-mode"] is "none" or "pre" or "external");
        var method = args["method"];
        Require(method is "GET" or "POST" or "PATCH");
        Require(args["feed"] is "true" or "false");
        string root = args["output-dir"];
        Require(Path.IsPathFullyQualified(root) && Path.GetFullPath(root) == root && Directory.Exists(root) && new DirectoryInfo(root).LinkTarget is null);
        byte[] source = Read(args["source-file"], BinaryClient.DocumentLimit);
        Require(method != "GET" || source.Length == 0);
        string? bearer = null;
        if (args.TryGetValue("token-file", out var tokenFile))
        {
            var bytes = Read(tokenFile, 512);
            Require(bytes.Length > 0 && bytes.All(b => b is >= 33 and <= 126));
            bearer = System.Text.Encoding.ASCII.GetString(bytes);
        }
        // Bound credential files before their native PEM loaders run.
        _ = Read(args["ca-file"], 65536); _ = Read(args["cert-file"], 65536); _ = Read(args["key-file"], 65536);
        var roots = new X509Certificate2Collection();
        roots.ImportFromPemFile(args["ca-file"]);
        try
        {
            using var identity = X509Certificate2.CreateFromPemFile(args["cert-file"], args["key-file"]);
            using var client = new BinaryClient(new BinaryClientOptions
            {
                Endpoint = $"https://127.0.0.1:{port}", ServerName = args["server-name"], TrustedRoots = roots.ToArray(),
                ClientCertificate = identity, Timeout = TimeSpan.FromMilliseconds(timeout), MaxFrameBytes = 4096, MaxConcurrentCalls = 1
            });
            using var cancel = new CancellationTokenSource();
            if (args["cancel-mode"] == "pre") cancel.Cancel();
            using var control = new Control(args["cancel-mode"] == "external", cancel);
            BinaryResponse? response = null;
            BinaryException? error = null;
            long elapsed;
            args.TryGetValue("if-match", out var match); args.TryGetValue("if-none-match", out var none);
            FileStream? feedFile = null;
            long start = Stopwatch.GetTimestamp();
            try
            {
                if (args["feed"] == "true") {
                    response = (await client.FeedAsync(args["target"], async (page, ct) => {
                        feedFile ??= new FileStream(Path.Combine(root, "body.bin"), FileMode.CreateNew, FileAccess.Write, FileShare.None);
                        await feedFile.WriteAsync(page, CancellationToken.None).ConfigureAwait(false);
                        await feedFile.FlushAsync(CancellationToken.None).ConfigureAwait(false);
                    }, bearer, args["request-id"], match, none, cancel.Token).ConfigureAwait(false)).Response;
                } else response = await client.OperationAsync(method, args["target"], args["content-type"], source,
                    bearer, match, none, args["request-id"], cancel.Token).ConfigureAwait(false);
                elapsed = Nanoseconds(start);
            }
            catch (BinaryException caught)
            {
                elapsed = Nanoseconds(start);
                error = caught;
                if (caught is BinaryOperationException failure) response = failure.Response;
            }
            finally { if (feedFile is not null) await feedFile.DisposeAsync().ConfigureAwait(false); }
            control.Finish();
            var api = new Dictionary<string, object?>
            {
                ["status"] = null, ["body_file"] = null, ["etag"] = null, ["revision"] = null,
                ["representation_length"] = null, ["request_id"] = null, ["receipt"] = null
            };
            string outcome = "success";
            string? kind = null;
            object? envelope = null;
            if (response is not null)
            {
                if (feedFile is null) Write(root, "body.bin", response.Body);
                api["status"] = response.StatusCode; api["body_file"] = "body.bin"; api["etag"] = response.ETag;
                api["revision"] = response.Revision; api["representation_length"] = response.RepresentationLength; api["request_id"] = response.RequestId;
            }
            if (error is not null)
            {
                kind = Kind(error.Kind); outcome = kind;
                if (error.StatusCode != 0) api["status"] = error.StatusCode;
                if (error is BinaryOperationException { Recovery: not null } uncertain)
                {
                    Require(uncertain.OutcomeMayBeCommitted);
                    var original = uncertain.Recovery!;
                    Write(root, "envelope.bin", original.Source);
                    envelope = new { method = original.Method, target = original.Target, content_type = original.ContentType,
                        if_match = original.IfMatch, if_none_match = original.IfNoneMatch, request_id = original.RequestId, source_file = "envelope.bin" };
                    outcome = "uncertain";
                }
                else Require(!error.OutcomeMayBeCommitted);
            }
            return new { schema = "yamora-operation-observation/3", outcome, error_kind = kind, elapsed_ns = elapsed, api, envelope };
        }
        finally { foreach (var rootCert in roots) rootCert.Dispose(); }
    }
    private static long Nanoseconds(long start) => checked((long)((decimal)(Stopwatch.GetTimestamp() - start) * 1_000_000_000 / Stopwatch.Frequency));

    // Console.ReadLineAsync may leave a blocking stdin reader behind. Poll the
    // runner's pipe instead, and join the sole reader before disposing the token.
    [StructLayout(LayoutKind.Sequential)]
    private struct PollFd { public int Fd; public short Events; public short Returned; }
    [DllImport("libc", EntryPoint = "poll", SetLastError = true)]
    private static extern int Poll(ref PollFd fd, nuint count, int timeout);
    [DllImport("libc", EntryPoint = "read", SetLastError = true)]
    private static extern nint ReadFd(int fd, [Out] byte[] bytes, nuint count);
    private sealed class Control : IDisposable
    {
        private volatile bool stop;
        private volatile bool good = true;
        private Thread? worker;
        public Control(bool enabled, CancellationTokenSource cancel)
        {
            if (!enabled) return;
            using var started = new ManualResetEventSlim();
            worker = new Thread(() =>
            {
                started.Set();
                int state = 0;
                var bytes = new byte[3];
                try
                {
                    while (!stop)
                    {
                        var fd = new PollFd { Fd = 0, Events = 1 };
                        int result = Poll(ref fd, 1, 20);
                        if (result < 0 && Marshal.GetLastPInvokeError() == 4) continue;
                        if (result < 0 || (fd.Returned & (8 | 32)) != 0) { good = false; cancel.Cancel(); return; }
                        if (result == 0) continue;
                        nint n = ReadFd(0, bytes, 3);
                        if (n < 0 && Marshal.GetLastPInvokeError() == 4) continue;
                        if (n == 0 && state != 1) return;
                        if (n <= 0) { good = false; cancel.Cancel(); return; }
                        for (int i = 0; i < n; ++i)
                        {
                            if (state == 2 || bytes[i] != (state == 1 ? (byte)'\n' : (byte)'C')) { good = false; cancel.Cancel(); return; }
                            ++state;
                        }
                        if (state == 2) cancel.Cancel();
                    }
                    if (state == 1) { good = false; cancel.Cancel(); }
                }
                catch { good = false; cancel.Cancel(); }
            }) { Name = "conformance-cancel" };
            worker.Start();
            Require(started.Wait(TimeSpan.FromSeconds(1)));
        }
        public void Finish()
        {
            stop = true;
            if (worker is not null) { Require(worker.Join(1000)); worker = null; }
            Require(good);
        }
        public void Dispose() => Finish();
    }
    private static async Task<int> Main(string[] argv)
    {
        try
        {
            var json = JsonSerializer.Serialize(await Observe(argv).ConfigureAwait(false));
            Require(System.Text.Encoding.UTF8.GetByteCount(json) + 1 <= 16384);
            Console.WriteLine(json);
            return 0;
        }
        catch { Console.Error.WriteLine("C# conformance adapter failed"); return 2; }
    }
}
