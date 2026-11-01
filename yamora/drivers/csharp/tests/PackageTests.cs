using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;

namespace DriverTests;

static partial class Program
{
    static string PackageSource()
    {
        // Locate source independently of dotnet's redirected artifact directory.
        string current = Directory.GetCurrentDirectory();
        return new[] { Path.Combine(current, "yamora/drivers/csharp"),
            Path.Combine(current, "drivers/csharp"), current }
            .First(path => File.Exists(Path.Combine(path, "Yamora/Yamora.csproj")));
    }

    static async Task PackageOwner(string script, params string[] arguments)
    {
        var start = new ProcessStartInfo("python3") {
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true,
        };
        start.ArgumentList.Add(Path.Combine(PackageSource(), "tests", script));
        foreach (string argument in arguments) start.ArgumentList.Add(argument);
        using var child = Process.Start(start) ?? throw new Exception("cannot start package owner");
        var output = child.StandardOutput.ReadToEndAsync();
        var errors = child.StandardError.ReadToEndAsync();
        // The existing Python owner bounds the inner fixture and verifies its
        // complete group before deleting scratch, including on tool kill failure.
        await child.WaitForExitAsync();
        string text = await output, diagnostics = await errors;
        Console.Write(text);
        Console.Error.Write(diagnostics);
        Check(child.ExitCode == 0, "package owner failed: " + text + diagnostics);
    }

    static Task PackageLifecycle() => PackageOwner("test_package_lifecycle.py");

    static async Task PackageArtifact(string binary)
    {
        string? allocation = Environment.GetEnvironmentVariable("YAMORA_PACKAGE_WORKSPACE");
        if (allocation is null)
        {
            string host = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet";
            await PackageOwner("package_process.py", host, typeof(Program).Assembly.Location);
            return;
        }
        string root = Path.GetFullPath(allocation);
        string anchor = Environment.GetEnvironmentVariable("YAMORA_PACKAGE_TASK_ROOT") ??
            throw new Exception("package task anchor required");
        Check(Path.GetDirectoryName(root) == anchor && new DirectoryInfo(root).LinkTarget is null &&
            File.Exists(Path.Combine(anchor, ".yamora-sdk-retained-" + Path.GetFileName(root))),
            "package allocation must belong to the Python workspace owner");
        string source = PackageSource();
        string dotnet = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet";
        async Task<string> Run(string[] arguments, string cwd, Dictionary<string, string>? environment = null)
        {
            var start = new ProcessStartInfo(dotnet) {
                WorkingDirectory = cwd, RedirectStandardOutput = true, RedirectStandardError = true,
                UseShellExecute = false,
            };
            foreach (string argument in arguments) start.ArgumentList.Add(argument);
            start.Environment["NUGET_PACKAGES"] = Path.Combine(root, "nuget");
            start.Environment["MSBUILDDISABLENODEREUSE"] = "1";
            if (environment is not null)
                foreach (var (name, value) in environment) start.Environment[name] = value;
            using var process = Process.Start(start) ?? throw new Exception("cannot start package tool");
            var output = process.StandardOutput.ReadToEndAsync();
            var errors = process.StandardError.ReadToEndAsync();
            try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(120)); }
            finally
            {
                if (!process.HasExited) process.Kill(true);
                await process.WaitForExitAsync();
            }
            string text = await output;
            string diagnostics = await errors;
            Check(process.ExitCode == 0, text + diagnostics);
            return text;
        }
        {
            string stage = Directory.CreateDirectory(Path.Combine(root, "source")).FullName;
            string library = Directory.CreateDirectory(Path.Combine(stage, "Yamora")).FullName;
            foreach (string file in Directory.GetFiles(Path.Combine(source, "Yamora")))
                File.Copy(file, Path.Combine(library, Path.GetFileName(file)));
            foreach (string name in new[] { "README.md", "LICENSE" })
                File.Copy(Path.Combine(source, name), Path.Combine(stage, name));
            string examples = Directory.CreateDirectory(Path.Combine(stage, "examples/Crud")).FullName;
            foreach (string file in Directory.GetFiles(Path.Combine(source, "examples/Crud")))
                File.Copy(file, Path.Combine(examples, Path.GetFileName(file)));
            string feed = Directory.CreateDirectory(Path.Combine(root, "feed")).FullName;
            await Run(["pack", Path.Combine(library, "Yamora.csproj"), "-c", "Release", "--output", feed,
                "--configfile", Path.Combine(source, "NuGet.Config"), "-p:NuGetAudit=false", "-p:UseSharedCompilation=false",
                "--disable-build-servers", "-m:1"], root);
            using var archive = ZipFile.OpenRead(Path.Combine(feed, "Yamora.0.1.0.nupkg"));
            Check(archive.GetEntry("lib/net10.0/Yamora.dll") is not null, "missing library");
            Check(archive.GetEntry("README.md") is not null && archive.GetEntry("LICENSE") is not null, "missing package documentation");
            using (var license = archive.GetEntry("LICENSE")!.Open())
            using (var reader = new StreamReader(license))
                Check(await reader.ReadToEndAsync() == await File.ReadAllTextAsync(Path.Combine(source, "LICENSE")), "license changed");
            using (var stream = archive.GetEntry("Yamora.nuspec")!.Open())
            {
                var manifest = XDocument.Load(stream);
                Check(!manifest.Descendants().Any(node => node.Name.LocalName == "dependency"), "unexpected runtime dependency");
                Check(manifest.Descendants().Single(node => node.Name.LocalName == "version").Value == "0.1.0", "wrong version");
            }
            foreach (var entry in archive.Entries)
            {
                string name = entry.FullName;
                Check(name == "lib/net10.0/Yamora.dll" || name == "README.md" || name == "LICENSE" ||
                    name == "Yamora.nuspec" || name == "[Content_Types].xml" || name == "_rels/.rels" ||
                    name.StartsWith("package/services/metadata/core-properties/", StringComparison.Ordinal) ||
                    name == "examples/Crud/Crud.csproj" || name == "examples/Crud/Program.cs",
                    "unexpected package member: " + name);
            }
            string consumer = Directory.CreateDirectory(Path.Combine(root, "consumer")).FullName;
            foreach (string name in new[] { "Crud.csproj", "Program.cs" })
            {
                using var stream = archive.GetEntry("examples/Crud/" + name)!.Open();
                using var destination = File.Create(Path.Combine(consumer, name));
                await stream.CopyToAsync(destination);
            }
            // Compile every transport family against the package, without a
            // project reference or SDK checkout on the consumer's resolution path.
            await File.WriteAllTextAsync(Path.Combine(consumer, "TransportProbe.cs"), """
                using Yamora;
                internal static class PackageTransports
                {
                    internal static readonly Type[] All = [
                        typeof(Client), typeof(ClusterClient), typeof(BinaryClient),
                        typeof(ClusterOptions), typeof(BinaryClientOptions)];
                }
                """);
            string config = Path.Combine(consumer, "NuGet.Config");
            new XDocument(new XElement("configuration", new XElement("packageSources", new XElement("clear"),
                new XElement("add", new XAttribute("key", "local"), new XAttribute("value", feed))))).Save(config);
            await Run(["restore", "Crud.csproj", "--configfile", config, "-p:NuGetAudit=false", "--disable-parallel"], consumer);
            await Run(["build", "Crud.csproj", "-c", "Release", "--no-restore", "-p:UseSharedCompilation=false",
                "--disable-build-servers", "-m:1"], consumer);
            using (var packed = archive.GetEntry("lib/net10.0/Yamora.dll")!.Open())
            using (var actual = File.OpenRead(Path.Combine(consumer, "bin/Release/net10.0/Yamora.dll")))
                Check(System.Security.Cryptography.SHA256.HashData(packed).SequenceEqual(
                    System.Security.Cryptography.SHA256.HashData(actual)), "consumer DLL differs from artifact");
            using var certificates = new Certificates();
            using var identity = certificates.Issue(client: true);
            string caPath = Path.Combine(root, "ca.pem"), certPath = Path.Combine(root, "client.pem"), keyPath = Path.Combine(root, "client.key");
            await File.WriteAllTextAsync(caPath, certificates.Root.ExportCertificatePem());
            await File.WriteAllTextAsync(certPath, identity.ExportCertificatePem());
            using (var privateKey = identity.GetECDsaPrivateKey()!)
                await File.WriteAllTextAsync(keyPath, privateKey.ExportECPrivateKeyPem());
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            await using var native = await Native.Start(binary, certificates: certificates);
            var endpoint = new Uri(native.Endpoint);
            string result = await Run([Path.Combine(consumer, "bin/Release/net10.0/Crud.dll")], consumer, new() {
                ["YAMORA_HOST"] = endpoint.Host, ["YAMORA_PORT"] = endpoint.Port.ToString(),
                ["YAMORA_CA_FILE"] = caPath, ["YAMORA_CLIENT_CERT_FILE"] = certPath, ["YAMORA_CLIENT_KEY_FILE"] = keyPath,
                ["YAMORA_READ_TOKEN"] = Native.ReadToken, ["YAMORA_WRITE_TOKEN"] = Native.WriteToken,
            });
            Check(result.Trim() == "CRUD_OK", result);
        }
    }
}
