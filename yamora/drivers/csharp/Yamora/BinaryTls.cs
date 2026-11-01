using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace Yamora;

internal sealed class BinaryTls : IDisposable
{
    internal readonly IPEndPoint Address;
    private readonly string serverName;
    private readonly List<X509Certificate2> roots = [], intermediates = [];
    private X509Certificate2? identity;
    private SslStreamCertificateContext? context;
    internal BinaryTls(BinaryClientOptions options)
    {
        Validation.Require(options.Endpoint is { Length: <= 64 }, "invalid binary endpoint");
        var match = Regex.Match(options.Endpoint ?? "", @"\Ahttps://([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]{1,5})\z", RegexOptions.CultureInvariant);
        Validation.Require(match.Success, "binary requires explicit private IPv4 TLS endpoint");
        var host = match.Groups[1].Value;
        Validation.Require(IPAddress.TryParse(host, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork && ip.ToString() == host, "canonical IPv4 required");
        var octets = ip!.GetAddressBytes();
        Validation.Require(octets[0] == 127 || octets[0] == 10 || octets[0] == 172 && octets[1] is >= 16 and <= 31 || octets[0] == 192 && octets[1] == 168, "private IPv4 required");
        var portText = match.Groups[2].Value;
        Validation.Require(int.TryParse(portText, out var port) && port is >= 1 and <= 65535 && port.ToString(System.Globalization.CultureInfo.InvariantCulture) == portText, "invalid binary port");
        Address = new IPEndPoint(ip, port);
        serverName = options.ServerName;
        Validation.Require(serverName is { Length: > 0 and <= 253 } && (IPAddress.TryParse(serverName, out var nameIp)
            ? nameIp.AddressFamily == AddressFamily.InterNetwork && nameIp.ToString() == serverName
            : Regex.IsMatch(serverName, @"\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\z", RegexOptions.CultureInvariant)), "invalid TLS server identity");
        ArgumentNullException.ThrowIfNull(options.TrustedRoots); ArgumentNullException.ThrowIfNull(options.ClientIntermediates);
        Validation.Require(options.TrustedRoots.Length is > 0 and <= 64 && options.ClientIntermediates.Length <= 64, "explicit bounded trust roots required");
        Validation.Require(options.ClientCertificate is not null || options.ClientIntermediates.Length == 0, "mTLS identity required with intermediates");
        try
        {
            foreach (var root in options.TrustedRoots) roots.Add(Clone(root));
            foreach (var intermediate in options.ClientIntermediates) intermediates.Add(Clone(intermediate));
            if (options.ClientCertificate is { } certificate)
            {
                Validation.Require(certificate.GetType() == typeof(X509Certificate2) && certificate.HasPrivateKey, "exportable mTLS identity required");
                var pfx = certificate.Export(X509ContentType.Pkcs12);
                try { identity = X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.EphemeralKeySet); }
                finally { CryptographicOperations.ZeroMemory(pfx); }
                context = SslStreamCertificateContext.Create(identity, new X509Certificate2Collection(intermediates.ToArray()), offline: true);
            }
        }
        catch { Dispose(); throw; }
    }
    private static X509Certificate2 Clone(X509Certificate2 certificate)
    {
        Validation.Require(certificate is not null && certificate.GetType() == typeof(X509Certificate2), "concrete certificate required");
        return X509CertificateLoader.LoadCertificate(certificate.RawData);
    }
    internal SslClientAuthenticationOptions Options()
    {
        var policy = new X509ChainPolicy
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            DisableCertificateDownloads = true,
            RevocationMode = X509RevocationMode.NoCheck,
        };
        policy.CustomTrustStore.AddRange(roots.ToArray());
        policy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
        return new SslClientAuthenticationOptions
        {
            TargetHost = serverName, EnabledSslProtocols = SslProtocols.Tls13,
            ApplicationProtocols = [new SslApplicationProtocol("yamora-binary/1")],
            CertificateChainPolicy = policy, ClientCertificateContext = context,
            AllowRenegotiation = false, AllowTlsResume = false,
        };
    }
    public void Dispose()
    {
        if (context is not null) foreach (var cert in context.IntermediateCertificates) cert.Dispose();
        context = null;
        identity?.Dispose(); identity = null;
        foreach (var certificate in intermediates) certificate.Dispose(); intermediates.Clear();
        foreach (var root in roots) root.Dispose(); roots.Clear();
    }
}
