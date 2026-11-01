package io.yamora;

import java.io.ByteArrayInputStream;
import java.net.InetAddress;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/** Owned TLS 1.3 configuration. Numeric private/loopback IPv4 routing and explicit
 * certificate serverName are independent. No DNS routing, proxies, redirects,
 * mutable SSLContext or opaque trust/key-manager injection. */
public final class BinaryConfig {
    final byte[] address;
    final int port, maxCalls, maxFrame;
    final String serverName;
    final long timeoutNanos;
    private final SSLContext tls;

    public BinaryConfig(String endpoint, int port, String serverName, byte[] trustDerOrPem,
            byte[] clientPkcs12, char[] password, Duration timeout, int maxCalls, int maxFrame)
            throws GeneralSecurityException {
        address = address(endpoint);
        if (port < 1 || port > 65535 || maxCalls < 1 || maxCalls > 4 || maxFrame < 4096 || maxFrame > 65536
                || timeout == null || timeout.isNegative() || timeout.isZero() || timeout.compareTo(Duration.ofSeconds(30)) > 0) {
            throw BinaryEnvelope.invalid();
        }
        // SNI DNS name or canonical IPv4 identity; never an authority/path/URL.
        if (serverName == null || serverName.length() > 253 || !serverName.matches("[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?")) {
            throw BinaryEnvelope.invalid();
        }
        if (serverName.matches("[0-9.]+")) address(serverName);
        else for (String label : serverName.split("\\.", -1)) {
            if (label.length() < 1 || label.length() > 63 || label.startsWith("-") || label.endsWith("-")) throw BinaryEnvelope.invalid();
        }
        this.port = port; this.serverName = serverName; this.maxCalls = maxCalls;
        this.maxFrame = maxFrame; this.timeoutNanos = timeout.toNanos();
        tls = context(trustDerOrPem, clientPkcs12, password);
    }
    static byte[] address(String host) {
        if (host == null || !host.matches("(0|[1-9][0-9]{0,2})(\\.(0|[1-9][0-9]{0,2})){3}")) throw BinaryEnvelope.invalid();
        String[] parts = host.split("\\."); byte[] ip = new byte[4];
        for (int i = 0; i < 4; i++) {
            int octet = Integer.parseInt(parts[i]); if (octet > 255) throw BinaryEnvelope.invalid(); ip[i] = (byte) octet;
        }
        int a = ip[0] & 255, b = ip[1] & 255;
        if (!(a == 127 || a == 10 || a == 172 && b >= 16 && b <= 31 || a == 192 && b == 168)) throw BinaryEnvelope.invalid();
        return ip;
    }
    SSLContext tls() { return tls; }
    InetAddress endpoint() throws java.net.UnknownHostException { return InetAddress.getByAddress(address); }

    private static SSLContext context(byte[] trustInput, byte[] identityInput, char[] passwordInput)
            throws GeneralSecurityException {
        if (trustInput == null || trustInput.length < 1 || trustInput.length > 65536
                || identityInput != null && (identityInput.length < 1 || identityInput.length > 131072)
                || (identityInput == null) != (passwordInput == null)
                || passwordInput != null && passwordInput.length > 1024) throw BinaryEnvelope.invalid();
        byte[] trust = trustInput.clone();
        byte[] identity = identityInput == null ? null : identityInput.clone();
        char[] password = passwordInput == null ? null : passwordInput.clone();
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream input = new ByteArrayInputStream(trust);
            var parsed = factory.generateCertificates(input);
            if (parsed.isEmpty() || parsed.size() > 16 || input.available() != 0) throw new CertificateException("invalid anchors");
            Set<TrustAnchor> anchors = new HashSet<>();
            List<X509Certificate> owned = new ArrayList<>();
            for (Certificate certificate : parsed) {
                X509Certificate fresh = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
                owned.add(fresh); anchors.add(new TrustAnchor(fresh, null));
            }
            KeyManager[] keys = null;
            if (identity != null) {
                KeyStore store = KeyStore.getInstance("PKCS12");
                store.load(new ByteArrayInputStream(identity), password);
                int entries = 0;
                for (var names = store.aliases(); names.hasMoreElements();) {
                    String alias = names.nextElement();
                    if (++entries > 16) throw new GeneralSecurityException("identity entries");
                    if (store.isKeyEntry(alias)) {
                        Certificate[] chain = store.getCertificateChain(alias);
                        if (chain == null || chain.length < 1 || chain.length > 8 || !(store.getKey(alias, password) instanceof java.security.PrivateKey)) {
                            throw new GeneralSecurityException("identity key/chain");
                        }
                    }
                }
                KeyManagerFactory km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                km.init(store, password); keys = km.getKeyManagers();
            }
            // Validate only the peer-supplied chain against owned anchors. No PKIX
            // builder, AIA fetch, revocation network access, or platform trust callbacks.
            X509TrustManager manager = new X509TrustManager() {
                @Override public X509Certificate[] getAcceptedIssuers() { return owned.toArray(X509Certificate[]::new); }
                @Override public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException { throw new CertificateException("server only"); }
                @Override public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    if (chain == null || chain.length < 1 || chain.length > 8) throw new CertificateException("chain bound");
                    try {
                        List<X509Certificate> path = new ArrayList<>(List.of(chain));
                        if (owned.contains(path.get(path.size() - 1))) path.remove(path.size() - 1);
                        if (path.isEmpty()) chain[0].checkValidity();
                        else {
                            PKIXParameters parameters = new PKIXParameters(anchors);
                            parameters.setRevocationEnabled(false);
                            CertPathValidator.getInstance("PKIX").validate(CertificateFactory.getInstance("X.509").generateCertPath(path), parameters);
                        }
                        List<String> usage = chain[0].getExtendedKeyUsage();
                        if (usage != null && !usage.contains("1.3.6.1.5.5.7.3.1") && !usage.contains("2.5.29.37.0")) throw new CertificateException("server usage");
                    } catch (GeneralSecurityException failure) { throw new CertificateException("untrusted server chain"); }
                }
            };
            // A basic X509TrustManager is wrapped by JSSE's endpoint/algorithm checks.
            SSLContext context = SSLContext.getInstance("TLSv1.3");
            context.init(keys, new TrustManager[]{manager}, null);
            return context;
        } catch (java.io.IOException failure) { throw new GeneralSecurityException("invalid owned TLS material"); }
        finally {
            Arrays.fill(trust, (byte) 0);
            if (identity != null) Arrays.fill(identity, (byte) 0);
            if (password != null) Arrays.fill(password, '\0');
        }
    }
    @Override public String toString() { return "BinaryConfig[redacted]"; }
}
