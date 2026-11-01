package io.yamora;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/** Verified JSSE TLS configuration; no trust-all/custom-verifier injection point. */
public final class Tls {
    private final SSLContext context;
    private Tls(SSLContext context) { this.context = context; }
    SSLContext context() { return context; }

    /** Uses the JDK trust store; hostname/IP verification remains mandatory. */
    public static Tls systemTrust() throws GeneralSecurityException {
        return create(null, null);
    }

    /** Explicit trust anchors and optional PKCS12 client identity for mutual TLS.
     * Paths are application-owned configuration, never server response fields. */
    public static Tls trustPem(Path caPem, Path clientPkcs12, char[] password)
            throws IOException, GeneralSecurityException {
        KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
        trust.load(null, null);
        try (InputStream input = Files.newInputStream(caPem)) {
            Collection<? extends Certificate> certificates = CertificateFactory.getInstance("X.509")
                    .generateCertificates(input);
            if (certificates.isEmpty()) throw new GeneralSecurityException("yamora: no trust anchors");
            int i = 0;
            for (Certificate certificate : certificates) trust.setCertificateEntry("ca-" + i++, certificate);
        }
        KeyManager[] keys = null;
        if (clientPkcs12 != null) {
            KeyStore identity = KeyStore.getInstance("PKCS12");
            try (InputStream input = Files.newInputStream(clientPkcs12)) { identity.load(input, password); }
            KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            factory.init(identity, password);
            keys = factory.getKeyManagers();
        } else if (password != null) throw new IllegalArgumentException("yamora: identity required with password");
        return create(trust, keys);
    }

    private static Tls create(KeyStore trust, KeyManager[] keys) throws GeneralSecurityException {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(trust);
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(keys, factory.getTrustManagers(), null);
        return new Tls(context);
    }
}
