package yamora_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	y "github.com/Andromeda1957/yamoraDB/yamora/drivers/go"
)

func TestTLSVerificationAndPolicy(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"status":"ok"}`)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	address := netip.MustParseAddrPort(strings.TrimPrefix(server.URL, "https://"))
	for _, insecure := range []*tls.Config{
		{InsecureSkipVerify: true}, {MinVersion: tls.VersionTLS12}, {MaxVersion: tls.VersionTLS12},
	} {
		if client, err := y.New(y.Config{Address: address, TLSConfig: insecure}); err == nil {
			client.Close()
			t.Fatal("accepted insecure TLS configuration")
		}
	}
	client, err := y.New(y.Config{Address: address, TLSConfig: &tls.Config{RootCAs: pool}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	untrusted, err := y.New(y.Config{Address: address, TLSConfig: &tls.Config{}})
	if err != nil {
		t.Fatal(err)
	}
	defer untrusted.Close()
	if _, err := untrusted.Health(context.Background()); err == nil {
		t.Fatal("accepted untrusted server")
	}
}

func TestNativeMutualTLSDriver(t *testing.T) {
	root := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(root, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600); err != nil {
		t.Fatal(err)
	}
	issue := func(name string, serial int64, usage x509.ExtKeyUsage) (string, string) {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		private, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		certPath, keyPath := filepath.Join(root, name+".pem"), filepath.Join(root, name+".key")
		for path, data := range map[string][]byte{certPath: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPath: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private})} {
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		return certPath, keyPath
	}
	serverCert, serverKey := issue("server", 2, x509.ExtKeyUsageServerAuth)
	clientCert, clientKey := issue("client", 3, x509.ExtKeyUsageClientAuth)
	certificate, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	client := nativeClientWithTLS(t, &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{certificate}},
		"--tls-cert-file", serverCert, "--tls-key-file", serverKey, "--tls-client-ca-file", caPath)
	ctx := context.Background()
	original := "# TLS round trip\r\nname: service\r\n"
	if _, err := client.Put(ctx, "services", "api", []byte(original), y.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	document, err := client.Get(ctx, "services", "api", "")
	if err != nil || string(document.Source) != original {
		t.Fatalf("%q %v", document.Source, err)
	}
}
