package yamora_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	y "github.com/Andromeda1957/yamoraDB/yamora/drivers/go"
)

func binaryTrustCA(t *testing.T, p binaryPKI) (*x509.Certificate, []byte) {
	t.Helper()
	encoded, err := os.ReadFile(p.caPath)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(encoded)
	if block == nil || len(rest) != 0 {
		t.Fatal("invalid fixture CA PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert, encoded
}

// Verification alerts are expected in the old CA-mutation reproduction. After
// a successful handshake the peer must still serve a valid binary GET reply.
func binaryTrustPeer(t *testing.T, p binaryPKI) y.BinaryConfig {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			done <- nil
			return
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(2 * time.Second))
		c := tls.Server(raw, p.server)
		if c.Handshake() != nil {
			done <- nil
			return
		}
		if err := binaryTestHello(c); err != nil {
			done <- err
			return
		}
		request, _, err := binaryTestRequest(c)
		if err != nil {
			done <- err
			return
		}
		body := []byte("v: 1\n")
		fields := binaryTestResponse(200, body, request[8])
		fields[2], fields[7], fields[8] = []byte("application/yaml"), []byte("config"), []byte("one")
		if err = binaryTestSend(c, 3, binaryTestMeta(fields)); err == nil {
			err = binaryTestSend(c, 4, body)
		}
		if err == nil {
			err = binaryTestSend(c, 5, nil)
		}
		done <- err
	}()
	t.Cleanup(func() {
		listener.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error("trust peer fixture:", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("trust peer failed to join")
		}
	})
	return y.BinaryConfig{Address: netip.MustParseAddrPort(listener.Addr().String()), Timeout: time.Second}
}

func TestBinaryOpaqueRootCAObjectMutation(t *testing.T) {
	for _, mutation := range []string{"not-after", "not-before", "public-key"} {
		t.Run(mutation, func(t *testing.T) {
			p := newBinaryPKI(t)
			cert, rootPEM := binaryTrustCA(t, p)
			pool := x509.NewCertPool()
			pool.AddCert(cert)
			config := binaryTrustPeer(t, p)
			config.TLSConfig = p.client.Clone()
			config.TLSConfig.RootCAs = pool
			config.RootCAPEM = rootPEM
			client, err := y.NewBinary(config)
			// An opaque pool cannot be safely copied. Rejecting it before I/O
			// is the repaired contract; old clients proceed to the live probe.
			if err != nil {
				return
			}
			switch mutation {
			case "not-after":
				cert.NotAfter = time.Now().Add(-time.Hour)
			case "not-before":
				cert.NotBefore = time.Now().Add(time.Hour)
			case "public-key":
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				cert.PublicKey = &key.PublicKey
			}
			_, err = client.Get(context.Background(), "config", "one", "")
			if err != nil {
				t.Fatalf("caller CA %s mutation changed created client trust: %v", mutation, err)
			}
			t.Fatal("opaque caller-owned root pool was accepted")
		})
	}
}

func TestBinaryOpaqueRootConstraintLifetime(t *testing.T) {
	p := newBinaryPKI(t)
	cert, rootPEM := binaryTrustCA(t, p)
	entered, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var enterOnce, releaseOnce, exitOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	pool := x509.NewCertPool()
	pool.AddCertWithConstraint(cert, func([]*x509.Certificate) error {
		enterOnce.Do(func() { close(entered) })
		<-release
		exitOnce.Do(func() { close(exited) })
		return nil
	})
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(time.Second))
		tls.Server(raw, p.server).Handshake()
	}()
	defer func() { listener.Close(); <-joined }()
	secure := p.client.Clone()
	secure.RootCAs = pool
	client, err := y.NewBinary(y.BinaryConfig{Address: netip.MustParseAddrPort(listener.Addr().String()), TLSConfig: secure, RootCAPEM: rootPEM, Timeout: 40 * time.Millisecond})
	if err != nil {
		select {
		case <-entered:
			t.Fatal("constraint invoked during root rejection")
		default:
		}
		return
	}
	result := make(chan error, 1)
	go func() { _, err := client.Get(context.Background(), "config", "one", ""); result <- err }()
	select {
	case <-entered:
	case err := <-result:
		t.Fatalf("constraint reproduction failed: %v", err)
	case <-time.After(time.Second):
		t.Fatal("constraint fixture not entered")
	}
	blocked := false
	var returned error
	select {
	case returned = <-result:
	case <-time.After(150 * time.Millisecond):
		blocked = true
	}
	releaseOnce.Do(func() { close(release) })
	if blocked {
		select {
		case returned = <-result:
		case <-time.After(time.Second):
			t.Fatal("call failed to join released constraint")
		}
	}
	<-exited
	if blocked {
		t.Fatal("opaque root constraint outlived deadline and blocked call teardown")
	}
	if !errors.Is(returned, context.DeadlineExceeded) {
		t.Fatalf("opaque constraint changed deadline outcome: %v", returned)
	}
	t.Fatal("opaque root constraint was accepted and executed")
}

func TestBinaryRootCAPEMOwnedTrust(t *testing.T) {
	p := newBinaryPKI(t)
	cert, rootPEM := binaryTrustCA(t, p)
	config := binaryTrustPeer(t, p)
	config.TLSConfig, config.RootCAPEM = p.binary, rootPEM
	client := binaryClient(t, config)
	// Mutate the input's encoded representation and parsed certificate fields,
	// including the public key. The constructed client must still verify TLS.
	clear(rootPEM)
	clear(cert.Raw)
	cert.NotAfter, cert.NotBefore = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	cert.PublicKey = nil
	document, err := client.Get(context.Background(), "config", "one", "")
	if err != nil || string(document.Source) != "v: 1\n" {
		t.Fatalf("owned PEM trust changed after caller mutation: %v", err)
	}
}

func TestBinaryRootCAPEMBoundsAndFormat(t *testing.T) {
	p := newBinaryPKI(t)
	_, valid := binaryTrustCA(t, p)
	block, _ := pem.Decode(valid)
	withHeader := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Unexpected": "header"}, Bytes: block.Bytes})
	invalidBlock := []byte("-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n")
	for _, test := range []struct {
		name string
		pem  []byte
	}{
		{"missing", nil}, {"whitespace", []byte(" \n\t")},
		{"oversized", bytes.Repeat([]byte("x"), 64*1024+1)},
		{"too-many", bytes.Repeat(valid, 33)}, {"DER", block.Bytes},
		{"prefix", append([]byte("untrusted prefix\n"), valid...)},
		{"suffix", append(bytes.Clone(valid), []byte("trailer")...)},
		{"headers", withHeader}, {"bad-base64", invalidBlock},
		{"bad-block-before-valid", append(bytes.Clone(invalidBlock), valid...)},
		{"bad-block-after-valid", append(bytes.Clone(valid), invalidBlock...)},
		{"nested-begin", append([]byte("-----BEGIN CERTIFICATE-----\n"), valid...)},
		{"wrong-label", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: block.Bytes})},
		{"invalid-certificate", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid DER")})},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := y.NewBinary(y.BinaryConfig{Address: netip.MustParseAddrPort("127.0.0.1:9"), TLSConfig: p.binary, RootCAPEM: test.pem})
			if err == nil {
				t.Fatal("accepted invalid root PEM configuration")
			}
		})
	}
	for _, encoded := range [][]byte{valid, bytes.Repeat(valid, 32), append(append([]byte(" \n"), valid...), []byte("\n\t")...)} {
		if _, err := y.NewBinary(y.BinaryConfig{Address: netip.MustParseAddrPort("127.0.0.1:9"), TLSConfig: p.binary, RootCAPEM: encoded}); err != nil {
			t.Fatalf("valid bounded roots rejected: %v", err)
		}
	}
	// Even a valid PEM alongside an opaque pool must reject without invoking it.
	var callbacks atomic.Int32
	cert, _ := binaryTrustCA(t, p)
	pool := x509.NewCertPool()
	pool.AddCertWithConstraint(cert, func([]*x509.Certificate) error { callbacks.Add(1); return nil })
	secure := p.binary.Clone()
	secure.RootCAs = pool
	if _, err := y.NewBinary(y.BinaryConfig{Address: netip.MustParseAddrPort("127.0.0.1:9"), TLSConfig: secure, RootCAPEM: valid}); err == nil || callbacks.Load() != 0 {
		t.Fatal("opaque root pool accepted or invoked")
	}
}
