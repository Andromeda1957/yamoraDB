package yamora_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	y "github.com/Andromeda1957/yamoraDB/yamora/drivers/go"
)

type binaryPKI struct {
	binary                    *tls.Config
	rootPEM                   []byte
	root                      string
	client, server            *tls.Config
	caPath, certPath, keyPath string
}

func newBinaryPKI(t *testing.T) binaryPKI {
	t.Helper()
	p := binaryPKI{root: t.TempDir()}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "binary Go test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	p.rootPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	p.caPath = binaryWrite(t, p.root, "ca.pem", p.rootPEM)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	issue := func(name string, serial int64, usage x509.ExtKeyUsage) (tls.Certificate, string, string) {
		t.Helper()
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		encoded, err := x509.CreateCertificate(rand.Reader, template, ca, &private.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		secret, err := x509.MarshalECPrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
		certPath := binaryWrite(t, p.root, name+".pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded}))
		keyPath := binaryWrite(t, p.root, name+".key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: secret}))
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			t.Fatal(err)
		}
		return cert, certPath, keyPath
	}
	server, certPath, keyPath := issue("server", 2, x509.ExtKeyUsageServerAuth)
	client, _, _ := issue("client", 3, x509.ExtKeyUsageClientAuth)
	p.certPath, p.keyPath = certPath, keyPath
	p.client = &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{client}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	p.binary = p.client.Clone()
	p.binary.RootCAs = nil
	p.server = &tls.Config{Certificates: []tls.Certificate{server}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"yamora-binary/1"}}
	return p
}
func binaryWrite(t *testing.T, root, name string, body []byte) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func binaryDigest(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

type binaryNative struct {
	config  y.BinaryConfig
	http    y.Config
	command *exec.Cmd
}

func newBinaryNative(t *testing.T, legacy, mtls bool, extra ...string) binaryNative {
	t.Helper()
	executable := os.Getenv("YAMORA_TEST_BINARY")
	if executable == "" {
		t.Fatal("YAMORA_TEST_BINARY is mandatory for binary daemon qualification (no skip)")
	}
	if !filepath.IsAbs(executable) {
		t.Fatal("absolute immutable daemon path required")
	}
	before := binaryDigest(t, executable)
	t.Cleanup(func() {
		if after := binaryDigest(t, executable); after != before {
			t.Errorf("immutable daemon digest changed: %s -> %s", before, after)
		}
	})
	p := newBinaryPKI(t)
	data := filepath.Join(p.root, "data")
	if err := os.Mkdir(data, 0700); err != nil {
		t.Fatal(err)
	}
	environment := append(os.Environ(), "ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1", "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	initialize := exec.CommandContext(ctx, executable, "--data-dir", data, "--init-disk", "--validate-only")
	initialize.Env = environment
	output, err := initialize.CombinedOutput()
	cancel()
	if err != nil || bytes.Contains(output, []byte("Sanitizer")) || bytes.Contains(output, []byte("runtime error:")) {
		t.Fatalf("native initialize failed: %v %s", err, output)
	}
	if legacy {
		path := filepath.Join(data, ".yamora-disk")
		image, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(image) < 8192 {
			t.Fatal("missing native superblocks")
		}
		for _, offset := range []int{0, 4096} {
			copy(image[offset:offset+8], "YAMDIS04")
			binary.LittleEndian.PutUint32(image[offset+4092:offset+4096], crc32.Checksum(image[offset:offset+4092], crc32.MakeTable(crc32.Castagnoli)))
		}
		if err := os.WriteFile(path, image, 0600); err != nil {
			t.Fatal(err)
		}
	}
	read := binaryWrite(t, p.root, "read", []byte(strings.Repeat("r", 32)))
	write := binaryWrite(t, p.root, "write", []byte(strings.Repeat("w", 32)))
	scoped := binaryWrite(t, p.root, "scoped", []byte(strings.Repeat("s", 32)))
	policy := binaryWrite(t, p.root, "policy.json", []byte(fmt.Sprintf(`{"version":1,"roles":{"one":{"read":["allowed"],"write":["allowed"]}},"principals":{"one":{"token_file":%q,"roles":["one"]}}}`, scoped)))
	args := []string{"--data-dir", data, "--port", "0", "--binary-port", "0", "--workers", "2", "--auth-token-file", read, "--write-auth-token-file", write, "--access-policy-file", policy, "--tls-cert-file", p.certPath, "--tls-key-file", p.keyPath, "--io-timeout-ms", "10000", "--cache-bytes", "1048576"}
	if mtls {
		args = append(args, "--tls-client-ca-file", p.caPath)
	}
	cmd := exec.Command(executable, append(args, extra...)...)
	cmd.Env = environment
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(p.root, "daemon.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = log
	if err = cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("native shutdown: %v", err)
			}
		case <-time.After(15 * time.Second):
			cmd.Process.Kill()
			<-done
			t.Error("native shutdown deadline")
		}
		log.Close()
		payload, err := os.ReadFile(log.Name())
		if err != nil {
			t.Error(err)
		}
		if bytes.Contains(payload, []byte("Sanitizer")) || bytes.Contains(payload, []byte("runtime error:")) {
			t.Errorf("fatal native sanitizer: %s", payload)
		}
	})
	lines := make(chan []string, 1)
	go func() {
		reader := bufio.NewReader(stdout)
		var out []string
		for i := 0; i < 2; i++ {
			line, err := reader.ReadString('\n')
			if len(line) > 8192 || err != nil {
				break
			}
			out = append(out, line)
		}
		lines <- out
	}()
	var banners []string
	select {
	case banners = <-lines:
	case <-time.After(10 * time.Second):
		t.Fatal("native startup deadline")
	}
	if len(banners) != 2 {
		payload, _ := os.ReadFile(log.Name())
		t.Fatalf("binary listener missing: %q %s", banners, payload)
	}
	getAddr := func(prefix, line string) netip.AddrPort {
		t.Helper()
		m := regexp.MustCompile("^" + prefix + ` listening on (127\.0\.0\.1:[0-9]+)`).FindStringSubmatch(line)
		if len(m) != 2 {
			t.Fatalf("missing %s readiness: %q", prefix, line)
		}
		return netip.MustParseAddrPort(m[1])
	}
	return binaryNative{config: y.BinaryConfig{Address: getAddr("binary", banners[1]), TLSConfig: p.binary, RootCAPEM: p.rootPEM, ReadToken: strings.Repeat("r", 32), WriteToken: strings.Repeat("w", 32), Timeout: 30 * time.Second, MaxFrameBytes: 4096}, http: y.Config{Address: getAddr("yamora", banners[0]), TLSConfig: p.client, ReadToken: strings.Repeat("r", 32), WriteToken: strings.Repeat("w", 32), Timeout: 30 * time.Second}, command: cmd}
}

// The fixture codec is independent of the driver and deliberately permits invalid
// frames. Literal goldens below anchor the wire bytes instead of round trips.
type binaryTestFrame struct {
	kind   byte
	stream uint32
	body   []byte
}

func binaryTestRead(c net.Conn) (binaryTestFrame, error) {
	var h [16]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return binaryTestFrame{}, err
	}
	if string(h[:4]) != "YMBF" || h[4] != 1 || h[6] != 0 || h[7] != 0 {
		return binaryTestFrame{}, errors.New("client sent malformed header")
	}
	n := binary.BigEndian.Uint32(h[12:])
	if n > 65536 {
		return binaryTestFrame{}, errors.New("client sent oversized frame")
	}
	f := binaryTestFrame{kind: h[5], stream: binary.BigEndian.Uint32(h[8:12]), body: make([]byte, n)}
	_, err := io.ReadFull(c, f.body)
	return f, err
}
func binaryTestFrameBytes(kind byte, stream uint32, body []byte) []byte {
	h := []byte{'Y', 'M', 'B', 'F', 1, kind, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(h[8:12], stream)
	binary.BigEndian.PutUint32(h[12:], uint32(len(body)))
	return append(h, body...)
}
func binaryTestSend(c net.Conn, kind byte, body []byte) error {
	stream := uint32(1)
	if kind == 1 || kind >= 8 {
		stream = 0
	}
	_, err := c.Write(binaryTestFrameBytes(kind, stream, body))
	return err
}
func binaryTestFields(payload []byte) (map[int][]byte, error) {
	if len(payload) < 4 {
		return nil, errors.New("short request")
	}
	count := int(binary.BigEndian.Uint16(payload[2:4]))
	result := map[int][]byte{}
	payload = payload[4:]
	for i := 0; i < count; i++ {
		if len(payload) < 4 {
			return nil, errors.New("short field")
		}
		id, n := int(binary.BigEndian.Uint16(payload[:2])), int(binary.BigEndian.Uint16(payload[2:4]))
		payload = payload[4:]
		if n > len(payload) {
			return nil, io.ErrUnexpectedEOF
		}
		result[id] = payload[:n]
		payload = payload[n:]
	}
	if len(payload) != 0 {
		return nil, errors.New("trailing request")
	}
	return result, nil
}
func binaryTestRequest(c net.Conn) (map[int][]byte, []byte, error) {
	first, err := binaryTestRead(c)
	if err != nil {
		return nil, nil, err
	}
	if first.kind != 2 || first.stream != 1 {
		return nil, nil, errors.New("missing request")
	}
	fields, err := binaryTestFields(first.body)
	if err != nil {
		return nil, nil, err
	}
	var source []byte
	for {
		f, err := binaryTestRead(c)
		if err != nil {
			return nil, nil, err
		}
		if f.kind == 5 {
			return fields, source, nil
		}
		if f.kind != 4 || f.stream != 1 || len(source)+len(f.body) > y.MaxDocumentBytes {
			return nil, nil, errors.New("bad input DATA")
		}
		source = append(source, f.body...)
	}
}
func binaryTestHello(c net.Conn) error {
	f, err := binaryTestRead(c)
	if err != nil {
		return err
	}
	if f.kind != 1 || f.stream != 0 {
		return errors.New("missing hello")
	}
	return binaryTestSend(c, 1, []byte{0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1})
}
func binaryTestMeta(fields map[int][]byte) []byte {
	out := []byte{0, 1, 0, 0}
	count := 0
	for id := 1; id <= 13; id++ {
		value, ok := fields[id]
		if !ok {
			continue
		}
		out = binary.BigEndian.AppendUint16(out, uint16(id))
		out = binary.BigEndian.AppendUint16(out, uint16(len(value)))
		out = append(out, value...)
		count++
	}
	binary.BigEndian.PutUint16(out[2:], uint16(count))
	return out
}
func binaryTestResponse(status int, body []byte, id []byte) map[int][]byte {
	fields := map[int][]byte{1: binary.BigEndian.AppendUint16(nil, uint16(status)), 2: []byte("application/json"), 3: binary.BigEndian.AppendUint64(nil, uint64(len(body))), 4: binary.BigEndian.AppendUint64(nil, uint64(len(body))), 5: []byte("0123456789abcdef")}
	if id != nil {
		fields[12] = bytes.Clone(id)
	}
	if status == 200 || status == 201 {
		fields[6] = []byte(`"fedcba9876543210"`)
	}
	return fields
}

const binaryGoodReceipt = `{"status":"stored","collection":"config","document":"one","etag":"fedcba9876543210","revision":"0123456789abcdef"}`

func binaryTestReply(c net.Conn, status int, body []byte, id []byte) error {
	if err := binaryTestSend(c, 3, binaryTestMeta(binaryTestResponse(status, body, id))); err != nil {
		return err
	}
	if len(body) > 0 {
		if err := binaryTestSend(c, 4, body); err != nil {
			return err
		}
	}
	return binaryTestSend(c, 5, nil)
}
func binaryPeer(t *testing.T, secure *tls.Config, script func(net.Conn) error) y.BinaryConfig {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	var extra atomic.Int32
	replayJoined := make(chan struct{})
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			done <- err
			close(replayJoined)
			return
		}
		go func() {
			defer close(replayJoined)
			again, err := listener.Accept()
			if err == nil {
				extra.Add(1)
				again.Close()
			}
		}()
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(5 * time.Second))
		conn := tls.Server(raw, secure)
		if err = conn.Handshake(); err == nil {
			err = script(conn)
		}
		done <- err
	}()
	t.Cleanup(func() {
		listener.Close()
		<-replayJoined
		if extra.Load() != 0 {
			t.Error("driver automatically replayed a request onto another connection")
		}
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("verified peer fixture: %v", err)
			}
		case <-time.After(6 * time.Second):
			t.Error("peer did not join")
		}
	})
	return y.BinaryConfig{Address: netip.MustParseAddrPort(listener.Addr().String()), Timeout: 2 * time.Second}
}
func binaryClient(t *testing.T, c y.BinaryConfig) *y.BinaryClient {
	t.Helper()
	client, err := y.NewBinary(c)
	if err != nil {
		t.Fatal(err)
	}
	return client
}
func binaryStatus(t *testing.T, err error, status int) {
	t.Helper()
	var remote *y.HTTPError
	if !errors.As(err, &remote) || remote.Status != status {
		t.Fatalf("expected status %d, got %v", status, err)
	}
}
func binaryUncertain(t *testing.T, err error, id string) *y.BinaryUncertainWriteError {
	t.Helper()
	var uncertain *y.BinaryUncertainWriteError
	if !errors.As(err, &uncertain) || (id != "" && uncertain.RequestID != id) || len(uncertain.RequestID) != 32 || uncertain.RequestID == strings.Repeat("0", 32) {
		t.Fatalf("expected original typed uncertainty, got %v", err)
	}
	return uncertain
}
