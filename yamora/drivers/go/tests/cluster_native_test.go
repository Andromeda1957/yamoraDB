package yamora_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	y "github.com/Andromeda1957/yamoraDB/yamora/drivers/go"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type nativeCluster struct {
	root, binary string
	secure       *tls.Config
	arguments    [][]string
	seeds        []netip.AddrPort
	processes    []*exec.Cmd
	finished     []chan error
	logs         []*os.File
	mu           sync.Mutex
}

func newNativeCluster(t *testing.T) *nativeCluster {
	t.Helper()
	binary := os.Getenv("YAMORA_TEST_BINARY")
	if binary == "" {
		t.Skip("set YAMORA_TEST_BINARY for the native replica-set contract")
	}
	cluster := &nativeCluster{root: t.TempDir(), binary: binary, processes: make([]*exec.Cmd, 3), finished: make([]chan error, 3), logs: make([]*os.File, 3)}
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(cluster.root, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Go cluster test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPath := write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	cluster.secure = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	var certificates, keys []string
	for i := 0; i < 3; i++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("node%d.test", i+1)
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		private, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		certificates = append(certificates, write(fmt.Sprintf("node%d.pem", i), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
		keys = append(keys, write(fmt.Sprintf("node%d.key", i), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private})))
	}
	read := write("read.token", []byte(strings.Repeat("r", 32)))
	writable := write("write.token", []byte(strings.Repeat("w", 32)))
	var reservations []net.Listener
	var peers []map[string]any
	defer func() {
		for _, listener := range reservations {
			listener.Close()
		}
	}()
	for i := 0; i < 3; i++ {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		reservations = append(reservations, listener)
		peers = append(peers, map[string]any{"id": i + 1, "name": fmt.Sprintf("node%d.test", i+1), "address": "127.0.0.1", "port": listener.Addr().(*net.TCPAddr).Port})
	}
	for i := 0; i < 3; i++ {
		data := filepath.Join(cluster.root, fmt.Sprintf("data%d", i))
		journal := filepath.Join(cluster.root, fmt.Sprintf("journal%d", i))
		for _, directory := range []string{data, journal} {
			if err := os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
		}
		config := map[string]any{"cluster": "01020304000000000000000000000000", "node": i + 1, "journal_dir": journal, "peer_tls": map[string]string{"cert_file": certificates[i], "key_file": keys[i], "ca_file": caPath}, "peers": peers, "request_timeout_ms": 3000, "journal_cache_bytes": 1048576}
		encoded, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		path := write(fmt.Sprintf("config%d.json", i), encoded)
		cluster.arguments = append(cluster.arguments, []string{"--data-dir", data, "--port", "0", "--workers", "4", "--cluster-config-file", path, "--auth-token-file", read, "--write-auth-token-file", writable, "--cache-bytes", "1048576", "--tls-cert-file", certificates[i], "--tls-key-file", keys[i], "--io-timeout-ms", "3000"})
	}
	t.Cleanup(func() {
		for i := 0; i < 3; i++ {
			if err := cluster.stop(i, false); err != nil {
				t.Error(err)
			}
		}
		for i, log := range cluster.logs {
			if log != nil {
				log.Close()
			}
			payload, _ := os.ReadFile(filepath.Join(cluster.root, fmt.Sprintf("node%d.log", i)))
			if bytes.Contains(payload, []byte("ERROR: AddressSanitizer")) || bytes.Contains(payload, []byte("runtime error:")) || bytes.Contains(payload, []byte("LeakSanitizer:")) {
				t.Errorf("native sanitizer report: %s", payload)
			}
		}
	})
	for _, listener := range reservations {
		listener.Close()
	}
	for i := 0; i < 3; i++ {
		cluster.start(t, i)
	}
	return cluster
}
func (cluster *nativeCluster) start(t *testing.T, node int) {
	t.Helper()
	command := exec.Command(cluster.binary, cluster.arguments[node]...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(cluster.root, fmt.Sprintf("node%d.log", node)), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = log
	if err := command.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	cluster.processes[node], cluster.logs[node] = command, log
	cluster.finished[node] = make(chan error, 1)
	go func() { cluster.finished[node] <- command.Wait() }()
	banner := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); banner <- line }()
	select {
	case line := <-banner:
		match := regexp.MustCompile(`^yamora listening on (127\.0\.0\.1:[0-9]+) `).FindStringSubmatch(line)
		if match == nil {
			payload, _ := os.ReadFile(log.Name())
			t.Fatalf("invalid cluster banner %q: %s", line, payload)
		}
		cluster.seeds = append(cluster.seeds, netip.MustParseAddrPort(match[1]))
	case <-time.After(10 * time.Second):
		t.Fatal("native cluster startup deadline")
	}
}
func (cluster *nativeCluster) stop(node int, crash bool) error {
	cluster.mu.Lock()
	defer cluster.mu.Unlock()
	process := cluster.processes[node]
	if process == nil {
		return nil
	}
	if crash {
		process.Process.Kill()
	} else {
		process.Process.Signal(syscall.SIGTERM)
	}
	select {
	case err := <-cluster.finished[node]:
		cluster.processes[node] = nil
		if !crash && err != nil {
			return fmt.Errorf("native member %d: %w", node, err)
		}
		return nil
	case <-time.After(10 * time.Second):
		process.Process.Kill()
		<-cluster.finished[node]
		cluster.processes[node] = nil
		return fmt.Errorf("native member %d did not stop", node)
	}
}
func (cluster *nativeCluster) config() y.Config {
	return y.Config{Seeds: cluster.seeds, TLSConfig: cluster.secure, ReadToken: strings.Repeat("r", 32), WriteToken: strings.Repeat("w", 32), Timeout: 5 * time.Second, RetryTimeout: 20 * time.Second}
}
func (cluster *nativeCluster) leader() (int, error) {
	client := &http.Client{Timeout: 300 * time.Millisecond, Transport: &http.Transport{Proxy: nil, TLSClientConfig: cluster.secure, DisableKeepAlives: true}}
	defer client.CloseIdleConnections()
	for i, seed := range cluster.seeds {
		request, _ := http.NewRequest("GET", "https://"+seed.String()+"/v1/cluster/leader", nil)
		request.Header.Set("Authorization", "Bearer "+strings.Repeat("r", 32))
		response, err := client.Do(request)
		if err != nil {
			continue
		}
		var status struct {
			Role string `json:"role"`
		}
		err = json.NewDecoder(io.LimitReader(response.Body, 512)).Decode(&status)
		response.Body.Close()
		if err == nil && response.StatusCode == 200 && status.Role == "leader" {
			return i, nil
		}
	}
	return -1, fmt.Errorf("leader unavailable")
}
func identity(t *testing.T, n int) context.Context {
	t.Helper()
	ctx, err := y.WithRequestID(context.Background(), fmt.Sprintf("%032x", n))
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

const clusterSource = "# exact source\r\ncount: 0 # retained\r\n"

func TestNativeClusterDriverFailoverAndPrimitiveReceipts(t *testing.T) {
	cluster := newNativeCluster(t)
	client := routedClient(t, cluster.config())
	if _, err := client.Put(identity(t, 1), "manifests", "counter", []byte(clusterSource), y.WriteOptions{CreateOnly: true}); err != nil {
		t.Fatal(err)
	}
	original, err := client.Patch(identity(t, 2), "manifests", "counter", map[string]any{"$inc": map[string]any{"count": 1}}, "")
	if err != nil {
		t.Fatal(err)
	}
	first, err := cluster.leader()
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := client.Changes(context.Background(), "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if err := cluster.stop(first, true); err != nil {
		t.Fatal(err)
	}
	replay, err := client.Patch(identity(t, 2), "manifests", "counter", map[string]any{"$inc": map[string]any{"count": 1}}, "")
	if err != nil || replay != original {
		t.Fatalf("%+v != %+v: %v cause=%v", replay, original, err, errors.Unwrap(err))
	}
	document, err := client.Get(context.Background(), "manifests", "counter", "")
	if err != nil || string(document.Source) != strings.Replace(clusterSource, "count: 0", "count: 1", 1) {
		t.Fatalf("%q %v", document.Source, err)
	}
	if _, err := client.Changes(context.Background(), checkpoint.NextAfter, 10); err != nil {
		t.Fatal(err)
	}
	operations := []y.Operation{{Collection: "manifests", Document: "counter", Patch: map[string]any{"$inc": map[string]any{"count": 1}}}}
	transaction, err := client.Transaction(identity(t, 3), operations, "")
	if err != nil {
		t.Fatal(err)
	}
	retry, err := client.Transaction(identity(t, 3), operations, "")
	if err != nil || retry != transaction {
		t.Fatalf("%+v %v", retry, err)
	}
	definitions := []y.Index{{Collection: "manifests", Name: "count", Fields: []string{"count"}}}
	catalog, err := client.SetIndexes(identity(t, 4), definitions, "")
	if err != nil {
		t.Fatal(err)
	}
	again, err := client.SetIndexes(identity(t, 4), definitions, "")
	if err != nil || again != catalog {
		t.Fatalf("%+v %v", again, err)
	}
	if err := client.Delete(identity(t, 5), "manifests", "counter", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Put(identity(t, 6), "manifests", "counter", []byte(clusterSource), y.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := client.Delete(identity(t, 5), "manifests", "counter", ""); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := client.Patch(context.Background(), "manifests", "counter", map[string]any{"$inc": map[string]any{"count": 1}}, "")
			failures <- err
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	document, err = client.Get(context.Background(), "manifests", "counter", "")
	if err != nil || string(document.Source) != strings.Replace(clusterSource, "count: 0", "count: 8", 1) {
		t.Fatalf("%q %v", document.Source, err)
	}
	leader, err := cluster.leader()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if i != leader {
			if err := cluster.stop(i, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := client.Get(ctx, "manifests", "counter", ""); err == nil {
		t.Fatal("isolated leader served a document")
	}
}

func TestNativeClusterDriverLostCommittedReplyRecoversOnce(t *testing.T) {
	cluster := newNativeCluster(t)
	admin := routedClient(t, cluster.config())
	if _, err := admin.Put(context.Background(), "manifests", "counter", []byte(clusterSource), y.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	var dropped atomic.Bool
	var identifier atomic.Value
	forward := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: cluster.secure, DisableKeepAlives: true}}
	defer forward.CloseIdleConnections()
	proxy := clusterServer(t, func(w http.ResponseWriter, r *http.Request) {
		if dropped.Load() {
			w.WriteHeader(503)
			return
		}
		target, err := cluster.leader()
		if err != nil {
			w.WriteHeader(503)
			return
		}
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(503)
			return
		}
		request, err := http.NewRequestWithContext(r.Context(), r.Method, "https://"+cluster.seeds[target].String()+r.URL.RequestURI(), bytes.NewReader(payload))
		if err != nil {
			w.WriteHeader(503)
			return
		}
		request.Header = r.Header.Clone()
		response, err := forward.Do(request)
		if err != nil {
			w.WriteHeader(503)
			return
		}
		defer response.Body.Close()
		payload, err = io.ReadAll(response.Body)
		if err != nil {
			w.WriteHeader(503)
			return
		}
		if r.Method == "PATCH" && response.StatusCode == 200 && dropped.CompareAndSwap(false, true) {
			identifier.Store(r.Header.Get("X-Yamora-Request-Id"))
			if err := cluster.stop(target, true); err != nil {
				t.Error(err)
			}
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		for key, values := range response.Header {
			w.Header()[key] = values
		}
		w.WriteHeader(response.StatusCode)
		w.Write(payload)
	})
	config := cluster.config()
	config.Seeds = append([]netip.AddrPort{netip.MustParseAddrPort(strings.TrimPrefix(proxy.URL, "https://"))}, config.Seeds...)
	config.TLSConfig = cluster.secure.Clone()
	config.TLSConfig.RootCAs = cluster.secure.RootCAs.Clone()
	config.TLSConfig.RootCAs.AddCert(proxy.Certificate())
	client := routedClient(t, config)
	if _, err := client.Patch(context.Background(), "manifests", "counter", map[string]any{"$inc": map[string]any{"count": 1}}, ""); err != nil {
		t.Fatal(err)
	}
	if !dropped.Load() || identifier.Load() == nil || identifier.Load().(string) == "" {
		t.Fatal("proxy did not drop a committed write")
	}
	document, err := client.Get(context.Background(), "manifests", "counter", "")
	if err != nil || string(document.Source) != strings.Replace(clusterSource, "count: 0", "count: 1", 1) {
		t.Fatalf("%q %v", document.Source, err)
	}
}
