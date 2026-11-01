// Package tests checks adapter controls with synthetic peers. These tests do
// not qualify native replica receipts, restart safety, or exactly-once effects.
package tests

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

var binary string

const inputRejectionDiagnostic = "HTTP replica adapter input or infrastructure failure\n"
const exitFixtureEnv = "YAMORA_HTTP_REPLICA_EXIT_FIXTURE"

var exitControls = []struct {
	mode, diagnostic string
	code             int
}{
	{"input", inputRejectionDiagnostic, 2},
	{"watchdog", "HTTP replica adapter command watchdog expired\n", 2},
	{"timeout", "infrastructure: process timeout\n", 2},
	{"signal", inputRejectionDiagnostic, -1},
	{"sanitizer", inputRejectionDiagnostic + "sanitizer: deliberate diagnostic control\n", 2},
	{"infrastructure", "infrastructure: deliberate setup diagnostic control\n", 2},
	{"wrong-code", inputRejectionDiagnostic, 1},
	{"silent", "", 2},
}

// Deliberately emit process results without a watchdog, timeout, sanitizer or
// broken setup. The oracle must distinguish these from ordinary input rejection.
func exitFixture(mode string) {
	for _, control := range exitControls {
		if control.mode != mode {
			continue
		}
		fmt.Fprint(os.Stderr, control.diagnostic)
		if control.code == -1 {
			syscall.Kill(os.Getpid(), syscall.SIGKILL)
			os.Exit(99)
		}
		os.Exit(control.code)
	}
	os.Exit(99)
}

func TestMain(m *testing.M) {
	if mode := os.Getenv(exitFixtureEnv); mode != "" {
		exitFixture(mode)
	}
	root, err := os.MkdirTemp(os.Getenv("TMPDIR"), "go-http-adapter-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	binary = filepath.Join(root, "http-replica")
	build := exec.Command("go", "build", "-o", binary, "..")
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err = build.Run(); err != nil {
		os.RemoveAll(root)
		os.Exit(2)
	}
	code := m.Run()
	if err := os.RemoveAll(root); err != nil {
		code = 2
	}
	os.Exit(code)
}

type hit struct{ method, path, id, match, none, body string }
type fixture struct {
	root   string
	config map[string]any
	mu     sync.Mutex
	status int
	hits   []hit
}

func write(t *testing.T, name string, body []byte) {
	t.Helper()
	if err := os.WriteFile(name, body, 0600); err != nil {
		t.Fatal(err)
	}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root, err := os.MkdirTemp(os.Getenv("TMPDIR"), "http-controls-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	f := &fixture{root: root, status: 409}
	if err := os.Mkdir(filepath.Join(root, "input"), 0700); err != nil {
		t.Fatal(err)
	}
	for seq := 1; seq <= 64; seq++ {
		if err := os.Mkdir(filepath.Join(root, fmt.Sprintf("call-%06d", seq)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(root, "input/value-a.bin"), []byte("# exact\r\nn: 0 # keep\r\n"))
	seeds := []any{}
	for node := 1; node <= 3; node++ {
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(io.LimitReader(r.Body, 131073))
			if err != nil {
				return
			}
			f.mu.Lock()
			f.hits = append(f.hits, hit{r.Method, r.URL.Path, r.Header.Get("X-Yamora-Request-Id"), r.Header.Get("If-Match"), r.Header.Get("If-None-Match"), string(body)})
			status := f.status
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/v1/cluster/leader" {
				io.WriteString(w, `{"node":1,"leader":1,"term":1,"role":"leader"}`)
				return
			}
			if status == 0 {
				connection, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					connection.Close()
				}
				return
			}
			if status == 200 { // Exposure control, never native qualification.
				w.Header().Set("X-YamlDB-Revision", "1111111111111111")
				if r.Method == "GET" {
					w.Header().Set("Content-Type", "application/yaml")
					w.Header().Set("ETag", `"0123456789abcdef"`)
					io.WriteString(w, "# exact\r\nn: 9 # keep\r\n")
					return
				}
				if r.Method == "DELETE" {
					w.WriteHeader(204)
					return
				}
				io.WriteString(w, `{"status":"stored","etag":"0123456789abcdef","revision":"1111111111111111"}`)
				return
			}
			w.WriteHeader(status)
			io.WriteString(w, `{"error":"private peer text"}`)
		}))
		server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
		server.StartTLS()
		t.Cleanup(server.Close)
		// All httptest peers share this fixture identity. It is trusted explicitly,
		// never via the machine's trust store or verification bypasses.
		if node == 1 {
			identity := server.TLS.Certificates[0]
			cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: identity.Certificate[0]})
			key, err := x509.MarshalPKCS8PrivateKey(identity.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			write(t, filepath.Join(root, "ca.pem"), cert)
			write(t, filepath.Join(root, "client.pem"), cert)
			write(t, filepath.Join(root, "client.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
		}
		address := strings.TrimPrefix(server.URL, "https://127.0.0.1:")
		var portNumber int
		if _, err := fmt.Sscanf(address, "%d", &portNumber); err != nil {
			t.Fatal(err)
		}
		seeds = append(seeds, map[string]any{"host": "127.0.0.1", "port": portNumber, "node": node})
	}
	for _, name := range []string{"read.token", "write.token"} {
		write(t, filepath.Join(root, name), []byte("synthetic-private-token-0123456789ab"))
	}
	f.config = map[string]any{"schema": "yamora-http-replica-config/2", "cluster_id": strings.Repeat("1", 32), "voters": 3, "seeds": seeds, "tls": map[string]any{"ca_file": "ca.pem", "cert_file": "client.pem", "key_file": "client.key"}, "tokens": map[string]any{"read_file": "read.token", "write_file": "write.token"}, "timeout_ms": 15000, "attempt_timeout_ms": 3000}
	return f
}

func (f *fixture) setStatus(status int) { f.mu.Lock(); defer f.mu.Unlock(); f.status = status }
func (f *fixture) mutations() []hit {
	f.mu.Lock()
	defer f.mu.Unlock()
	var hits []hit
	for _, h := range f.hits {
		if h.path != "/v1/cluster/leader" {
			hits = append(hits, h)
		}
	}
	return hits
}
func (f *fixture) save(t *testing.T) {
	t.Helper()
	data, err := json.Marshal(f.config)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(f.root, "config.json"), data)
}
func call(seq int, method string) map[string]any {
	var source any
	if method == "PUT" || method == "PATCH" {
		source = "input/value-a.bin"
	}
	return map[string]any{"schema": "yamora-http-replica-command/2", "seq": seq, "action": "call", "method": method, "collection": "manifests", "document": "counter", "source_file": source, "request_id": nil, "if_match": nil, "if_none_match": nil}
}
func control(seq int, action string) map[string]any {
	return map[string]any{"schema": "yamora-http-replica-command/2", "seq": seq, "action": action}
}

type process struct {
	cmd         *exec.Cmd
	in          io.WriteCloser
	out         *bufio.Reader
	errorOutput bytes.Buffer
	done        bool
}

func (f *fixture) launch(t *testing.T) *process {
	t.Helper()
	f.save(t)
	p := &process{cmd: exec.Command(binary, "--config", filepath.Join(f.root, "config.json"), "--root", f.root)}
	p.cmd.Dir = f.root
	var err error
	p.in, err = p.cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	p.out = bufio.NewReader(out)
	p.cmd.Stderr = &p.errorOutput
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		p.in.Close()
		if !p.done {
			p.cmd.Process.Kill()
			p.cmd.Wait()
		}
	})
	return p
}
func (p *process) exchange(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.in.Write(append(data, '\n')); err != nil {
		t.Fatal(err)
	}
	type response struct {
		line []byte
		err  error
	}
	done := make(chan response, 1)
	go func() { line, err := p.out.ReadBytes('\n'); done <- response{line, err} }()
	select {
	case result := <-done:
		if result.err != nil {
			t.Fatalf("missing observation: %v", result.err)
		}
		if len(result.line) > 16384 {
			t.Fatal("oversized observation")
		}
		var observation map[string]any
		if err := json.Unmarshal(result.line, &observation); err != nil {
			t.Fatal(err)
		}
		return observation
	case <-time.After(24 * time.Second):
		p.cmd.Process.Kill()
		p.cmd.Wait()
		p.done = true
		<-done
		t.Fatal("infrastructure: observation watchdog")
		return nil
	}
}
func normalInputRejection(err error, diagnostic string) bool {
	var exited *exec.ExitError
	return errors.As(err, &exited) && exited.ExitCode() == 2 && diagnostic == inputRejectionDiagnostic
}

func (p *process) wait(t *testing.T, wantSuccess bool) {
	t.Helper()
	finished := make(chan error, 1)
	go func() { finished <- p.cmd.Wait() }()
	var err error
	select {
	case err = <-finished:
	case <-time.After(3 * time.Second):
		p.cmd.Process.Kill()
		<-finished
		p.done = true
		t.Fatal("infrastructure: process exit timeout")
	}
	p.done = true
	if wantSuccess {
		if err != nil || p.errorOutput.Len() != 0 {
			t.Fatalf("infrastructure: expected clean success: exit=%v diagnostic=%q", err, p.errorOutput.String())
		}
	} else if !normalInputRejection(err, p.errorOutput.String()) {
		t.Fatalf("infrastructure: expected normal input rejection (exit 2, exact diagnostic): exit=%v diagnostic=%q", err, p.errorOutput.String())
	}
}

func TestInputRejectionOracle(t *testing.T) {
	for _, control := range exitControls {
		t.Run(control.mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0])
			child.Env = append(os.Environ(), exitFixtureEnv+"="+control.mode)
			var diagnostic bytes.Buffer
			child.Stderr = &diagnostic
			err := child.Run()
			if ctx.Err() != nil || child.ProcessState == nil {
				t.Fatalf("infrastructure: process-result control did not complete: %v", err)
			}
			if child.ProcessState.ExitCode() != control.code || diagnostic.String() != control.diagnostic {
				t.Fatalf("infrastructure: process-result control differed: exit=%v diagnostic=%q", err, diagnostic.String())
			}
			if control.code == -1 {
				status, ok := child.ProcessState.Sys().(syscall.WaitStatus)
				if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
					t.Fatal("infrastructure: deliberate signal control did not receive SIGKILL")
				}
			}
			if got, want := normalInputRejection(err, diagnostic.String()), control.mode == "input"; got != want {
				t.Fatalf("normal input rejection=%v, want %v: exit=%v diagnostic=%q", got, want, err, diagnostic.String())
			}
		})
	}
}
func api(t *testing.T, r map[string]any) map[string]any {
	t.Helper()
	a, ok := r["api"].(map[string]any)
	if !ok || len(a) != 5 {
		t.Fatal("invalid api shape")
	}
	return a
}

func TestStatusSessionAndPreconditions(t *testing.T) {
	f := newFixture(t)
	p := f.launch(t)
	for i, condition := range []string{"none", "match", "create"} {
		c := call(i+1, "PUT")
		c["request_id"] = strings.Repeat("a", 32)
		if condition == "match" {
			c["if_match"] = `"0123456789abcdef"`
		}
		if condition == "create" {
			c["if_none_match"] = "*"
		}
		r := p.exchange(t, c)
		if r["outcome"] != "status" || api(t, r)["status"] != float64(409) {
			t.Fatal(r)
		}
		for _, key := range []string{"sdk_request_id", "envelope", "recovery_handle", "recovery_mode"} {
			if r[key] != nil {
				t.Fatalf("invented %s", key)
			}
		}
	}
	hits := f.mutations()
	if len(hits) != 3 {
		t.Fatal(hits)
	}
	for _, h := range hits {
		if h.body != "# exact\r\nn: 0 # keep\r\n" || h.id != strings.Repeat("a", 32) {
			t.Fatal(h)
		}
	}
	if hits[0].match != "" || hits[0].none != "" || hits[1].match != `"0123456789abcdef"` || hits[2].none != "*" {
		t.Fatal(hits)
	}
	if p.exchange(t, control(4, "close"))["outcome"] != "closed" {
		t.Fatal("close")
	}
	p.wait(t, true)
}

func TestRealUncertaintyReissuesImmutablePrimitiveWithExceptionID(t *testing.T) {
	f := newFixture(t)
	f.setStatus(0)
	p := f.launch(t)
	write(t, filepath.Join(f.root, "input/value-a.bin"), []byte(`{ "$inc" : {"n":1} }`))
	c := call(1, "PATCH")
	c["if_match"] = `"0123456789abcdef"`
	r := p.exchange(t, c)
	id, ok := r["sdk_request_id"].(string)
	if r["outcome"] != "uncertain" || api(t, r)["status"] != nil || !ok || len(id) != 32 || r["recovery_handle"] != "h1" || r["recovery_mode"] != "caller-reissue" || r["envelope"] != nil {
		t.Fatal(r)
	}
	hits := f.mutations()
	if len(hits) < 2 {
		t.Fatal("SDK retries disabled", hits)
	}
	for _, h := range hits {
		if h.id != id || h.body != hits[0].body || h.match != `"0123456789abcdef"` {
			t.Fatal(h)
		}
	}
	if hits[0].body != `{"$inc":{"n":1}}` {
		t.Fatal(hits[0])
	}
	if err := os.Remove(filepath.Join(f.root, "input/value-a.bin")); err != nil {
		t.Fatal(err)
	}
	f.setStatus(409)
	recover := control(2, "recover")
	recover["handle"] = "h1"
	r = p.exchange(t, recover)
	if r["outcome"] != "status" || api(t, r)["status"] != float64(409) || r["sdk_request_id"] != nil || r["recovery_handle"] != "h1" {
		t.Fatal(r)
	}
	hits = f.mutations()
	last := hits[len(hits)-1]
	if last.id != id || last.body != hits[0].body || last.match != hits[0].match {
		t.Fatal(last)
	}
	p.exchange(t, control(3, "close"))
	p.wait(t, true)
}

func TestPublicExposureControls(t *testing.T) {
	f := newFixture(t)
	f.setStatus(200)
	p := f.launch(t)
	r := p.exchange(t, call(1, "PUT"))
	a := api(t, r)
	if r["outcome"] != "success" || a["status"] != nil || a["body_file"] != nil || a["etag"] != "0123456789abcdef" || a["revision"] != "1111111111111111" || r["sdk_request_id"] != nil {
		t.Fatal(r)
	}
	receipt := a["receipt"].(map[string]any)
	if len(receipt) != 3 || receipt["status"] != "stored" {
		t.Fatal(receipt)
	}
	r = p.exchange(t, call(2, "DELETE"))
	for _, v := range api(t, r) {
		if v != nil {
			t.Fatal("DELETE invented metadata", r)
		}
	}
	r = p.exchange(t, call(3, "GET"))
	a = api(t, r)
	data, err := os.ReadFile(filepath.Join(f.root, "call-000003/body.bin"))
	if err != nil || string(data) != "# exact\r\nn: 9 # keep\r\n" || a["body_file"] != "call-000003/body.bin" || a["etag"] != "0123456789abcdef" {
		t.Fatal(r, err)
	}
	r = p.exchange(t, control(4, "close"))
	if r["elapsed_ns"] != float64(0) || r["error_kind"] != nil {
		t.Fatal(r)
	}
	p.wait(t, true)
}

func TestInputAndConfigRejectionsBeforeDispatch(t *testing.T) {
	f := newFixture(t)
	for _, change := range []map[string]any{{"method": "HEAD"}, {"seq": true}, {"unknown": 1}, {"source_file": "../escape.bin"}, {"request_id": strings.Repeat("0", 32)}, {"if_match": "0123456789abcdef"}, {"if_none_match": "*", "if_match": `"0123456789abcdef"`}, {"collection": "yamldb-system"}} {
		c := call(1, "PUT")
		for k, v := range change {
			c[k] = v
		}
		p := f.launch(t)
		data, _ := json.Marshal(c)
		p.in.Write(append(data, '\n'))
		p.in.Close()
		p.wait(t, false)
	}
	for _, data := range []string{"", `{"seq":1`, "x" + strings.Repeat(" ", 16384) + "\n", `{"seq":1,"seq":1}` + "\n", `{"n":NaN}` + "\n", `{"n":1e999}` + "\n", strings.Repeat("[", 13) + "0" + strings.Repeat("]", 13) + "\n"} {
		p := f.launch(t)
		p.in.Write([]byte(data))
		p.in.Close()
		p.wait(t, false)
	}
	valid, _ := json.Marshal(call(1, "PUT"))
	duplicate := strings.Replace(string(valid), `"seq":1`, `"seq":1,"seq":1`, 1)
	p := f.launch(t)
	p.in.Write(append([]byte(duplicate), '\n'))
	p.in.Close()
	p.wait(t, false)
	for key, value := range map[string]any{"voters": true, "timeout_ms": 15001, "attempt_timeout_ms": 0, "cluster_id": strings.Repeat("0", 32)} {
		original := f.config[key]
		f.config[key] = value
		p := f.launch(t)
		data, _ := json.Marshal(control(1, "close"))
		p.in.Write(append(data, '\n'))
		p.in.Close()
		p.wait(t, false)
		f.config[key] = original
	}
	if len(f.mutations()) != 0 {
		t.Fatal("invalid input dispatched")
	}
}

func TestSourceAndSymlinkGuards(t *testing.T) {
	f := newFixture(t)
	name := filepath.Join(f.root, "input/value-a.bin")
	for _, body := range []string{`{"$inc":{"n":true}}`, `{"$inc":{"n":1.0}}`, `{"$inc":{"n":1,"n":1}}`, `{"$inc":{"n":2}}`, strings.Repeat("x", 131073), "\xff"} {
		write(t, name, []byte(body))
		p := f.launch(t)
		data, _ := json.Marshal(call(1, "PATCH"))
		p.in.Write(append(data, '\n'))
		p.in.Close()
		p.wait(t, false)
	}
	os.Remove(name)
	if err := os.Symlink(filepath.Join(f.root, "read.token"), name); err != nil {
		t.Fatal(err)
	}
	p := f.launch(t)
	data, _ := json.Marshal(call(1, "PUT"))
	p.in.Write(append(data, '\n'))
	p.in.Close()
	p.wait(t, false)
	os.Remove(name)
	if err := syscall.Mkfifo(name, 0600); err != nil {
		t.Fatal(err)
	}
	p = f.launch(t)
	p.in.Write(append(data, '\n'))
	p.in.Close()
	p.wait(t, false)
	os.Remove(name)
	write(t, name, []byte("n: 0\n"))
	out := filepath.Join(f.root, "call-000001")
	os.Remove(out)
	os.Symlink(filepath.Join(f.root, "input"), out)
	p = f.launch(t)
	p.in.Write(append(data, '\n'))
	p.in.Close()
	p.wait(t, false)
	if len(f.mutations()) != 0 {
		t.Fatal("unsafe source/output dispatched")
	}
}

func TestUnknownRecoverySequence(t *testing.T) {
	f := newFixture(t)
	unknown := control(1, "recover")
	unknown["handle"] = "h1"
	for _, c := range []map[string]any{unknown, control(2, "close"), control(65, "close")} {
		p := f.launch(t)
		data, _ := json.Marshal(c)
		p.in.Write(append(data, '\n'))
		p.in.Close()
		p.wait(t, false)
	}
	if len(f.mutations()) != 0 {
		t.Fatal("invalid recovery dispatched")
	}
}

func TestIntentionalSignalInterruptsPartialInput(t *testing.T) {
	f := newFixture(t)
	p := f.launch(t)
	// Observe a handled SDK rejection first so the adapter's signal handler is
	// installed before deliberately interrupting the next, incomplete command.
	if r := p.exchange(t, call(1, "PUT")); r["outcome"] != "status" || api(t, r)["status"] != float64(409) {
		t.Fatal(r)
	}
	if _, err := p.in.Write([]byte(`{"schema":`)); err != nil {
		t.Fatal(err)
	}
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	p.wait(t, false)
	if len(f.mutations()) != 1 {
		t.Fatal("incomplete input dispatched")
	}
}

func TestSessionLimitsAndRetainedHandles(t *testing.T) {
	f := newFixture(t)
	f.setStatus(500) // A public uncertainty with a definitive typed cause, no timer.
	p := f.launch(t)
	for seq := 1; seq <= 16; seq++ {
		r := p.exchange(t, call(seq, "PUT"))
		if r["outcome"] != "uncertain" || r["recovery_handle"] != fmt.Sprintf("h%d", seq) {
			t.Fatal(r)
		}
	}
	f.setStatus(409)
	for seq := 17; seq <= 63; seq++ {
		c := control(seq, "recover")
		c["handle"] = "h1"
		r := p.exchange(t, c)
		if r["outcome"] != "status" || r["sdk_request_id"] != nil || r["recovery_handle"] != "h1" {
			t.Fatal(r)
		}
	}
	p.exchange(t, control(64, "close"))
	p.wait(t, true)
	p = f.launch(t)
	f.setStatus(500)
	for seq := 1; seq <= 16; seq++ {
		p.exchange(t, call(seq, "PUT"))
	}
	c := call(17, "PUT")
	data, _ := json.Marshal(c)
	p.in.Write(append(data, '\n'))
	p.in.Close()
	remaining, err := io.ReadAll(io.LimitReader(p.out, 16385))
	if err != nil || len(remaining) != 0 {
		t.Fatal("17th handle emitted an observation", err)
	}
	p.wait(t, false)
}

func TestExceptionIdentityAndSavedSourceControl(t *testing.T) {
	f := newFixture(t)
	f.setStatus(500)
	p := f.launch(t)
	c := call(1, "PUT")
	c["if_none_match"] = "*"
	r := p.exchange(t, c)
	id, ok := r["sdk_request_id"].(string)
	if r["outcome"] != "uncertain" || r["error_kind"] != "status" || api(t, r)["status"] != float64(500) || !ok || len(id) != 32 {
		t.Fatal(r)
	}
	first := f.mutations()[0]
	if id != first.id {
		t.Fatal("exception identity differs from public dispatch")
	}
	write(t, filepath.Join(f.root, "input/value-a.bin"), []byte("changed: true\n"))
	f.setStatus(409)
	recover := control(2, "recover")
	recover["handle"] = "h1"
	r = p.exchange(t, recover)
	hits := f.mutations()
	last := hits[len(hits)-1]
	if r["outcome"] != "status" || r["sdk_request_id"] != nil || last.id != id || last.body != first.body || last.none != first.none {
		t.Fatal("saved primitive or exception identity changed", r)
	}
	p.exchange(t, control(3, "close"))
	p.wait(t, true)
}

func TestRawCRFrameRejected(t *testing.T) {
	f := newFixture(t)
	p := f.launch(t)
	data, _ := json.Marshal(control(1, "close"))
	p.in.Write(append(data, '\r', '\n'))
	p.in.Close()
	p.wait(t, false)
	if len(f.mutations()) != 0 {
		t.Fatal("CR frame dispatched")
	}
}

func TestPEMAndKeyLimit(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{"ca.pem", "client.pem", "client.key"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(f.root, name)
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			defer write(t, path, original)
			write(t, path, append(bytes.Clone(original), bytes.Repeat([]byte(" "), 16385-len(original))...))
			p := f.launch(t)
			data, _ := json.Marshal(control(1, "close"))
			p.in.Write(append(data, '\n'))
			p.in.Close()
			p.wait(t, false)
		})
	}
}
