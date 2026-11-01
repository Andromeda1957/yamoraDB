// Command http_replica observes public HTTP replica calls without its own retries.
// See ADAPTER_HTTP_REPLICA_V2.md. Descriptor-relative file guards target Linux.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	y "github.com/Andromeda1957/yamoraDB/drivers/go"
)

const lineLimit = 16384
const fileLimit = 131072

var invalid = errors.New("HTTP replica adapter input or infrastructure failure")
var idPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var namePattern = regexp.MustCompile(`^[a-z0-9-]{1,128}$`)
var etagPattern = regexp.MustCompile(`^"[0-9a-f]{16}"$`)
var sourcePattern = regexp.MustCompile(`^input/[a-z0-9-]{1,64}\.bin$`)

func validID(v any) bool {
	s, ok := v.(string)
	return ok && idPattern.MatchString(s) && s != strings.Repeat("0", 32)
}

func keys(m map[string]any, names ...string) bool {
	if m == nil || len(m) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := m[name]; !ok {
			return false
		}
	}
	return true
}

func integer(v any) (int, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := strconv.ParseInt(string(n), 10, 32)
	return int(i), err == nil
}

// Token validation rejects duplicate keys at every level before Unmarshal can
// discard them. UseNumber also preserves type checks for integer-only fields.
func jsonValue(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, invalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		if depth > 12 {
			return nil, invalid
		}
		token, err := d.Token()
		if err != nil {
			return nil, invalid
		}
		switch token {
		case json.Delim('{'):
			m := map[string]any{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return nil, invalid
				}
				s, ok := key.(string)
				if !ok {
					return nil, invalid
				}
				if _, exists := m[s]; exists {
					return nil, invalid
				}
				v, err := read(depth + 1)
				if err != nil {
					return nil, err
				}
				m[s] = v
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, invalid
			}
			return m, nil
		case json.Delim('['):
			list := []any{}
			for d.More() {
				v, err := read(depth + 1)
				if err != nil {
					return nil, err
				}
				list = append(list, v)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, invalid
			}
			return list, nil
		case json.Delim('}'), json.Delim(']'):
			return nil, invalid
		}
		if n, ok := token.(json.Number); ok {
			if strings.ContainsAny(string(n), ".eE") {
				return nil, invalid
			}
		}
		return token, nil
	}
	v, err := read(1)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, invalid
	}
	return v, nil
}

type files struct{ root int }

const dirFlags = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC

func openFiles(root string) (*files, error) {
	if !strings.HasPrefix(root, "/") || root == "/" {
		return nil, invalid
	}
	fd, err := syscall.Open("/", dirFlags, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(root[1:], "/") {
		if part == "" || part == "." || part == ".." {
			syscall.Close(fd)
			return nil, invalid
		}
		next, err := syscall.Openat(fd, part, dirFlags, 0)
		syscall.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
	}
	return &files{fd}, nil
}
func (f *files) close()                             { syscall.Close(f.root) }
func (f *files) directory(name string) (int, error) { return syscall.Openat(f.root, name, dirFlags, 0) }
func (f *files) read(name string, limit int64) ([]byte, error) {
	parts := strings.Split(name, "/")
	parent, err := syscall.Dup(f.root)
	if err != nil {
		return nil, err
	}
	defer func() { syscall.Close(parent) }()
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, invalid
		}
		flags := dirFlags
		if i == len(parts)-1 {
			flags = syscall.O_RDONLY | syscall.O_NONBLOCK | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
		}
		fd, err := syscall.Openat(parent, part, flags, 0)
		if err != nil {
			return nil, err
		}
		if i != len(parts)-1 {
			syscall.Close(parent)
			parent = fd
			continue
		}
		file := os.NewFile(uintptr(fd), part)
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return nil, invalid
		}
		data, err := io.ReadAll(io.LimitReader(file, limit+1))
		if err != nil || int64(len(data)) > limit {
			return nil, invalid
		}
		return data, nil
	}
	return nil, invalid
}
func writeBody(dir int, body []byte) error {
	if len(body) > fileLimit {
		return invalid
	}
	fd, err := syscall.Openat(dir, "body.bin", syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "body.bin")
	defer file.Close()
	n, err := file.Write(body)
	if err != nil {
		return err
	}
	if n != len(body) {
		return io.ErrShortWrite
	}
	return nil
}

func config(f *files) (y.Config, error) {
	result := y.Config{}
	data, err := f.read("config.json", lineLimit)
	if err != nil {
		return result, err
	}
	v, err := jsonValue(data)
	if err != nil {
		return result, err
	}
	m, _ := v.(map[string]any)
	if !keys(m, "schema", "cluster_id", "voters", "seeds", "tls", "tokens", "timeout_ms", "attempt_timeout_ms") || m["schema"] != "yamora-http-replica-config/2" || !validID(m["cluster_id"]) {
		return result, invalid
	}
	for key, want := range map[string]int{"voters": 3, "timeout_ms": 15000, "attempt_timeout_ms": 3000} {
		n, ok := integer(m[key])
		if !ok || n != want {
			return result, invalid
		}
	}
	seeds, ok := m["seeds"].([]any)
	if !ok || len(seeds) != 3 {
		return result, invalid
	}
	nodes, ports := map[int]bool{}, map[int]bool{}
	for _, value := range seeds {
		seed, _ := value.(map[string]any)
		if !keys(seed, "host", "port", "node") || seed["host"] != "127.0.0.1" {
			return result, invalid
		}
		port, p := integer(seed["port"])
		node, n := integer(seed["node"])
		if !p || !n || port < 1 || port > 65535 || port == 8000 || ports[port] || node < 1 || node > 3 || nodes[node] {
			return result, invalid
		}
		ports[port], nodes[node] = true, true
		result.Seeds = append(result.Seeds, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)))
	}
	tlsFields, _ := m["tls"].(map[string]any)
	tokens, _ := m["tokens"].(map[string]any)
	if !keys(tlsFields, "ca_file", "cert_file", "key_file") || tlsFields["ca_file"] != "ca.pem" || tlsFields["cert_file"] != "client.pem" || tlsFields["key_file"] != "client.key" || !keys(tokens, "read_file", "write_file") || tokens["read_file"] != "read.token" || tokens["write_file"] != "write.token" {
		return result, invalid
	}
	ca, err := f.read("ca.pem", lineLimit)
	if err != nil {
		return result, err
	}
	cert, err := f.read("client.pem", lineLimit)
	if err != nil {
		return result, err
	}
	key, err := f.read("client.key", lineLimit)
	if err != nil {
		return result, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return result, invalid
	}
	identity, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return result, err
	}
	result.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{identity}}
	for name, target := range map[string]*string{"read.token": &result.ReadToken, "write.token": &result.WriteToken} {
		data, err := f.read(name, 512)
		if err != nil {
			return result, err
		}
		token := strings.TrimRight(string(data), "\r\n")
		if len(token) < 32 || len(token) > 512 {
			return result, invalid
		}
		for _, b := range []byte(token) {
			if b < 33 || b > 126 {
				return result, invalid
			}
		}
		*target = token
	}
	result.Timeout, result.RetryTimeout = 3*time.Second, 15*time.Second
	return result, nil
}

// All saved fields are private scalars/strings. No mutable SDK map or source
// buffer aliases the retained primitive; every invocation receives a fresh copy.
type primitive struct {
	method, collection, document, source, requestID, match string
	create                                                 bool
}
type recovery struct {
	call      primitive
	exception *y.UncertainWriteError
}

func parseCall(m map[string]any, f *files) (primitive, error) {
	c := primitive{}
	if !keys(m, "schema", "seq", "action", "method", "collection", "document", "source_file", "request_id", "if_match", "if_none_match") {
		return c, invalid
	}
	c.method, _ = m["method"].(string)
	c.collection, _ = m["collection"].(string)
	c.document, _ = m["document"].(string)
	if (c.method != "GET" && c.method != "PUT" && c.method != "PATCH" && c.method != "DELETE") || !namePattern.MatchString(c.collection) || !namePattern.MatchString(c.document) || (c.method != "GET" && c.collection == "yamldb-system") {
		return c, invalid
	}
	if m["request_id"] != nil {
		if !validID(m["request_id"]) {
			return c, invalid
		}
		c.requestID = m["request_id"].(string)
	}
	if m["if_match"] != nil {
		s, ok := m["if_match"].(string)
		if !ok || !etagPattern.MatchString(s) {
			return c, invalid
		}
		c.match = s[1:17]
	}
	if m["if_none_match"] != nil {
		if m["if_none_match"] != "*" || c.method != "PUT" || c.match != "" {
			return c, invalid
		}
		c.create = true
	}
	if c.method == "GET" && (c.requestID != "" || c.match != "" || c.create) {
		return c, invalid
	}
	if c.method == "PUT" || c.method == "PATCH" {
		name, ok := m["source_file"].(string)
		if !ok || !sourcePattern.MatchString(name) {
			return c, invalid
		}
		data, err := f.read(name, fileLimit)
		if err != nil || len(data) == 0 || !utf8.Valid(data) {
			return c, invalid
		}
		if c.method == "PATCH" {
			v, err := jsonValue(data)
			if err != nil {
				return c, err
			}
			object, _ := v.(map[string]any)
			inc, _ := object["$inc"].(map[string]any)
			n, ok := integer(inc["n"])
			if !keys(object, "$inc") || !keys(inc, "n") || !ok || n != 1 {
				return c, invalid
			}
		}
		c.source = string(data)
	} else if m["source_file"] != nil {
		return c, invalid
	}
	return c, nil
}

type api struct {
	Status   *int    `json:"status"`
	BodyFile *string `json:"body_file"`
	ETag     *string `json:"etag"`
	Revision *string `json:"revision"`
	Receipt  any     `json:"receipt"`
}
type observation struct {
	Schema         string  `json:"schema"`
	Seq            int     `json:"seq"`
	Action         string  `json:"action"`
	Outcome        string  `json:"outcome"`
	ErrorKind      *string `json:"error_kind"`
	Elapsed        int64   `json:"elapsed_ns"`
	API            api     `json:"api"`
	SDKRequestID   *string `json:"sdk_request_id"`
	Envelope       any     `json:"envelope"`
	RecoveryMode   *string `json:"recovery_mode"`
	RecoveryHandle *string `json:"recovery_handle"`
}

func pointer[T any](v T) *T { return &v }

// Only these public SDK methods are invoked. Test peers exercise controls only;
// real native receipts/source witnesses are qualified by the parent fixture.
type publicClient interface {
	Get(context.Context, string, string, string) (y.Document, error)
	Put(context.Context, string, string, []byte, y.WriteOptions) (y.Mutation, error)
	Patch(context.Context, string, string, map[string]any, string) (y.Mutation, error)
	Delete(context.Context, string, string, string) error
	Close()
}
type session struct {
	files   *files
	client  publicClient
	seq     int
	handles map[string]recovery
}

func (s *session) close() {
	if s.client != nil {
		s.client.Close()
		s.client = nil
	}
	clear(s.handles)
}

func category(err error) *string {
	var remote *y.HTTPError
	var network net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return pointer("deadline")
	case errors.Is(err, context.Canceled):
		return pointer("cancelled")
	case errors.As(err, &remote):
		return pointer("status")
	case errors.As(err, &network):
		return pointer("transport")
	default:
		return nil
	}
}

func (s *session) execute(ctx context.Context, m map[string]any) (observation, error) {
	seq, ok := integer(m["seq"])
	action, _ := m["action"].(string)
	r := observation{Schema: "yamora-http-replica-observation/2", Seq: seq, Action: action, Outcome: "success"}
	if !ok || seq != s.seq+1 || seq > 64 || m["schema"] != "yamora-http-replica-command/2" {
		return r, invalid
	}
	if action == "close" {
		if !keys(m, "schema", "seq", "action") {
			return r, invalid
		}
		s.close()
		s.seq = seq
		r.Outcome = "closed"
		return r, nil
	}
	var call primitive
	var err error
	id := ""
	if action == "call" {
		call, err = parseCall(m, s.files)
		id = call.requestID
	} else {
		handle, ok := m["handle"].(string)
		saved, found := s.handles[handle]
		if !keys(m, "schema", "seq", "action", "handle") || action != "recover" || !ok || !found {
			return r, invalid
		}
		call, id = saved.call, saved.exception.RequestID
		r.RecoveryMode, r.RecoveryHandle = pointer("caller-reissue"), pointer(handle)
	}
	if err != nil {
		return r, err
	}
	dirName := fmt.Sprintf("call-%06d", seq)
	dir, err := s.files.directory(dirName)
	if err != nil {
		return r, err
	}
	defer syscall.Close(dir)
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if id != "" {
		ctx, err = y.WithRequestID(ctx, id)
		if err != nil {
			return r, err
		}
	}
	// Prepare typed PATCH before starting the public-call clock.
	operations := map[string]any{"$inc": map[string]any{"n": 1}}
	source := []byte(call.source)
	var doc y.Document
	var mutation y.Mutation
	start := time.Now()
	switch call.method {
	case "GET":
		doc, err = s.client.Get(ctx, call.collection, call.document, "")
	case "PUT":
		mutation, err = s.client.Put(ctx, call.collection, call.document, source, y.WriteOptions{ETag: call.match, CreateOnly: call.create})
	case "PATCH":
		mutation, err = s.client.Patch(ctx, call.collection, call.document, operations, call.match)
	case "DELETE":
		err = s.client.Delete(ctx, call.collection, call.document, call.match)
	default:
		return r, invalid
	}
	r.Elapsed = time.Since(start).Nanoseconds()
	s.seq = seq
	if err != nil {
		var remote *y.HTTPError
		if errors.As(err, &remote) {
			r.API.Status = pointer(remote.Status)
		}
		var uncertain *y.UncertainWriteError
		if errors.As(err, &uncertain) {
			if call.method == "GET" || !validID(uncertain.RequestID) {
				return r, invalid
			}
			if action == "call" {
				if len(s.handles) >= 16 {
					return r, invalid
				}
				handle := fmt.Sprintf("h%d", len(s.handles)+1)
				s.handles[handle] = recovery{call, uncertain}
				r.RecoveryMode, r.RecoveryHandle = pointer("caller-reissue"), pointer(handle)
			}
			r.Outcome, r.ErrorKind, r.SDKRequestID = "uncertain", category(err), pointer(uncertain.RequestID)
			return r, nil
		}
		r.ErrorKind = category(err)
		if r.ErrorKind == nil {
			r.ErrorKind = pointer("protocol")
		}
		r.Outcome = *r.ErrorKind
		return r, nil
	}
	switch call.method {
	case "GET":
		if err := writeBody(dir, doc.Source); err != nil {
			return r, err
		}
		r.API.BodyFile, r.API.ETag, r.API.Revision = pointer(dirName+"/body.bin"), pointer(doc.ETag), pointer(doc.Revision)
	case "PUT", "PATCH":
		r.API.ETag, r.API.Revision, r.API.Receipt = pointer(mutation.ETag), pointer(mutation.Revision), mutation
	}
	return r, nil
}

func run(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	if len(args) != 4 {
		return invalid
	}
	values := map[string]string{}
	for i := 0; i < len(args); i += 2 {
		if (args[i] != "--config" && args[i] != "--root") || values[args[i]] != "" {
			return invalid
		}
		values[args[i]] = args[i+1]
	}
	if values["--config"] != values["--root"]+"/config.json" {
		return invalid
	}
	f, err := openFiles(values["--root"])
	if err != nil {
		return err
	}
	defer f.close()
	cfg, err := config(f)
	if err != nil {
		return err
	}
	client, err := y.New(cfg)
	if err != nil {
		return err
	}
	s := &session{files: f, client: client, handles: map[string]recovery{}}
	defer s.close()
	reader := bufio.NewReaderSize(input, lineLimit)
	for {
		line, err := reader.ReadSlice('\n')
		if err != nil || len(line) > lineLimit || bytes.ContainsRune(line, '\r') {
			return invalid
		}
		watchdog := time.AfterFunc(25*time.Second, func() { fmt.Fprintln(os.Stderr, "HTTP replica adapter command watchdog expired"); os.Exit(2) })
		value, err := jsonValue(line)
		command, _ := value.(map[string]any)
		var result observation
		if err == nil && command != nil {
			result, err = s.execute(ctx, command)
		} else {
			err = invalid
		}
		if err == nil {
			var encoded []byte
			encoded, err = json.Marshal(result)
			if err == nil {
				encoded = append(encoded, '\n')
				if len(encoded) > lineLimit {
					err = invalid
				} else {
					var n int
					n, err = output.Write(encoded)
					if err == nil && n != len(encoded) {
						err = io.ErrShortWrite
					}
				}
			}
		}
		watchdog.Stop()
		if err != nil {
			return err
		}
		if result.Outcome == "closed" {
			return nil
		}
	}
}

func exitCode() (code int) {
	defer func() {
		if recover() != nil {
			fmt.Fprintln(os.Stderr, invalid)
			code = 2
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Inherited stdin may be a blocking pipe that os.Stdin.Close cannot
	// interrupt. Give the runtime poller a nonblocking owned duplicate instead.
	inputFD, err := syscall.Dup(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Fprintln(os.Stderr, invalid)
		return 2
	}
	if err := syscall.SetNonblock(inputFD, true); err != nil {
		syscall.Close(inputFD)
		fmt.Fprintln(os.Stderr, invalid)
		return 2
	}
	input := os.NewFile(uintptr(inputFD), "http-replica-stdin")
	defer input.Close()
	// Cancellation also interrupts a partial/idle input read without a helper
	// goroutine remaining blocked on stdin after session close.
	interrupt := context.AfterFunc(ctx, func() { input.Close() })
	defer interrupt()
	if err := run(ctx, os.Args[1:], input, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, invalid)
		return 2
	}
	return 0
}

func main() { os.Exit(exitCode()) }
