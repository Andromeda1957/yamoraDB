// Command conformance observes exactly one public binary SDK call.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"

	yamora "github.com/Andromeda1957/yamldb/yamora/drivers/go"
)

var required = []string{"host", "port", "server-name", "ca-file", "cert-file", "key-file", "method", "target", "content-type", "feed", "source-file", "request-id", "timeout-ms", "max-frame-bytes", "cancel-mode", "output-dir"}
var invalid = errors.New("adapter infrastructure failure")

func arguments() (map[string]string, error) {
	allowed := map[string]bool{"token-file": true, "if-match": true, "if-none-match": true}
	for _, key := range required {
		allowed[key] = true
	}
	args := os.Args[1:]
	if len(args)%2 != 0 {
		return nil, invalid
	}
	values := make(map[string]string)
	for i := 0; i < len(args); i += 2 {
		if len(args[i]) < 3 || args[i][:2] != "--" {
			return nil, invalid
		}
		key := args[i][2:]
		if _, present := values[key]; !allowed[key] || present {
			return nil, invalid
		}
		values[key] = args[i+1]
	}
	for _, key := range required {
		if _, ok := values[key]; !ok {
			return nil, invalid
		}
	}
	if values["host"] != "127.0.0.1" || values["server-name"] != "localhost" || values["max-frame-bytes"] != "4096" {
		return nil, invalid
	}
	if !regexp.MustCompile(`^(GET|POST|PATCH)$`).MatchString(values["method"]) || !regexp.MustCompile(`^(none|pre|external)$`).MatchString(values["cancel-mode"]) {
		return nil, invalid
	}
	for key, limit := range map[string]int{"port": 65535, "timeout-ms": 30000} {
		value, err := strconv.Atoi(values[key])
		if err != nil || value < 1 || value > limit {
			return nil, invalid
		}
	}
	if values["feed"] != "true" && values["feed"] != "false" {
		return nil, invalid
	}
	if values["feed"] == "true" && (values["method"] != "GET" || values["content-type"] != "") {
		return nil, invalid
	}
	if port, _ := strconv.Atoi(values["port"]); port == 8000 {
		return nil, invalid
	}
	return values, nil
}

func read(path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, invalid
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, invalid
	}
	value, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(value)) > limit {
		return nil, invalid
	}
	return value, nil
}

// Select plus an explicit stop channel bounds the stdin goroutine even if the
// runner keeps its control pipe open after the SDK returns.
func controls(cancel context.CancelFunc, stop <-chan struct{}, entered chan<- struct{}, done chan<- error) {
	close(entered)
	var pending []byte
	for {
		select {
		case <-stop:
			if len(pending) != 0 {
				done <- invalid
			} else {
				done <- nil
			}
			return
		default:
		}
		var ready syscall.FdSet
		ready.Bits[0] = 1
		timeout := syscall.Timeval{Usec: 20000}
		n, err := syscall.Select(1, &ready, nil, nil, &timeout)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			cancel()
			done <- invalid
			return
		}
		if n == 0 {
			continue
		}
		var buffer [3]byte
		n, err = syscall.Read(0, buffer[:])
		if err != nil {
			cancel()
			done <- invalid
			return
		}
		if n == 0 {
			if len(pending) != 0 {
				cancel()
				done <- invalid
			} else {
				done <- nil
			}
			return
		}
		pending = append(pending, buffer[:n]...)
		if len(pending) > 2 || pending[0] != 'C' || (len(pending) == 2 && pending[1] != '\n') {
			cancel()
			done <- invalid
			return
		}
		if bytes.Equal(pending, []byte("C\n")) {
			cancel()
			done <- nil
			return
		}
	}
}

// Classify public sentinels through the original error chain. Unknown causes
// remain infrastructure failures; never compare peer text or guess from input.
func kind(err error) (string, error) {
	if errors.Is(err, context.Canceled) {
		return "cancelled", nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline", nil
	}
	if errors.Is(err, yamora.ErrBinaryProtocol) {
		return "protocol", nil
	}
	if errors.Is(err, yamora.ErrBinaryTransport) || errors.Is(err, yamora.ErrBinaryUnsupported) {
		return "transport", nil
	}
	var status *yamora.HTTPError
	if errors.As(err, &status) {
		return "status", nil
	}
	return "", invalid
}

func run() error {
	a, err := arguments()
	if err != nil {
		return err
	}
	source, err := read(a["source-file"], 16*1024*1024)
	if err != nil {
		return err
	}
	if a["method"] == "GET" && len(source) != 0 {
		return invalid
	}
	ca, err := read(a["ca-file"], 1024*1024)
	if err != nil {
		return err
	}
	cert, err := read(a["cert-file"], 1024*1024)
	if err != nil {
		return err
	}
	key, err := read(a["key-file"], 1024*1024)
	if err != nil {
		return err
	}
	identity, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return err
	}
	root, err := filepath.EvalSymlinks(a["output-dir"])
	if err != nil {
		return err
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() || !filepath.IsAbs(root) {
		return invalid
	}
	file := func(name string, value []byte) error {
		output, err := os.OpenFile(filepath.Join(root, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, err = output.Write(value)
		closed := output.Close()
		if err != nil {
			return err
		}
		return closed
	}
	var token string
	if path, present := a["token-file"]; present {
		value, err := read(path, 512)
		if err != nil {
			return err
		}
		token = string(value)
	}
	port, _ := strconv.Atoi(a["port"])
	timeout, _ := strconv.Atoi(a["timeout-ms"])
	client, err := yamora.NewBinary(yamora.BinaryConfig{Address: netip.AddrPortFrom(netip.MustParseAddr(a["host"]), uint16(port)),
		TLSConfig: &tls.Config{ServerName: a["server-name"], Certificates: []tls.Certificate{identity}}, RootCAPEM: ca,
		ReadToken: token, WriteToken: token, Timeout: time.Duration(timeout) * time.Millisecond, MaxConcurrentCalls: 1, MaxFrameBytes: 4096})
	if err != nil {
		return err
	}
	conditions := map[string]string{}
	if value, ok := a["if-match"]; ok {
		conditions["If-Match"] = value
	}
	if value, ok := a["if-none-match"]; ok {
		conditions["If-None-Match"] = value
	}

	ctx, err := yamora.WithRequestID(context.Background(), a["request-id"])
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if a["cancel-mode"] == "pre" {
		cancel()
	}
	stop, done, entered := make(chan struct{}), make(chan error, 1), make(chan struct{})
	if a["cancel-mode"] == "external" {
		go controls(cancel, stop, entered, done)
		<-entered
	}
	api := map[string]any{"status": nil, "body_file": nil, "etag": nil, "revision": nil, "representation_length": nil, "request_id": nil, "receipt": nil}
	obs := map[string]any{"schema": "yamora-operation-observation/3", "outcome": "success", "error_kind": nil, "elapsed_ns": 0, "api": api, "envelope": nil}
	var result yamora.BinaryOperationResponse
	var bodyFile *os.File
	defer func() {
		if bodyFile != nil {
			bodyFile.Close()
		}
	}()
	started := time.Now()
	if a["feed"] == "true" {
		result, err = client.Feed(ctx, a["target"], func(page []byte) error {
			if bodyFile == nil {
				bodyFile, err = os.OpenFile(filepath.Join(root, "body.bin"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
				if err != nil {
					return err
				}
				api["body_file"] = "body.bin"
			}
			_, e := bodyFile.Write(page)
			return e
		}, conditions)
	} else {
		result, err = client.Operation(ctx, a["method"], a["target"], a["content-type"], source, conditions)
	}

	obs["elapsed_ns"] = time.Since(started).Nanoseconds()
	if a["cancel-mode"] == "external" {
		close(stop)
		select {
		case controlError := <-done:
			if controlError != nil {
				return controlError
			}
		case <-time.After(time.Second):
			return invalid
		}
	}
	if err != nil {
		category, classifyError := kind(err)
		if classifyError != nil {
			return classifyError
		}
		obs["outcome"], obs["error_kind"] = category, category
		var status *yamora.HTTPError
		if errors.As(err, &status) {
			api["status"] = status.Status
		}
		var uncertain *yamora.BinaryUncertainWriteError
		if errors.As(err, &uncertain) {
			original := uncertain.Envelope()
			if err := file("envelope.bin", original.Source()); err != nil {
				return err
			}
			var match, none any
			if v, ok := original.Conditions["If-Match"]; ok {
				match = v
			}
			if v, ok := original.Conditions["If-None-Match"]; ok {
				none = v
			}
			obs["outcome"] = "uncertain"
			obs["envelope"] = map[string]any{"method": original.Method, "target": original.Target, "content_type": original.ContentType, "if_match": match, "if_none_match": none, "request_id": uncertain.RequestID, "source_file": "envelope.bin"}

		}
	}
	if result.Status != 0 {
		api["status"] = result.Status
		api["revision"] = result.Revision
		api["request_id"] = result.RequestID
		api["representation_length"] = result.RepresentationLength
		if result.ETag != "" {
			api["etag"] = result.ETag
		}
		if a["feed"] != "true" && result.Body != nil {
			if e := file("body.bin", result.Body); e != nil {
				return e
			}
			api["body_file"] = "body.bin"
		}
	}

	encoded, err := json.Marshal(obs)
	if err != nil || len(encoded)+1 > 16384 {
		return invalid
	}
	_, err = fmt.Fprintln(os.Stdout, string(encoded))
	return err
}

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "Go conformance adapter failed")
		os.Exit(2)
	}
}
