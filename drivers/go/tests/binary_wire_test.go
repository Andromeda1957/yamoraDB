package yamora_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	y "github.com/Andromeda1957/yamoraDB/drivers/go"
)

func TestBinaryLiteralWireGolden(t *testing.T) {
	p := newBinaryPKI(t)
	id := "000102030405060708090a0b0c0d0e0f"
	config := binaryPeer(t, p.server, func(c net.Conn) error {
		f, err := binaryTestRead(c)
		if err != nil {
			return err
		}
		if f.kind != 1 || f.stream != 0 || hex.EncodeToString(f.body) != "000100010001000000000001" {
			return errors.New("literal HELLO mismatch")
		}
		// A literal header/payload, split at every byte, independent of the client codec.
		hello, _ := hex.DecodeString("594d424601010000000000000000000c000100010000100000000001")
		for _, b := range hello {
			if _, err = c.Write([]byte{b}); err != nil {
				return err
			}
		}
		f, err = binaryTestRead(c)
		if err != nil {
			return err
		}
		expected := []byte("\x00\x01\x00\x08" +
			"\x00\x01\x00\x01\x03" +
			"\x00\x02\x00\x24/v1/collections/config/documents/one" +
			"\x00\x03\x00\x10application/yaml" +
			"\x00\x04\x00\x08\x00\x00\x00\x00\x00\x00\x00\x05" +
			"\x00\x05\x00\x27Bearer " + strings.Repeat("t", 32) +
			"\x00\x07\x00\x01*" +
			"\x00\x08\x00\x10\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f")
		if f.kind != 2 || f.stream != 1 || len(f.body) != len(expected)+8 || !bytes.Equal(f.body[:len(expected)], expected) {
			return fmt.Errorf("literal REQUEST mismatch: %x", f.body)
		}
		timeout := f.body[len(expected):]
		if hex.EncodeToString(timeout[:4]) != "00090004" || binary.BigEndian.Uint32(timeout[4:]) == 0 || binary.BigEndian.Uint32(timeout[4:]) > 2000 {
			return errors.New("wire deadline mismatch")
		}
		data, err := binaryTestRead(c)
		if err != nil {
			return err
		}
		if data.kind != 4 || string(data.body) != "v: 1\n" {
			return errors.New("literal DATA mismatch")
		}
		end, err := binaryTestRead(c)
		if err != nil {
			return err
		}
		if !bytes.Equal(binaryTestFrameBytes(end.kind, end.stream, end.body), []byte("YMBF\x01\x05\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00")) {
			return errors.New("literal END mismatch")
		}
		// Literal response metadata: 201, application/json, 114-byte receipt, revision,
		// ETag and exact request ID; count/lengths are not produced by the client.
		receipt := []byte(binaryGoodReceipt)
		response := []byte("\x00\x01\x00\x07" +
			"\x00\x01\x00\x02\x00\xc9" +
			"\x00\x02\x00\x10application/json" +
			"\x00\x03\x00\x08\x00\x00\x00\x00\x00\x00\x00\x72" +
			"\x00\x04\x00\x08\x00\x00\x00\x00\x00\x00\x00\x72" +
			"\x00\x05\x00\x100123456789abcdef" +
			"\x00\x06\x00\x12\"fedcba9876543210\"" +
			"\x00\x0c\x00\x10\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f")
		if len(receipt) != 114 {
			return fmt.Errorf("literal receipt size: %d", len(receipt))
		}
		if err = binaryTestSend(c, 3, response); err != nil {
			return err
		}
		if err = binaryTestSend(c, 4, receipt); err != nil {
			return err
		}
		return binaryTestSend(c, 5, nil)
	})
	config.TLSConfig = p.binary
	config.RootCAPEM = p.rootPEM
	config.WriteToken = strings.Repeat("t", 32)
	ctx, err := y.WithRequestID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	mutation, err := binaryClient(t, config).Put(ctx, "config", "one", []byte("v: 1\n"), y.WriteOptions{CreateOnly: true})
	if err != nil || mutation.Revision != "0123456789abcdef" || mutation.ETag != "fedcba9876543210" {
		t.Fatalf("literal golden rejected: %+v %v", mutation, err)
	}
}

func TestBinaryHostileVerifiedPeer(t *testing.T) {
	p := newBinaryPKI(t)
	cases := []string{"wrong-stream", "even-stream", "flags", "version", "magic", "unknown-frame", "huge-frame", "metadata-limit", "unknown-field", "duplicate-field", "missing-field", "trailing-metadata", "wrong-id", "missing-id", "missing-id-rejection", "zero-id", "wrong-status", "etag", "revision", "collection", "document", "duplicate-json", "unknown-json", "bad-json", "bad-utf8", "body-length", "representation", "ack-limit", "empty-ack", "head-data", "delete-body", "data-before-response", "duplicate-response", "partial-data", "partial-end", "early-end", "error", "error-zero", "goaway-eof", "duplicate-goaway", "pong", "control-flood", "hello-again", "error-503", "rejection-412", "ping-goaway-success"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			id := "0102030405060708090a0b0c0d0e0f10"
			config := binaryPeer(t, p.server, func(c net.Conn) error {
				if err := binaryTestHello(c); err != nil {
					return err
				}
				request, _, err := binaryTestRequest(c)
				if err != nil {
					return err
				}
				body := []byte(binaryGoodReceipt)
				fields := binaryTestResponse(201, body, request[8])
				switch name {
				case "wrong-stream", "even-stream", "flags", "version", "magic", "unknown-frame", "huge-frame", "metadata-limit":
					frame := binaryTestFrameBytes(3, 1, binaryTestMeta(fields))
					switch name {
					case "wrong-stream":
						frame[11] = 3
					case "even-stream":
						frame[11] = 2
					case "flags":
						frame[7] = 1
					case "version":
						frame[4] = 2
					case "magic":
						frame[0] = 'X'
					case "unknown-frame":
						frame[5] = 255
					case "huge-frame":
						binary.BigEndian.PutUint32(frame[12:], 0xffffffff)
					case "metadata-limit":
						binary.BigEndian.PutUint32(frame[12:], 2049)
					}
					c.Write(frame)
					binaryTestSend(c, 4, body)
					binaryTestSend(c, 5, nil)
					return nil
				case "unknown-field":
					fields[13] = []byte{1}
				case "missing-field":
					delete(fields, 5)
				case "duplicate-field":
					meta := binaryTestMeta(fields)
					meta[3]++
					meta = append(meta, 0, 12, 0, 16)
					meta = append(meta, request[8]...)
					binaryTestSend(c, 3, meta)
					return nil
				case "trailing-metadata":
					binaryTestSend(c, 3, append(binaryTestMeta(fields), 0))
					return nil
				case "wrong-id":
					fields[12] = bytes.Repeat([]byte{42}, 16)
				case "missing-id":
					delete(fields, 12)
				case "missing-id-rejection":
					return binaryTestReply(c, 412, []byte(`{"error":"precondition"}`), nil)
				case "zero-id":
					fields[12] = make([]byte, 16)
				case "wrong-status":
					fields[1] = []byte{0, 202}
				case "etag":
					body = bytes.ReplaceAll(body, []byte("fedcba9876543210"), []byte("1111111111111111"))
				case "revision":
					body = bytes.ReplaceAll(body, []byte("0123456789abcdef"), []byte("1111111111111111"))
				case "collection":
					body = bytes.ReplaceAll(body, []byte("config"), []byte("wrongx"))
				case "document":
					body = bytes.ReplaceAll(body, []byte("one"), []byte("two"))
				case "duplicate-json":
					body = bytes.Replace(body, []byte("{"), []byte(`{"status":"bad",`), 1)
				case "unknown-json":
					body = bytes.Replace(body, []byte("{"), []byte(`{"other":"x",`), 1)
				case "bad-json":
					body = []byte(`{"status":`)
				case "bad-utf8":
					body = bytes.Replace(body, []byte("one"), []byte{255, 255, 255}, 1)
				case "body-length":
					fields[3] = binary.BigEndian.AppendUint64(nil, uint64(len(body)+1))
					fields[4] = fields[3]
				case "representation":
					fields[4] = binary.BigEndian.AppendUint64(nil, 0)
				case "ack-limit":
					body = append(body, bytes.Repeat([]byte(" "), 4097-len(body))...)
					fields[3] = binary.BigEndian.AppendUint64(nil, 4097)
					fields[4] = fields[3]
				case "empty-ack":
					fields[3] = binary.BigEndian.AppendUint64(nil, 0)
					fields[4] = fields[3]
				case "head-data":
					fields[1] = []byte{0, 200}
					fields[2] = []byte("application/yaml")
					fields[7] = []byte("config")
					fields[8] = []byte("one")
				case "delete-body":
					fields[1] = []byte{0, 204}
				case "data-before-response":
					binaryTestSend(c, 4, body)
					return nil
				case "early-end":
					return binaryTestSend(c, 5, nil)
				case "error":
					return binaryTestSend(c, 7, []byte{0, 0, 0, 1})
				case "error-zero":
					return binaryTestSend(c, 7, []byte{0, 0, 0, 0})
				case "goaway-eof":
					return binaryTestSend(c, 10, nil)
				case "duplicate-goaway":
					binaryTestSend(c, 10, nil)
					return binaryTestSend(c, 10, nil)
				case "pong":
					return binaryTestSend(c, 9, []byte("12345678"))
				case "control-flood":
					for i := 0; i < 17; i++ {
						if binaryTestSend(c, 8, []byte("12345678")) != nil {
							return nil
						}
						if i < 16 {
							if _, err = binaryTestRead(c); err != nil {
								return err
							}
						}
					}
					return nil
				case "hello-again":
					return binaryTestSend(c, 1, []byte{0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1})
				case "error-503":
					return binaryTestReply(c, 503, []byte(`{"error":"unavailable"}`), request[8])
				case "rejection-412":
					return binaryTestReply(c, 412, []byte(`{"error":"precondition"}`), request[8])
				case "ping-goaway-success":
					if err = binaryTestSend(c, 8, []byte("12345678")); err != nil {
						return err
					}
					pong, err := binaryTestRead(c)
					if err != nil || pong.kind != 9 || string(pong.body) != "12345678" {
						return errors.New("missing correlated PONG")
					}
					if err = binaryTestSend(c, 10, nil); err != nil {
						return err
					}
				}
				// Recompute lengths only for JSON-body substitutions, preserving explicit
				// length contradictions in the adversarial length cases.
				switch name {
				case "etag", "revision", "collection", "document", "duplicate-json", "unknown-json", "bad-json", "bad-utf8":
					fields[3] = binary.BigEndian.AppendUint64(nil, uint64(len(body)))
					fields[4] = fields[3]
				}
				if err = binaryTestSend(c, 3, binaryTestMeta(fields)); err != nil {
					return err
				}
				if name == "duplicate-response" {
					binaryTestSend(c, 3, binaryTestMeta(fields))
					return nil
				}
				if name == "partial-data" {
					c.Write(binaryTestFrameBytes(4, 1, body)[:20])
					return nil
				}
				if err = binaryTestSend(c, 4, body); err != nil {
					return nil
				}
				if name == "partial-end" {
					c.Write([]byte("YMBF\x01\x05"))
					return nil
				}
				binaryTestSend(c, 5, nil)
				return nil
			})
			config.TLSConfig = p.binary
			config.RootCAPEM = p.rootPEM
			ctx, err := y.WithRequestID(context.Background(), id)
			if err != nil {
				t.Fatal(err)
			}
			client := binaryClient(t, config)
			if name == "head-data" {
				_, err = client.Head(ctx, "config", "one", "")
			} else if name == "delete-body" {
				err = client.Delete(ctx, "config", "one", "")
			} else {
				_, err = client.Put(ctx, "config", "one", []byte("v: 1\n"), y.WriteOptions{})
			}
			switch name {
			case "ping-goaway-success":
				if err != nil {
					t.Fatal("valid controls/receipt failed", err)
				}
			case "rejection-412":
				binaryStatus(t, err, 412)
				var uncertain *y.BinaryUncertainWriteError
				if errors.As(err, &uncertain) {
					t.Fatal("validated rejection marked uncertain")
				}
			case "head-data":
				if err == nil {
					t.Fatal("HEAD DATA accepted")
				}
			default:
				binaryUncertain(t, err, id)
			}
		})
	}
}

func TestBinaryFrozenEnvelopeAndSanitizedUncertainty(t *testing.T) {
	p := newBinaryPKI(t)
	source := []byte("secret: never-print-this-source\n")
	began := make(chan struct{})
	resume := make(chan struct{})
	config := binaryPeer(t, p.server, func(c net.Conn) error {
		if err := binaryTestHello(c); err != nil {
			return err
		}
		first, err := binaryTestRead(c)
		if err != nil {
			return err
		}
		fields, err := binaryTestFields(first.body)
		if err != nil {
			return err
		}
		if string(fields[6]) != `"0123456789abcdef"` {
			return errors.New("lost precondition")
		}
		close(began)
		<-resume
		var observed []byte
		for {
			f, err := binaryTestRead(c)
			if err != nil {
				return err
			}
			if f.kind == 5 {
				break
			}
			observed = append(observed, f.body...)
		}
		if string(observed) != "secret: never-print-this-source\n" {
			return errors.New("input was not frozen before I/O")
		}
		return nil // lost receipt after full dispatch, without automatic replay
	})
	config.TLSConfig = p.binary
	config.RootCAPEM = p.rootPEM
	config.WriteToken = "credential-must-never-appear"
	client := binaryClient(t, config)
	result := make(chan error, 1)
	options := y.WriteOptions{ETag: "0123456789abcdef"}
	go func() { _, err := client.Put(context.Background(), "config", "one", source, options); result <- err }()
	<-began
	clear(source)
	options.ETag = "1111111111111111"
	close(resume)
	uncertain := binaryUncertain(t, <-result, "")
	envelope := uncertain.Envelope()
	if envelope.Method != "PUT" || envelope.Collection != "config" || envelope.Document != "one" || envelope.Options.ETag != "0123456789abcdef" || string(envelope.Source()) != "secret: never-print-this-source\n" {
		t.Fatal("original envelope lost")
	}
	owned := envelope.Source()
	clear(owned)
	if !strings.Contains(string(uncertain.Envelope().Source()), "never-print") {
		t.Fatal("caller could mutate uncertainty source")
	}
	for _, rendered := range []string{fmt.Sprint(uncertain), fmt.Sprintf("%+v", uncertain), fmt.Sprintf("%#v", uncertain), fmt.Sprintf("%+v", envelope), fmt.Sprintf("%#v", envelope)} {
		if strings.Contains(rendered, "never-print") || strings.Contains(rendered, config.WriteToken) {
			t.Fatal("private body or credential exposed")
		}
	}
}

func TestBinaryContextOneDeadlineAndCancellation(t *testing.T) {
	p := newBinaryPKI(t)
	for _, phase := range []string{"handshake", "hello", "response", "partial-data", "end", "admission"} {
		for _, cancelled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cancel=%v", phase, cancelled), func(t *testing.T) {
				arrived := make(chan struct{})
				release := make(chan struct{})
				var releaseOnce sync.Once
				defer releaseOnce.Do(func() { close(release) })
				t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
				script := func(c net.Conn) error {
					if phase != "hello" {
						if err := binaryTestHello(c); err != nil {
							return err
						}
					}
					if phase != "hello" {
						fields, _, err := binaryTestRequest(c)
						if err != nil {
							return err
						}
						if phase == "partial-data" || phase == "end" {
							body := []byte(binaryGoodReceipt)
							if err = binaryTestSend(c, 3, binaryTestMeta(binaryTestResponse(201, body, fields[8]))); err != nil {
								return err
							}
							if phase == "partial-data" {
								c.Write(binaryTestFrameBytes(4, 1, body)[:20])
							} else {
								binaryTestSend(c, 4, body)
							}
						}
					}
					close(arrived)
					<-release
					return nil
				}
				var config y.BinaryConfig
				if phase == "handshake" {
					listener, err := net.Listen("tcp4", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					done := make(chan struct{})
					go func() {
						defer close(done)
						raw, err := listener.Accept()
						if err != nil {
							return
						}
						defer raw.Close()
						close(arrived)
						<-release
					}()
					t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); listener.Close(); <-done })
					config = y.BinaryConfig{Address: netip.MustParseAddrPort(listener.Addr().String())}
				} else {
					config = binaryPeer(t, p.server, script)
				}
				config.TLSConfig = p.binary
				config.RootCAPEM = p.rootPEM
				config.Timeout = 220 * time.Millisecond
				config.MaxConcurrentCalls = 1
				client := binaryClient(t, config)
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				result := make(chan error, 1)
				started := time.Now()
				go func() { _, err := client.Put(ctx, "config", "one", []byte("v: 1\n"), y.WriteOptions{}); result <- err }()
				<-arrived
				if phase == "admission" {
					waitCtx, stop := context.WithTimeout(context.Background(), 35*time.Millisecond)
					_, err := client.Put(waitCtx, "config", "two", []byte("v: 2\n"), y.WriteOptions{})
					stop()
					if !errors.Is(err, context.DeadlineExceeded) {
						t.Fatal("admission deadline", err)
					}
					var uncertain *y.BinaryUncertainWriteError
					if errors.As(err, &uncertain) {
						t.Fatal("waiting call marked dispatched")
					}
				}
				cancelStarted := time.Now()
				if cancelled {
					cancel()
				}
				err := <-result
				if cancelled && time.Since(cancelStarted) > 120*time.Millisecond {
					t.Fatal("cancellation did not promptly close its own socket")
				}
				expected := context.DeadlineExceeded
				if cancelled {
					expected = context.Canceled
				}
				if !errors.Is(err, expected) {
					t.Fatalf("%s deadline/cancellation lost: %v", phase, err)
				}
				var uncertain *y.BinaryUncertainWriteError
				dispatched := phase != "handshake" && phase != "hello"
				if errors.As(err, &uncertain) != dispatched {
					t.Fatalf("wrong dispatch uncertainty at %s: %v", phase, err)
				}
				if time.Since(started) > 370*time.Millisecond {
					t.Fatal("deadline was reset by a phase")
				}
				releaseOnce.Do(func() { close(release) })
			})
		}
	}
	// Slow fragments must consume one total budget, not renew it on progress.
	config := binaryPeer(t, p.server, func(c net.Conn) error {
		time.Sleep(70 * time.Millisecond)
		if err := binaryTestHello(c); err != nil {
			return err
		}
		fields, _, err := binaryTestRequest(c)
		if err != nil {
			return err
		}
		time.Sleep(70 * time.Millisecond)
		body := []byte(binaryGoodReceipt)
		if binaryTestSend(c, 3, binaryTestMeta(binaryTestResponse(201, body, fields[8]))) != nil {
			return nil
		}
		for _, b := range body {
			time.Sleep(15 * time.Millisecond)
			if _, err = c.Write(binaryTestFrameBytes(4, 1, []byte{b})); err != nil {
				return nil
			}
		}
		return binaryTestSend(c, 5, nil)
	})
	config.TLSConfig = p.binary
	config.RootCAPEM = p.rootPEM
	config.Timeout = 200 * time.Millisecond
	_, err := binaryClient(t, config).Put(context.Background(), "config", "one", []byte("v: 1\n"), y.WriteOptions{})
	binaryUncertain(t, err, "")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("progress reset total deadline", err)
	}
}

func TestBinaryConfigurationAndInputs(t *testing.T) {
	p := newBinaryPKI(t)
	base := y.BinaryConfig{Address: netip.MustParseAddrPort("127.0.0.1:9"), TLSConfig: p.binary, RootCAPEM: p.rootPEM}
	for _, addr := range []string{"8.8.8.8:443", "169.254.169.254:80", "[::1]:443", "127.0.0.1:0"} {
		c := base
		c.Address = netip.MustParseAddrPort(addr)
		if _, err := y.NewBinary(c); err == nil {
			t.Fatal("accepted credential destination", addr)
		}
	}
	for _, secure := range []*tls.Config{nil, {InsecureSkipVerify: true}, {MinVersion: tls.VersionTLS12}, {MaxVersion: tls.VersionTLS12}, {VerifyConnection: func(tls.ConnectionState) error { return nil }}, {GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return nil, nil }}, {KeyLogWriter: io.Discard}} {
		c := base
		c.TLSConfig = secure
		if _, err := y.NewBinary(c); err == nil {
			t.Fatal("accepted unsupported TLS policy")
		}
	}
	for _, change := range []func(*y.BinaryConfig){func(c *y.BinaryConfig) { c.MaxFrameBytes = 4095 }, func(c *y.BinaryConfig) { c.MaxFrameBytes = 65537 }, func(c *y.BinaryConfig) { c.MaxConcurrentCalls = 5 }, func(c *y.BinaryConfig) { c.Timeout = 31 * time.Second }, func(c *y.BinaryConfig) { c.Timeout = -1 }, func(c *y.BinaryConfig) { c.WriteToken = "secret\nheader" }, func(c *y.BinaryConfig) { c.ReadToken = strings.Repeat("x", 513) }} {
		c := base
		change(&c)
		if _, err := y.NewBinary(c); err == nil {
			t.Fatal("accepted invalid config")
		}
	}
	client := binaryClient(t, base)
	for _, invoke := range []func() error{
		func() error { _, e := client.Get(context.Background(), "../bad", "one", ""); return e },
		func() error { _, e := client.Head(context.Background(), "config", "one", "bad"); return e },
		func() error {
			_, e := client.Put(context.Background(), "config", "one", nil, y.WriteOptions{})
			return e
		},
		func() error {
			_, e := client.Put(context.Background(), "config", "one", []byte{255}, y.WriteOptions{})
			return e
		},
		func() error {
			_, e := client.Put(context.Background(), "config", "one", make([]byte, y.MaxDocumentBytes+1), y.WriteOptions{})
			return e
		},
		func() error {
			_, e := client.Put(context.Background(), "config", "one", []byte("v: 1\n"), y.WriteOptions{ETag: "0123456789abcdef", CreateOnly: true})
			return e
		},
		func() error { return client.Delete(context.Background(), "config", "one", "bad") },
	} {
		err := invoke()
		var uncertain *y.BinaryUncertainWriteError
		if err == nil || errors.As(err, &uncertain) {
			t.Fatal("invalid input dispatched", err)
		}
	}
}

func TestBinaryRejectsAbsentALPNAndIncompatibleHello(t *testing.T) {
	p := newBinaryPKI(t)
	for _, name := range []string{"absent-alpn", "short-frame-cap", "zero-stream", "bad-version-range", "duplicate-hello"} {
		t.Run(name, func(t *testing.T) {
			server := p.server.Clone()
			if name == "absent-alpn" {
				server.NextProtos = nil
			}
			config := binaryPeer(t, server, func(c net.Conn) error {
				if name == "absent-alpn" {
					if err := binaryTestHello(c); err != nil {
						return nil
					} // verified client must close before HELLO
					fields, _, err := binaryTestRequest(c)
					if err != nil {
						return err
					}
					body := []byte("v: 1\n")
					reply := binaryTestResponse(200, body, fields[8])
					reply[2] = []byte("application/yaml")
					reply[7] = []byte("config")
					reply[8] = []byte("one")
					if err = binaryTestSend(c, 3, binaryTestMeta(reply)); err != nil {
						return err
					}
					if err = binaryTestSend(c, 4, body); err != nil {
						return err
					}
					return binaryTestSend(c, 5, nil)
				}
				if _, err := binaryTestRead(c); err != nil {
					return err
				}
				hello := []byte{0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1}
				switch name {
				case "short-frame-cap":
					hello[5] = 0
					hello[6] = 15
					hello[7] = 255
				case "zero-stream":
					hello[11] = 0
				case "bad-version-range":
					hello[1] = 2
					hello[3] = 3
				}
				binaryTestSend(c, 1, hello)
				if name == "duplicate-hello" {
					binaryTestRequest(c)
					binaryTestSend(c, 1, hello)
				}
				return nil
			})
			config.TLSConfig = p.binary
			config.RootCAPEM = p.rootPEM
			_, err := binaryClient(t, config).Get(context.Background(), "config", "one", "")
			if err == nil {
				t.Fatal("unsupported peer accepted")
			}
		})
	}
}

func TestBinaryCancellationOwnsOnlyItsSocket(t *testing.T) {
	p := newBinaryPKI(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	joined := make(chan struct{})
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	var once sync.Once
	serverErrors := make(chan error, 2)
	go func() {
		defer close(joined)
		var workers sync.WaitGroup
		for i := 0; i < 2; i++ {
			raw, err := listener.Accept()
			if err != nil {
				serverErrors <- err
				break
			}
			workers.Add(1)
			go func(raw net.Conn) {
				defer workers.Done()
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(3 * time.Second))
				c := tls.Server(raw, p.server)
				if err := c.Handshake(); err != nil {
					serverErrors <- err
					return
				}
				if err := binaryTestHello(c); err != nil {
					serverErrors <- err
					return
				}
				fields, _, err := binaryTestRequest(c)
				if err != nil {
					serverErrors <- err
					return
				}
				arrived <- struct{}{}
				if strings.HasSuffix(string(fields[2]), "/cancel") {
					var one [1]byte
					_, err := c.Read(one[:])
					if err == nil {
						serverErrors <- errors.New("cancelled socket stayed open")
					}
					return
				}
				<-release
				serverErrors <- binaryTestReply(c, 201, []byte(strings.ReplaceAll(binaryGoodReceipt, `"one"`, `"survive"`)), fields[8])
			}(raw)
		}
		workers.Wait()
	}()
	t.Cleanup(func() {
		once.Do(func() { close(release) })
		listener.Close()
		<-joined
		close(serverErrors)
		for err := range serverErrors {
			if err != nil {
				t.Error("socket-ownership fixture:", err)
			}
		}
	})
	client := binaryClient(t, y.BinaryConfig{Address: netip.MustParseAddrPort(listener.Addr().String()), TLSConfig: p.binary, RootCAPEM: p.rootPEM, Timeout: 2 * time.Second, MaxConcurrentCalls: 2})
	cancelled, stop := context.WithCancel(context.Background())
	defer stop()
	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() {
		_, err := client.Put(cancelled, "config", "cancel", []byte("v: 1\n"), y.WriteOptions{})
		first <- err
	}()
	go func() {
		_, err := client.Put(context.Background(), "config", "survive", []byte("v: 2\n"), y.WriteOptions{})
		second <- err
	}()
	<-arrived
	<-arrived
	stop()
	err = <-first
	binaryUncertain(t, err, "")
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	once.Do(func() { close(release) })
	if err = <-second; err != nil {
		t.Fatal("one call cancelled another's socket", err)
	}
}

func TestBinaryUncertaintyOwnsSourceAfterReturn(t *testing.T) {
	p := newBinaryPKI(t)
	source := []byte("secret: retained original\n")
	config := binaryPeer(t, p.server, func(c net.Conn) error {
		if err := binaryTestHello(c); err != nil {
			return err
		}
		_, body, err := binaryTestRequest(c)
		if err != nil {
			return err
		}
		if !bytes.Equal(body, source) {
			return errors.New("wrong original upload")
		}
		return nil
	})
	config.TLSConfig = p.binary
	config.RootCAPEM = p.rootPEM
	_, err := binaryClient(t, config).Put(context.Background(), "config", "one", source, y.WriteOptions{})
	uncertain := binaryUncertain(t, err, "")
	clear(source)
	if string(uncertain.Envelope().Source()) != "secret: retained original\n" {
		t.Fatal("uncertainty retained caller-owned source")
	}
}

func TestBinaryDeleteLostReceiptRetainsOriginalEnvelope(t *testing.T) {
	p := newBinaryPKI(t)
	config := binaryPeer(t, p.server, func(c net.Conn) error {
		if err := binaryTestHello(c); err != nil {
			return err
		}
		fields, body, err := binaryTestRequest(c)
		if err != nil {
			return err
		}
		if !bytes.Equal(fields[1], []byte{4}) || len(body) != 0 || len(fields[3]) != 0 || string(fields[6]) != `"0123456789abcdef"` {
			return errors.New("DELETE primitive envelope changed")
		}
		return nil
	})
	config.TLSConfig = p.binary
	config.RootCAPEM = p.rootPEM
	id := "00112233445566778899aabbccddeeff"
	ctx, err := y.WithRequestID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	err = binaryClient(t, config).Delete(ctx, "config", "one", "0123456789abcdef")
	envelope := binaryUncertain(t, err, id).Envelope()
	if envelope.Method != "DELETE" || envelope.Collection != "config" || envelope.Document != "one" || envelope.Options.ETag != "0123456789abcdef" || len(envelope.Source()) != 0 {
		t.Fatal("DELETE original envelope lost")
	}
}
