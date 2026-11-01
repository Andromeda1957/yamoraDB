package yamora_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	y "github.com/Andromeda1957/yamoraDB/yamora/drivers/go"
)

func TestBinaryNativeMTLSCRUDHTTPInterop(t *testing.T) {
	daemon := newBinaryNative(t, false, true)
	client := binaryClient(t, daemon.config)
	http, err := y.New(daemon.http)
	if err != nil {
		t.Fatal(err)
	}
	defer http.Close()
	ctx := context.Background()
	sources := [][]byte{[]byte("# café\r\nvalue: 01 # spelling\r\ntext: 'λ'\r\nn: 9223372036854775807\r\n"), []byte("# HTTP scalar\n-9223372036854775808\n"), []byte("# block and escapes\nvalue: |\n  東京\nquoted: \"a\\nb\"\n")}
	for i, source := range sources {
		name := fmt.Sprintf("doc%d", i)
		var stored y.Mutation
		if i == 1 {
			stored, err = http.Put(ctx, "config", name, source, y.WriteOptions{CreateOnly: true})
		} else {
			stored, err = client.Put(ctx, "config", name, source, y.WriteOptions{CreateOnly: true})
		}
		if err != nil {
			t.Fatal(err)
		}
		got, err := client.Get(ctx, "config", name, stored.Revision)
		if err != nil || !bytes.Equal(got.Source, source) || got.ETag != stored.ETag {
			t.Fatalf("exact binary source/receipt: %v", err)
		}
		other, err := http.Get(ctx, "config", name, stored.Revision)
		if err != nil || !bytes.Equal(other.Source, source) || other.ETag != stored.ETag {
			t.Fatalf("HTTP source/receipt: %v", err)
		}
		head, err := client.Head(ctx, "config", name, stored.Revision)
		if err != nil || head.Length != uint64(len(source)) || head.ETag != stored.ETag {
			t.Fatalf("HEAD representation: %+v %v", head, err)
		}
		_, err = client.Put(ctx, "config", name, source, y.WriteOptions{CreateOnly: true})
		binaryStatus(t, err, 412)
		_, err = client.Put(ctx, "config", name, source, y.WriteOptions{ETag: "0000000000000000"})
		binaryStatus(t, err, 412)
		err = client.Delete(ctx, "config", name, "0000000000000000")
		binaryStatus(t, err, 412)
		changed, err := client.Put(ctx, "config", name, []byte("value: replacement\n"), y.WriteOptions{ETag: stored.ETag})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = client.Get(ctx, "config", name, stored.Revision); err == nil {
			t.Fatal("accepted changed revision")
		}
		if err = client.Delete(ctx, "config", name, changed.ETag); err != nil {
			t.Fatal(err)
		}
		_, err = client.Get(ctx, "config", name, "")
		binaryStatus(t, err, 404)
		_, err = http.Get(ctx, "config", name, "")
		binaryStatus(t, err, 404)
		_, err = client.Head(ctx, "config", name, "")
		binaryStatus(t, err, 404)
	}
	// Standalone IDs are echoed but do not deduplicate subsequent operations.
	id := "0102030405060708090a0b0c0d0e0f10"
	identified, err := y.WithRequestID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.Put(identified, "config", "id", []byte("v: 1\n"), y.WriteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.Put(identified, "config", "id", []byte("v: 2\n"), y.WriteOptions{})
	if err != nil || second.ETag == first.ETag {
		t.Fatal("standalone ID incorrectly deduplicated", err)
	}
	// Copied configuration survives caller certificate destruction and endpoint edits.
	copied := binaryClient(t, daemon.config)
	changedConfig := daemon.config
	changedConfig.Address = daemon.http.Address
	for _, cert := range daemon.config.TLSConfig.Certificates {
		for _, der := range cert.Certificate {
			clear(der)
		}
	}
	if _, err = copied.Get(ctx, "config", "id", ""); err != nil {
		t.Fatalf("TLS identity was not copied: %v", err)
	}
}

func TestBinaryNativeAuthRolesMTLS(t *testing.T) {
	daemon := newBinaryNative(t, false, true)
	ctx := context.Background()
	for _, token := range []string{"", "wrong"} {
		cfg := daemon.config
		cfg.ReadToken = token
		cfg.WriteToken = token
		client := binaryClient(t, cfg)
		_, err := client.Get(ctx, "allowed", "one", "")
		binaryStatus(t, err, 401)
		_, err = client.Put(ctx, "allowed", "one", []byte("v: 1\n"), y.WriteOptions{})
		binaryStatus(t, err, 401)
	}
	readOnly := daemon.config
	readOnly.WriteToken = readOnly.ReadToken
	_, err := binaryClient(t, readOnly).Put(ctx, "allowed", "one", []byte("v: 1\n"), y.WriteOptions{})
	binaryStatus(t, err, 401)
	scoped := daemon.config
	scoped.ReadToken = strings.Repeat("s", 32)
	scoped.WriteToken = scoped.ReadToken
	client := binaryClient(t, scoped)
	if _, err = client.Put(ctx, "allowed", "one", []byte("v: 1\n"), y.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = client.Get(ctx, "allowed", "one", ""); err != nil {
		t.Fatal(err)
	}
	_, err = client.Get(ctx, "denied", "one", "")
	binaryStatus(t, err, 403)
	_, err = client.Put(ctx, "denied", "one", []byte("v: 1\n"), y.WriteOptions{})
	binaryStatus(t, err, 403)
	_, err = client.Put(ctx, "yamldb-system", "one", []byte("v: 1\n"), y.WriteOptions{})
	if err == nil {
		t.Fatal("reserved collection accepted")
	}
	noCert := daemon.config
	noCert.TLSConfig = noCert.TLSConfig.Clone()
	noCert.TLSConfig.Certificates = nil
	_, err = binaryClient(t, noCert).Get(ctx, "allowed", "one", "")
	if err == nil {
		t.Fatal("mTLS accepted no certificate")
	}
	noTrust := daemon.config
	noTrust.TLSConfig = &tls.Config{}
	noTrust.RootCAPEM = newBinaryPKI(t).rootPEM
	_, err = binaryClient(t, noTrust).Get(ctx, "allowed", "one", "")
	if err == nil {
		t.Fatal("untrusted server accepted")
	}
	wrongName := daemon.config
	wrongName.TLSConfig = wrongName.TLSConfig.Clone()
	wrongName.TLSConfig.ServerName = "wrong.test"
	_, err = binaryClient(t, wrongName).Get(ctx, "allowed", "one", "")
	if err == nil {
		t.Fatal("wrong peer identity accepted")
	}
}

func TestBinaryNativeSixteenMiBAndLegacyProfile(t *testing.T) {
	daemon := newBinaryNative(t, false, false)
	client := binaryClient(t, daemon.config)
	prefix := []byte("# exact CRLF Unicode λ\r\nvalue: 9223372036854775807\r\n# ")
	source := append(bytes.Clone(prefix), bytes.Repeat([]byte("x"), y.MaxDocumentBytes-len(prefix)-2)...)
	source = append(source, '\r', '\n')
	stored, err := client.Put(context.Background(), "config", "large", source, y.WriteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.Get(context.Background(), "config", "large", stored.Revision)
	if err != nil || !bytes.Equal(got.Source, source) {
		t.Fatalf("16 MiB fragmented source: %v", err)
	}
	head, err := client.Head(context.Background(), "config", "large", stored.Revision)
	if err != nil || head.Length != y.MaxDocumentBytes {
		t.Fatalf("large HEAD: %+v %v", head, err)
	}
	http, err := y.New(daemon.http)
	if err != nil {
		t.Fatal(err)
	}
	defer http.Close()
	got, err = http.Get(context.Background(), "config", "large", stored.Revision)
	if err != nil || !bytes.Equal(got.Source, source) {
		t.Fatalf("large HTTP interoperability: %v", err)
	}
	legacy := newBinaryNative(t, true, false)
	old := binaryClient(t, legacy.config)
	_, err = old.Put(context.Background(), "config", "large", source[:256*1024+1], y.WriteOptions{})
	binaryStatus(t, err, 413)
	_, err = old.Get(context.Background(), "config", "large", "")
	binaryStatus(t, err, 404)
	if _, err = old.Put(context.Background(), "config", "small", []byte("v: 1\n"), y.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestBinaryNativeBusyErrorAndCancellation(t *testing.T) {
	daemon := newBinaryNative(t, false, false)
	var held []*tls.Conn
	t.Cleanup(func() {
		for _, c := range held {
			c.Close()
		}
	})
	for i := 0; i < 4; i++ {
		secure := daemon.http.TLSConfig.Clone()
		secure.NextProtos = []string{"yamora-binary/1"}
		conn, err := tls.Dial("tcp4", daemon.config.Address.String(), secure)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, conn)
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if err = binaryTestSend(conn, 1, []byte{0, 1, 0, 1, 0, 0, 16, 0, 0, 0, 0, 1}); err != nil {
			t.Fatal(err)
		}
		hello, err := binaryTestRead(conn)
		if err != nil || hello.kind != 1 {
			t.Fatal("native HELLO", err)
		}
		request := map[int][]byte{1: {3}, 2: []byte("/v1/collections/config/documents/held"), 3: []byte("application/yaml"), 4: binary.BigEndian.AppendUint64(nil, 10), 5: []byte("Bearer " + daemon.config.WriteToken), 8: bytes.Repeat([]byte{byte(i + 1)}, 16), 9: binary.BigEndian.AppendUint32(nil, 3000)}
		if err = binaryTestSend(conn, 2, binaryTestMeta(request)); err != nil {
			t.Fatal(err)
		}
		if err = binaryTestSend(conn, 8, []byte("12345678")); err != nil {
			t.Fatal(err)
		}
		pong, err := binaryTestRead(conn)
		if err != nil || pong.kind != 9 {
			t.Fatalf("ticket admission PONG: %d %v", pong.kind, err)
		}
	}
	config := daemon.config
	config.Timeout = time.Second
	client := binaryClient(t, config)
	_, err := client.Put(context.Background(), "config", "busy", []byte("v: 1\n"), y.WriteOptions{})
	binaryUncertain(t, err, "")
	for _, c := range held {
		c.Close()
	}
	held = nil
	// Cancel before dispatch: no uncertain outcome and no mutation.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = client.Put(ctx, "config", "cancelled", []byte("v: 1\n"), y.WriteOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("pre-dispatch cancellation", err)
	}
	var uncertain *y.BinaryUncertainWriteError
	if errors.As(err, &uncertain) {
		t.Fatal("pre-dispatch cancellation marked uncertain")
	}
	deadline := time.Now().Add(time.Second)
	for {
		_, err = client.Get(context.Background(), "config", "busy", "")
		var remote *y.HTTPError
		if errors.As(err, &remote) && remote.Status == 404 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("busy ticket release", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Parallel independent calls exercise the client admission bound and socket ownership.
func TestBinaryNativeConcurrentCalls(t *testing.T) {
	daemon := newBinaryNative(t, false, false)
	client := binaryClient(t, daemon.config)
	var group sync.WaitGroup
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			name := fmt.Sprintf("n%d", i)
			_, err := client.Put(context.Background(), "config", name, []byte("v: 1\n"), y.WriteOptions{})
			if err == nil {
				_, err = client.Get(context.Background(), "config", name, "")
			}
			failures <- err
		}(i)
	}
	group.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// A verified TLS relay forwards the original wire request to the immutable
// native daemon, waits for its real terminal receipt, then loses part of it.
// This proves uncertainty after publication without implementing recovery.
func TestBinaryNativeCommittedPartialReceipt(t *testing.T) {
	daemon := newBinaryNative(t, false, true)
	http, err := y.New(daemon.http)
	if err != nil {
		t.Fatal(err)
	}
	defer http.Close()
	p := newBinaryPKI(t)
	for _, loss := range []string{"response", "data", "end"} {
		t.Run(loss, func(t *testing.T) {
			name := "lost-" + loss
			id := "11223344556677889900aabbccddeeff"
			config := binaryPeer(t, p.server, func(downstream net.Conn) error {
				secure := daemon.http.TLSConfig.Clone()
				secure.NextProtos = []string{"yamora-binary/1"}
				upstream, err := tls.Dial("tcp4", daemon.config.Address.String(), secure)
				if err != nil {
					return err
				}
				defer upstream.Close()
				upstream.SetDeadline(time.Now().Add(5 * time.Second))
				hello, err := binaryTestRead(downstream)
				if err != nil {
					return err
				}
				if _, err = upstream.Write(binaryTestFrameBytes(hello.kind, hello.stream, hello.body)); err != nil {
					return err
				}
				hello, err = binaryTestRead(upstream)
				if err != nil {
					return err
				}
				if _, err = downstream.Write(binaryTestFrameBytes(hello.kind, hello.stream, hello.body)); err != nil {
					return err
				}
				for {
					f, err := binaryTestRead(downstream)
					if err != nil {
						return err
					}
					if _, err = upstream.Write(binaryTestFrameBytes(f.kind, f.stream, f.body)); err != nil {
						return err
					}
					if f.kind == 5 {
						break
					}
				}
				var frames []binaryTestFrame
				total := 0
				for {
					f, err := binaryTestRead(upstream)
					if err != nil {
						return err
					}
					total += len(f.body)
					if total > 8192 {
						return errors.New("unbounded native receipt")
					}
					frames = append(frames, f)
					if f.kind == 5 {
						break
					}
				}
				for _, f := range frames {
					if loss == "response" {
						return nil
					}
					encoded := binaryTestFrameBytes(f.kind, f.stream, f.body)
					if loss == "data" && f.kind == 4 {
						downstream.Write(encoded[:17])
						return nil
					}
					if loss == "end" && f.kind == 5 {
						downstream.Write(encoded[:7])
						return nil
					}
					if _, err = downstream.Write(encoded); err != nil {
						return err
					}
				}
				return errors.New("loss fixture failed to intercept receipt")
			})
			config.TLSConfig = p.binary
			config.RootCAPEM = p.rootPEM
			config.WriteToken = daemon.config.WriteToken
			ctx, err := y.WithRequestID(context.Background(), id)
			if err != nil {
				t.Fatal(err)
			}
			original := []byte("# commit despite lost receipt\r\nvalue: λ\r\nn: 9223372036854775807\r\n")
			_, err = binaryClient(t, config).Put(ctx, "config", name, original, y.WriteOptions{CreateOnly: true})
			uncertain := binaryUncertain(t, err, id)
			if !bytes.Equal(uncertain.Envelope().Source(), original) || !uncertain.Envelope().Options.CreateOnly {
				t.Fatal("lost receipt discarded request")
			}
			observed, err := http.Get(context.Background(), "config", name, "")
			if err != nil || !bytes.Equal(observed.Source, original) {
				t.Fatalf("native mutation did not publish exact bytes before loss: %v", err)
			}
		})
	}
}
