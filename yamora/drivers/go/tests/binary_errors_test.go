package yamora_test

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	y "github.com/Andromeda1957/yamldb/yamora/drivers/go"
)

func TestBinaryPublicFailureClassification(t *testing.T) {
	p := newBinaryPKI(t)
	for _, method := range []string{"GET", "PUT"} {
		for _, kind := range []string{"protocol", "transport"} {
			t.Run(method+"/"+kind, func(t *testing.T) {
				var received atomic.Bool
				config := binaryPeer(t, p.server, func(c net.Conn) error {
					if err := binaryTestHello(c); err != nil {
						return err
					}
					if _, _, err := binaryTestRequest(c); err != nil {
						return err
					}
					received.Store(true)
					if kind == "protocol" {
						// A complete illegal frame, after confirmed TLS and request END.
						return binaryTestSend(c, 255, nil)
					}
					return nil // Close without a response after receiving the request.
				})
				config.TLSConfig, config.RootCAPEM = p.binary, p.rootPEM
				client := binaryClient(t, config)
				ctx, err := y.WithRequestID(context.Background(), "0102030405060708090a0b0c0d0e0f10")
				if err != nil {
					t.Fatal(err)
				}
				if method == "PUT" {
					_, err = client.Put(ctx, "config", "one", []byte("v: 1\n"), y.WriteOptions{CreateOnly: true})
				} else {
					_, err = client.Get(ctx, "config", "one", "")
				}
				if !received.Load() {
					t.Fatalf("classification requires a completed peer request: %v", err)
				}
				wanted, other := y.ErrBinaryProtocol, y.ErrBinaryTransport
				if kind == "transport" {
					wanted, other = other, wanted
				}
				if !errors.Is(err, wanted) || errors.Is(err, other) {
					t.Fatalf("public binary failure classification lost: %v", err)
				}
				var uncertain *y.BinaryUncertainWriteError
				if errors.As(err, &uncertain) != (method == "PUT") {
					t.Fatalf("classification changed write uncertainty: %v", err)
				}
				if uncertain != nil && (uncertain.RequestID != "0102030405060708090a0b0c0d0e0f10" || string(uncertain.Envelope().Source()) != "v: 1\n") {
					t.Fatal("classification lost the original mutation")
				}
			})
		}
	}
}
