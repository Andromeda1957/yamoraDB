package yamora_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"

	y "github.com/Andromeda1957/yamoraDB/drivers/go"
)

func operationPeer(t *testing.T, answer func(net.Conn, map[int][]byte, []byte) error, minimum ...byte) *y.BinaryClient {
	p := newBinaryPKI(t)
	config := binaryPeer(t, p.server, func(c net.Conn) error {
		hello, err := binaryTestRead(c)
		if err != nil {
			return err
		}
		if hello.kind != 1 || binary.BigEndian.Uint16(hello.body[2:4]) != 2 {
			return errors.New("protocol2 HELLO required")
		}
		low := byte(1)
		if len(minimum) != 0 {
			low = minimum[0]
		}
		if err = binaryTestSend(c, 1, []byte{0, low, 0, 2, 0, 0, 16, 0, 0, 0, 0, 1}); err != nil {
			return err
		}
		fields, source, err := binaryTestRequest(c)
		if err != nil {
			return err
		}
		return answer(c, fields, source)
	})
	config.TLSConfig = p.binary
	config.RootCAPEM = p.rootPEM
	config.ReadToken = "read-synthetic"
	config.WriteToken = "write-synthetic"
	return binaryClient(t, config)
}
func TestBinaryOperationProtocolTwoOnlyPeer(t *testing.T) {
	body := []byte(`{"revision":"0123456789abcdef"}`)
	client := operationPeer(t, func(c net.Conn, fields map[int][]byte, _ []byte) error {
		return operationReply(c, body, fields[8], 0, nil)
	}, 2)
	result, err := client.Operation(context.Background(), "POST", "/v1/query/a", "application/json", []byte(`{}`), nil)
	if err != nil || !bytes.Equal(result.Body, body) {
		t.Fatalf("common protocol2 range rejected: %v", err)
	}
}
func TestBinaryOperationLegacyPeerUnsupportedBeforeRequest(t *testing.T) {
	p := newBinaryPKI(t)
	config := binaryPeer(t, p.server, func(c net.Conn) error {
		if _, err := binaryTestRead(c); err != nil {
			return err
		}
		if err := binaryTestSend(c, 1, []byte{0, 1, 0, 1, 0, 0, 16, 0, 0, 0, 0, 1}); err != nil {
			return err
		}
		if _, err := binaryTestRead(c); err == nil {
			return errors.New("unsupported peer received REQUEST")
		}
		return nil
	})
	config.TLSConfig, config.RootCAPEM = p.binary, p.rootPEM
	client := binaryClient(t, config)
	_, err := client.Operation(context.Background(), "PATCH", "/v1/collections/a/documents/b", "application/json", []byte(`{}`), nil)
	var uncertain *y.BinaryUncertainWriteError
	if !errors.Is(err, y.ErrBinaryUnsupported) || errors.As(err, &uncertain) {
		t.Fatalf("legacy peer must fail before dispatch: %v", err)
	}
}
func operationReply(c net.Conn, body []byte, id []byte, mode byte, change func(map[int][]byte)) error {
	fields := binaryTestResponse(200, body, id)
	fields[13] = []byte{mode}
	if mode == 1 {
		fields[2] = []byte("application/x-ndjson")
		fields[3] = make([]byte, 8)
		fields[4] = make([]byte, 8)
	}
	if change != nil {
		change(fields)
	}
	meta := binaryTestMeta(fields)
	meta[1] = 2
	if err := binaryTestSend(c, 3, meta); err != nil {
		return err
	}
	if len(body) > 0 {
		if err := binaryTestSend(c, 4, body); err != nil {
			return err
		}
	}
	return binaryTestSend(c, 5, nil)
}
func TestBinaryOperationRawQuery(t *testing.T) {
	source := []byte(`{"filter":{"n":18446744073709551615},"limit":1}`)
	body := []byte(`{"revision":"0123456789abcdef","documents":[{"n":18446744073709551615}],"next_after":"one"}`)
	client := operationPeer(t, func(c net.Conn, fields map[int][]byte, actual []byte) error {
		if !bytes.Equal(actual, source) || string(fields[5]) != "Bearer read-synthetic" || fields[1][0] != 5 || string(fields[2]) != "/v1/query/a" || string(fields[3]) != "application/json" {
			return errors.New("raw query identity changed")
		}
		return operationReply(c, body, fields[8], 0, nil)
	})
	result, err := client.Operation(context.Background(), "POST", "/v1/query/a", "application/json", source, nil)
	if err != nil || !bytes.Equal(result.Body, body) {
		t.Fatalf("raw query changed: %s %v", result.Body, err)
	}
}
func TestBinaryOperationResponseDepthBudget(t *testing.T) {
	mapping := `{"deep":` + strings.Repeat(`{"n":`, 63) + `{}` + strings.Repeat(`}`, 64)
	values := []string{`{"value":` + strings.Repeat(`[`, 64) + `0` + strings.Repeat(`]`, 64) + `}`, mapping, `{"edge":[` + mapping + `]}`}
	for index, value := range values {
		t.Run(string(rune('a'+index)), func(t *testing.T) {
			body := []byte(`{"revision":"0123456789abcdef","documents":[` + value + `]}`)
			client := operationPeer(t, func(c net.Conn, fields map[int][]byte, _ []byte) error {
				return operationReply(c, body, fields[8], 0, nil)
			})
			result, err := client.Operation(context.Background(), "POST", "/v1/query/a", "application/json", []byte(`{}`), nil)
			if err != nil || !bytes.Equal(result.Body, body) {
				t.Fatalf("native domain edge response was rejected: %v", err)
			}
		})
	}
	for _, value := range []string{strings.Repeat(`[`, 80) + `0` + strings.Repeat(`]`, 80), `1,"v":2`, `"` + string([]byte{255}) + `"`} {
		body := []byte(`{"revision":"0123456789abcdef","v":` + value + `}`)
		client := operationPeer(t, func(c net.Conn, fields map[int][]byte, _ []byte) error {
			return operationReply(c, body, fields[8], 0, nil)
		})
		if _, err := client.Operation(context.Background(), "POST", "/v1/query/a", "application/json", []byte(`{}`), nil); !errors.Is(err, y.ErrBinaryProtocol) {
			t.Fatalf("response guard accepted invalid JSON: %v", err)
		}
	}
	source := []byte(`{"operations":[{}],"v":` + strings.Repeat(`[`, 64) + `0` + strings.Repeat(`]`, 64) + `}`)
	client := operationPeer(t, func(c net.Conn, fields map[int][]byte, _ []byte) error {
		return operationReply(c, []byte(`{"status":"committed","operations":1,"revision":"0123456789abcdef"}`), fields[8], 0, nil)
	})
	_, err := client.Operation(context.Background(), "POST", "/v1/transactions", "application/json", source, nil)
	var uncertain *y.BinaryUncertainWriteError
	if !errors.As(err, &uncertain) || !errors.Is(err, y.ErrBinaryProtocol) {
		t.Fatalf("transaction domain depth guard changed: %v", err)
	}
}
func TestBinaryOperationMalformedModeAndTransactionCount(t *testing.T) {
	for _, fault := range []string{"missing-mode", "stream-mode", "wrong-id", "wrong-identity", "transaction-count"} {
		t.Run(fault, func(t *testing.T) {
			client := operationPeer(t, func(c net.Conn, fields map[int][]byte, _ []byte) error {
				count := "1"
				if fault == "transaction-count" {
					count = "2"
				}
				return operationReply(c, []byte(`{"status":"committed","operations":`+count+`,"revision":"0123456789abcdef"}`), fields[8], 0, func(m map[int][]byte) {
					switch fault {
					case "missing-mode":
						delete(m, 13)
					case "stream-mode":
						m[13] = []byte{1}
					case "wrong-id":
						m[12] = bytes.Repeat([]byte{1}, 16)
					case "wrong-identity":
						m[7] = []byte("other")
					}
				})
			})
			_, err := client.Operation(context.Background(), "POST", "/v1/transactions", "application/json", []byte(`{"operations":[{"collection":"a","document":"b","delete":true}]}`), map[string]string{"If-Match": ""})
			var uncertain *y.BinaryUncertainWriteError
			if !errors.As(err, &uncertain) {
				t.Fatalf("unvalidated transaction receipt accepted: %v", err)
			}
			envelope := uncertain.Envelope()
			if envelope.Method != "POST" || envelope.Target != "/v1/transactions" || envelope.ContentType != "application/json" || envelope.Conditions["If-Match"] != "" {
				t.Fatal("uncertainty identity lost")
			}
		})
	}
}

// Reflection keeps the unfixed client buildable, so missing functionality is an
// ordinary behavioral assertion rather than a compiler/import failure.
func TestBinaryOperationPublicAPI(t *testing.T) {
	c := &y.BinaryClient{}
	operation := reflect.ValueOf(c).MethodByName("Operation")
	if !operation.IsValid() {
		t.Fatal("public finite operation API is required")
	}
	result := operation.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf("POST"), reflect.ValueOf("/metrics"), reflect.ValueOf("application/json"), reflect.ValueOf([]byte("{}")), reflect.ValueOf(map[string]string{})})
	if result[1].IsNil() {
		t.Fatal("non-operation target must fail before network admission")
	}
}
