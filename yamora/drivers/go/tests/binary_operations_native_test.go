package yamora_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	y "github.com/Andromeda1957/yamldb/yamora/drivers/go"
)

func TestBinaryOperationsNative(t *testing.T) {
	native := newBinaryNative(t, false, true)
	client := binaryClient(t, native.config)
	ctx := context.Background()
	source := []byte("# exact spelling\r\nn: 9223372036854775807\r\ntext: hello\r\n")
	if _, err := client.Put(ctx, "operations", "one", source, y.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	first, err := client.Operation(ctx, "POST", "/v1/query/operations", "application/json", []byte(`{"limit":1}`), nil)
	if err != nil || !bytes.Contains(first.Body, []byte("9223372036854775807")) {
		t.Fatalf("raw numeric query: %s %v", first.Body, err)
	}
	patch, err := client.Operation(ctx, "PATCH", "/v1/collections/operations/documents/one", "application/json", []byte(`{"$set":{"text":"changed"}}`), nil)
	if err != nil || patch.ETag == "" {
		t.Fatalf("PATCH receipt: %+v %v", patch, err)
	}
	raw := "# transaction spelling\r\nn: 4\r\n"
	spec, _ := json.Marshal(map[string]any{"operations": []map[string]any{{"collection": "operations", "document": "two", "put": raw}}})
	tx, err := client.Operation(ctx, "POST", "/v1/transactions", "application/json", spec, nil)
	if err != nil || !bytes.Contains(tx.Body, []byte(`"operations":1`)) {
		t.Fatalf("transaction: %s %v", tx.Body, err)
	}
	got, err := client.Get(ctx, "operations", "two", "")
	if err != nil || string(got.Source) != raw {
		t.Fatal("transaction source changed", err)
	}
	page, err := client.Operation(ctx, "GET", "/v1/changes", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		After string `json:"next_after"`
	}
	if json.Unmarshal(page.Body, &data) != nil || data.After == "" {
		t.Fatal("checkpoint unavailable")
	}
	count := 0
	result, err := client.Feed(ctx, "/v1/changes/stream?after="+data.After+"&duration_ms=150&heartbeat_ms=100", func(page []byte) error {
		count++
		if !bytes.HasSuffix(page, []byte{'\n'}) {
			t.Error("incomplete page exposed")
		}
		return nil
	})
	if err != nil || count == 0 || result.ResumeAfter != data.After {
		t.Fatalf("finite feed: %+v %v pages=%d", result, err, count)
	}
	cancelled, cancel := context.WithCancel(ctx)
	defer cancel()
	prefix := 0
	_, err = client.Feed(cancelled, "/v1/changes/stream?after="+data.After, func([]byte) error { prefix++; cancel(); return nil })
	if !errors.Is(err, context.Canceled) || prefix != 1 {
		t.Fatalf("feed cancellation: %v %d", err, prefix)
	}
}
