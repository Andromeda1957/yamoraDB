package yamora_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	y "github.com/Andromeda1957/yamldb/yamora/drivers/go"
)

func nativeClient(t *testing.T, options ...string) *y.Client {
	return nativeClientWithTLS(t, nil, options...)
}

func TestNativeOnlineIndexBuild(t *testing.T) {
	client := nativeClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	source := []byte("# rollback guide\r\nname: first\r\nn: 9007199254740993\r\n")
	if _, err := client.Put(ctx, "examples", "one", source, y.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	catalog, err := client.Indexes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	job, err := client.StartIndexBuild(ctx, []y.Index{{Collection: "examples", Name: "words", Fields: []string{"$source"}, Type: "text"}}, catalog.Revision)
	if err != nil {
		t.Fatal(err)
	}
	done, err := client.WaitIndexBuild(ctx, job.ID)
	if err != nil || done.Status != "succeeded" || done.DocumentsScanned < 1 {
		t.Fatalf("%+v %v", done, err)
	}
	if _, err = client.Put(ctx, "examples", "later", []byte("name: later\n"), y.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	observed, err := client.IndexBuild(ctx, job.ID)
	if err != nil || observed.Revision != done.Revision {
		t.Fatalf("%+v %v", observed, err)
	}
	result, err := client.Search(ctx, "examples", y.Search{Index: "words", Text: "rollback"})
	if err != nil || len(result.Documents) != 1 || !strings.Contains(string(result.Documents[0].Value), "9007199254740993") {
		t.Fatalf("%+v %v", result, err)
	}
	if _, err = client.CancelIndexBuild(ctx, job.ID); err == nil {
		t.Fatal("completed build was cancellable")
	}
	if _, err = client.StartIndexBuild(ctx, []y.Index{}, catalog.Revision); err == nil {
		t.Fatal("stale guarded build was accepted")
	}
	replica := nativeClient(t, "--replica")
	if _, err = replica.StartIndexBuild(ctx, []y.Index{}, ""); err == nil {
		t.Fatal("replica accepted catalog mutation")
	}
}

func nativeClientWithTLS(t *testing.T, secure *tls.Config, options ...string) *y.Client {
	t.Helper()
	binary := os.Getenv("YAMORA_TEST_BINARY")
	if binary == "" {
		t.Skip("set YAMORA_TEST_BINARY to run the native integration contract")
	}
	root := t.TempDir()
	database := filepath.Join(root, "database")
	if err := os.Mkdir(database, 0700); err != nil {
		t.Fatal(err)
	}
	read, write := strings.Repeat("r", 32), strings.Repeat("w", 32)
	for name, token := range map[string]string{"read.token": read, "write.token": write} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(token), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	if output, err := exec.CommandContext(ctx, binary, "--data-dir", database, "--init-disk", "--validate-only").CombinedOutput(); err != nil {
		t.Fatalf("initialize: %v %s", err, output)
	}
	arguments := []string{"--data-dir", database, "--port", "0", "--auth-token-file", filepath.Join(root, "read.token"), "--write-auth-token-file", filepath.Join(root, "write.token")}
	cmd := exec.CommandContext(ctx, binary, append(arguments, options...)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(root, "daemon.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = log
	if err = cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); cmd.Wait(); log.Close() })
	type bannerResult struct {
		line string
		err  error
	}
	ready := make(chan bannerResult, 1)
	go func() { line, err := bufio.NewReader(stdout).ReadString('\n'); ready <- bannerResult{line, err} }()
	var line string
	select {
	case result := <-ready:
		if result.err != nil {
			t.Fatal(result.err)
		}
		line = result.line
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	match := regexp.MustCompile(`^yamora listening on (127\.0\.0\.1:[0-9]+) `).FindStringSubmatch(line)
	if match == nil {
		t.Fatalf("invalid startup banner: %q", line)
	}
	client, err := y.New(y.Config{Address: netip.MustParseAddrPort(match[1]), ReadToken: read, WriteToken: write, Timeout: 10 * time.Second, TLSConfig: secure})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func TestNativeReplicaBootstrapAndIncrementalResume(t *testing.T) {
	source := nativeClient(t)
	destination := nativeClient(t, "--replica")
	ctx := context.Background()
	original := "# mirrored exactly\r\nvalue: old\r\n"
	if _, err := source.Put(ctx, "examples", "one", []byte(original), y.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	// Escaped envelopes exceed one request in total; the bootstrap must flush
	// bounded batches while preserving the literal source bytes.
	large := "value: |\n  " + strings.Repeat(`\`, 180000) + "\n"
	for i := 0; i < 8; i++ {
		if _, err := source.Put(ctx, "examples", fmt.Sprintf("large-%d", i), []byte(large), y.WriteOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := destination.ReplicateFrom(ctx, source); err != nil {
		t.Fatal(err)
	}
	copied, err := destination.Get(ctx, "examples", "large-7", "")
	if err != nil || string(copied.Source) != large {
		t.Fatalf("large exact source: %v", err)
	}
	mirrored, err := destination.Get(ctx, "examples", "one", "")
	if err != nil || string(mirrored.Source) != original {
		t.Fatalf("%q %v", mirrored.Source, err)
	}
	changed := "# newer\r\nvalue: updated\r\n"
	if _, err = source.Put(ctx, "examples", "one", []byte(changed), y.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	result, err := destination.ReplicateChangesFrom(ctx, source)
	if err != nil || result.Commits != 1 {
		t.Fatalf("%+v %v", result, err)
	}
	mirrored, err = destination.Get(ctx, "examples", "one", result.Revision)
	if err != nil || string(mirrored.Source) != changed {
		t.Fatalf("%q %v", mirrored.Source, err)
	}
	resumed, err := destination.ReplicateChangesFrom(ctx, source)
	if err != nil || resumed.Commits != 0 || *resumed.After != *result.After {
		t.Fatalf("%+v %v", resumed, err)
	}
	if _, err = source.SetIndexes(ctx, []y.Index{}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err = destination.ReplicateChangesFrom(ctx, source); !errors.Is(err, y.ErrResnapshotRequired) {
		t.Fatalf("reset: %v", err)
	}
	if _, err = destination.ReplicateFrom(ctx, source); err != nil {
		t.Fatal(err)
	}
}

func TestNativeSearchAndTextReplication(t *testing.T) {
	source, target := nativeClient(t), nativeClient(t, "--replica")
	ctx := context.Background()
	original := "# Straße deploy\r\nname: Alpha\r\nn: 1\r\n"
	if _, err := source.Put(ctx, "examples", "one", []byte(original), y.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := source.CreateIndex(ctx, y.Index{Collection: "examples", Name: "words", Fields: []string{"$source"}, Type: "text"}); err != nil {
		t.Fatal(err)
	}
	if _, err := source.CreateIndex(ctx, y.Index{Collection: "examples", Name: "n", Fields: []string{"n"}}); err != nil {
		t.Fatal(err)
	}
	catalog, err := source.Indexes(ctx)
	if err != nil || len(catalog.Indexes) != 2 || catalog.Indexes[0].Type != "text" {
		t.Fatalf("%+v %v", catalog, err)
	}
	check := func(client *y.Client, text string, count int) {
		t.Helper()
		result, err := client.Search(ctx, "examples", y.Search{Index: "words", Text: text})
		if err != nil || len(result.Documents) != count {
			t.Fatalf("%+v %v", result, err)
		}
		if count > 0 && result.Documents[0].ID != "one" {
			t.Fatal(result)
		}
	}
	check(source, "STRASSE deploy", 1)
	if _, err := target.ReplicateFrom(ctx, source); err != nil {
		t.Fatal(err)
	}
	check(target, "strasse alpha", 1)
	copied, err := target.Get(ctx, "examples", "one", "")
	if err != nil || string(copied.Source) != original {
		t.Fatalf("%q %v", copied.Source, err)
	}
	if _, err := source.Patch(ctx, "examples", "one", map[string]any{"$set": map[string]any{"name": "Beta"}}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := target.ReplicateChangesFrom(ctx, source); err != nil {
		t.Fatal(err)
	}
	check(target, "alpha", 0)
	check(target, "strasse beta", 1)
}

func TestNativeAggregation(t *testing.T) {
	client := nativeClient(t)
	ctx := context.Background()
	for i, source := range []string{"country: US\nrating: 2400\n", "country: GB\nrating: 2600\n", "country: US\nrating: 2800\n"} {
		if _, err := client.Put(ctx, "people", fmt.Sprintf("p%d", i), []byte(source), y.WriteOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	pipeline := []map[string]any{
		{"$group": map[string]any{"_id": "$country", "n": map[string]any{"$sum": 1}, "total": map[string]any{"$sum": "$rating"}}},
		{"$sort": y.Sort{{Path: "total", Descending: true}, {Path: "_id"}}},
	}
	result, err := client.Aggregate(ctx, "people", pipeline, "")
	if err != nil || len(result.Documents) != 2 || result.DocumentsExamined != 3 {
		t.Fatalf("%+v %v", result, err)
	}
	var top struct {
		ID    string `json:"_id"`
		N     int    `json:"n"`
		Total int    `json:"total"`
	}
	if err := json.Unmarshal(result.Documents[0], &top); err != nil || top.ID != "US" || top.N != 2 || top.Total != 5200 {
		t.Fatalf("%+v %v", top, err)
	}
	if _, err := client.Aggregate(ctx, "people", pipeline, result.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Patch(ctx, "people", "p0", map[string]any{"$inc": map[string]any{"rating": 1}}, ""); err != nil {
		t.Fatal(err)
	}
	var response *y.HTTPError
	if _, err := client.Aggregate(ctx, "people", pipeline, result.Revision); !errors.As(err, &response) || response.Status != 412 {
		t.Fatalf("stale aggregation: %v", err)
	}
}

func TestNativeDocumentsIndexesTransactionsAndChanges(t *testing.T) {
	client := nativeClient(t)
	ctx := context.Background()
	ready, err := client.Ready(ctx)
	if err != nil || string(ready["storage"]) != `"native-disk-v2"` {
		t.Fatalf("%v %v", ready, err)
	}
	if _, err = client.Health(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = client.Stats(ctx); err != nil {
		t.Fatal(err)
	}
	metrics, err := client.Metrics(ctx)
	if err != nil || !strings.Contains(metrics, "yamldb_uptime_seconds") {
		t.Fatalf("metrics: %v", err)
	}
	checkpoint, err := client.Changes(ctx, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	source := "# original\r\nname: Alpha\r\nn: 1 # unchanged comment\r\n"
	created, err := client.Put(ctx, "examples", "one", []byte(source), y.WriteOptions{CreateOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	document, err := client.Get(ctx, "examples", "one", created.Revision)
	if err != nil || string(document.Source) != source {
		t.Fatalf("%q %v", document.Source, err)
	}
	updated, err := client.Patch(ctx, "examples", "one", map[string]any{"$inc": map[string]any{"n": 1}}, created.ETag)
	if err != nil || updated.ETag == created.ETag {
		t.Fatalf("%+v %v", updated, err)
	}
	_, err = client.Put(ctx, "examples", "one", []byte(source), y.WriteOptions{ETag: created.ETag})
	var remote *y.HTTPError
	if !errors.As(err, &remote) || remote.Status != 412 {
		t.Fatalf("stale ETag: %v", err)
	}
	if _, err = client.CreateIndex(ctx, y.Index{Collection: "examples", Name: "by-name", Fields: []string{"name"}, Unique: true}); err != nil {
		t.Fatal(err)
	}
	indexes, err := client.Indexes(ctx)
	if err != nil || len(indexes.Indexes) != 1 {
		t.Fatalf("%+v %v", indexes, err)
	}
	before, err := client.Changes(ctx, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	next := "name: Beta\nn: 9223372036854775807\n"
	receipt, err := client.Transaction(ctx, []y.Operation{
		{Collection: "examples", Document: "two", Put: &next, CreateOnly: true},
		{Collection: "examples", Document: "one", Patch: map[string]any{"$set": map[string]any{"name": "Omega"}}},
	}, indexes.Revision)
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.Query(ctx, "examples", y.Query{Filter: map[string]any{"name": "Beta"}, Explain: true, Limit: 1})
	if err != nil || len(page.Documents) != 1 || !strings.Contains(string(page.Documents[0].Value), "9223372036854775807") || page.Revision != receipt.Revision {
		t.Fatalf("%+v %v", page, err)
	}
	count, err := client.Count(ctx, "examples", nil, page.Revision)
	if err != nil || count != 2 {
		t.Fatalf("count=%d %v", count, err)
	}
	seen := 0
	if err = client.Documents(ctx, "examples", page.Revision, func(string) error { seen++; return nil }); err != nil || seen != 2 {
		t.Fatalf("seen=%d %v", seen, err)
	}
	var frames []y.Change
	after, err := client.FollowChanges(ctx, before.NextAfter, y.FollowOptions{}, func(frame y.Change) error { frames = append(frames, frame); return nil })
	if err != nil || len(frames) != 1 || len(frames[0].Operations) != 2 {
		t.Fatalf("%+v %v", frames, err)
	}
	expected := errors.New("consumer failed")
	unchanged, err := client.FollowChanges(ctx, before.NextAfter, y.FollowOptions{}, func(y.Change) error { return expected })
	if !errors.Is(err, expected) || unchanged != before.NextAfter {
		t.Fatalf("%s %v", unchanged, err)
	}
	if err = client.Delete(ctx, "examples", "two", ""); err != nil {
		t.Fatal(err)
	}
	delta, err := client.Changes(ctx, after, 100)
	if err != nil || len(delta.Transactions) != 1 || !delta.Transactions[0].Operations[0].Delete {
		t.Fatalf("%+v %v", delta, err)
	}
	_, err = client.FollowChanges(ctx, checkpoint.NextAfter, y.FollowOptions{}, func(y.Change) error { return nil })
	if !errors.Is(err, y.ErrResnapshotRequired) {
		t.Fatalf("catalog rebuild should require snapshot: %v", err)
	}
	if _, err = client.DropIndex(ctx, "examples", "by-name"); err != nil {
		t.Fatal(err)
	}
}

func TestNativeLargeDocuments(t *testing.T) {
	client := nativeClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	source := []byte("# exact large YAML\r\nn: 9007199254740993\r\ntext: " + strings.Repeat("é", 1600000) + "\r\n")
	checkpoint, err := client.Changes(ctx, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Put(ctx, "examples", "large", source, y.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	document, err := client.Get(ctx, "examples", "large", "")
	if err != nil || string(document.Source) != string(source) {
		t.Fatalf("source mismatch: %v", err)
	}
	changes, err := client.Changes(ctx, checkpoint.NextAfter, 100)
	if err != nil || len(changes.Transactions) != 1 || changes.Transactions[0].ResnapshotRequired || len(changes.Transactions[0].Operations) != 2 || changes.Transactions[0].Operations[1].Put == nil || string(*changes.Transactions[0].Operations[1].Put) != string(source) {
		t.Fatalf("large feed: %v", err)
	}
	replica := nativeClient(t, "--replica")
	if _, err = replica.ReplicateFrom(ctx, client); err != nil {
		t.Fatal(err)
	}
	if _, err = client.Patch(ctx, "examples", "large", map[string]any{"$inc": map[string]any{"n": 1}}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err = replica.ReplicateChangesFrom(ctx, client); err != nil {
		t.Fatal(err)
	}
	document, err = replica.Get(ctx, "examples", "large", "")
	expected := strings.Replace(string(source), "9007199254740993", "9007199254740994", 1)
	if err != nil || string(document.Source) != expected {
		t.Fatalf("replica source mismatch: %v", err)
	}
}

func TestNativeContinuousChangeStream(t *testing.T) {
	client := nativeClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	checkpoint, err := client.Changes(ctx, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan y.Change, 1)
	type outcome struct {
		after string
		err   error
	}
	finished := make(chan outcome, 1)
	go func() {
		after, err := client.StreamChanges(ctx, checkpoint.NextAfter, y.StreamOptions{Duration: 1500 * time.Millisecond, Heartbeat: 100 * time.Millisecond}, func(frame y.Change) error { seen <- frame; return nil })
		finished <- outcome{after, err}
	}()
	// A commit preceding subscription registration must still be delivered.
	source := []byte("# exact streamed source\r\ntext: " + strings.Repeat("é", 1600000) + "\r\n")
	if _, err = client.Put(ctx, "examples", "large", source, y.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	select {
	case frame := <-seen:
		if frame.ResnapshotRequired || len(frame.Operations) != 2 || frame.Operations[1].Put == nil || *frame.Operations[1].Put != string(source) {
			t.Fatal("incomplete stream frame")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	result := <-finished
	position, err := client.Changes(ctx, "", 100)
	if err != nil || result.err != nil || result.after != position.Checkpoint {
		t.Fatalf("%s %v %v", result.after, result.err, err)
	}
	stop := errors.New("consumer did not commit")
	after, err := client.StreamChanges(ctx, checkpoint.NextAfter, y.StreamOptions{Duration: 100 * time.Millisecond}, func(y.Change) error { return stop })
	if !errors.Is(err, stop) || after != checkpoint.NextAfter {
		t.Fatalf("advanced past failed callback: %s %v", after, err)
	}
	interrupted, stopSession := context.WithCancel(context.Background())
	stopSession()
	if _, err = client.StreamChanges(interrupted, result.after, y.StreamOptions{}, func(y.Change) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
