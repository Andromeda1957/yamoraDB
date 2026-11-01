package yamora_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	y "github.com/Andromeda1957/yamoraDB/yamora/drivers/go"
)

func TestNativeStreamReplicationLiveCommitAndResume(t *testing.T) {
	source, target := nativeClient(t), nativeClient(t, "--replica")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := target.ReplicateFrom(ctx, source); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		result y.ReplicationResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := target.StreamReplication(ctx, source, y.StreamOptions{Duration: 1500 * time.Millisecond, Heartbeat: 100 * time.Millisecond}, func(receipt y.ReplicaPosition) error {
			position, err := target.ReplicationStatus(ctx)
			if err != nil {
				return err
			}
			if *position.After != *receipt.After || position.Revision != receipt.Revision {
				return errors.New("receipt preceded durable publication")
			}
			return nil
		})
		done <- outcome{result, err}
	}()
	for {
		stats, err := source.Stats(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var active int
		if err = json.Unmarshal(stats["active_change_streams"], &active); err != nil {
			t.Fatal(err)
		}
		if active != 0 {
			break
		}
		select {
		case <-time.After(5 * time.Millisecond):
		case result := <-done:
			t.Fatalf("session ended before subscription: %+v", result)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	exact := []byte("# streamed replica\r\ntext: " + strings.Repeat("Ω", 65536) + "\r\n")
	if _, err := source.Put(ctx, "examples", "one", exact, y.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	result := <-done
	if result.err != nil || result.result.Commits != 1 {
		t.Fatalf("%+v %v", result.result, result.err)
	}
	got, err := target.Get(ctx, "examples", "one", result.result.Revision)
	if err != nil || string(got.Source) != string(exact) {
		t.Fatalf("exact source: %v", err)
	}
	stop := errors.New("stop receipt visitor")
	for _, value := range []string{"next", "last"} {
		if _, err = source.Put(ctx, "examples", "one", []byte("value: "+value+"\n"), y.WriteOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	first, err := target.StreamReplication(ctx, source, y.StreamOptions{Duration: 100 * time.Millisecond, Limit: 1}, func(y.ReplicaPosition) error { return stop })
	if !errors.Is(err, stop) || first.Commits != 1 {
		t.Fatalf("visitor result: %+v %v", first, err)
	}
	position, err := target.ReplicationStatus(ctx)
	if err != nil || *position.After != *first.After {
		t.Fatalf("committed visitor failure: %+v %v", position, err)
	}
	resumed, err := target.StreamReplication(ctx, source, y.StreamOptions{Duration: 100 * time.Millisecond}, nil)
	if err != nil || resumed.Commits != 1 || *resumed.After == *first.After {
		t.Fatalf("resume: %+v %v", resumed, err)
	}
}

func TestNativeStreamReplicationVisitorCannotMutateCheckpoint(t *testing.T) {
	source, target := nativeClient(t), nativeClient(t, "--replica")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := target.ReplicateFrom(ctx, source); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"one", "two"} {
		if _, err := source.Put(ctx, "examples", value, []byte("value: "+value+"\n"), y.WriteOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	result, err := target.StreamReplication(ctx, source, y.StreamOptions{Duration: 100 * time.Millisecond}, func(receipt y.ReplicaPosition) error {
		*receipt.After = "caller-owned receipt"
		return nil
	})
	if err != nil || result.Commits != 2 {
		t.Fatalf("mutated progress: %+v %v", result, err)
	}
	checkpoint, err := source.Changes(ctx, "", 100)
	if err != nil || *result.After != checkpoint.Checkpoint {
		t.Fatalf("result checkpoint: %+v %v", result, err)
	}
}

func TestNativeStreamReplicationBootstrapResetAndCancellation(t *testing.T) {
	source, target := nativeClient(t), nativeClient(t, "--replica")
	ctx := context.Background()
	if _, err := target.StreamReplication(ctx, source, y.StreamOptions{}, nil); !errors.Is(err, y.ErrResnapshotRequired) {
		t.Fatal(err)
	}
	if _, err := target.StreamReplication(ctx, target, y.StreamOptions{}, nil); err == nil {
		t.Fatal("accepted self-replication")
	}
	before, err := target.ReplicateFrom(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = source.SetIndexes(ctx, []y.Index{}, ""); err != nil {
		t.Fatal(err)
	}
	result, err := target.StreamReplication(ctx, source, y.StreamOptions{Duration: 100 * time.Millisecond}, nil)
	if !errors.Is(err, y.ErrResnapshotRequired) || result.Commits != 0 || *result.After != *before.After || result.Revision != before.Revision {
		t.Fatalf("reset: %+v %v", result, err)
	}
	if _, err = target.ReplicateFrom(ctx, source); err != nil {
		t.Fatal(err)
	}
	interrupted, stop := context.WithCancel(ctx)
	stop()
	if _, err = target.StreamReplication(interrupted, source, y.StreamOptions{}, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
