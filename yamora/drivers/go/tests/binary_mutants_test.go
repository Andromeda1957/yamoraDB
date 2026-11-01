package yamora_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Compile and execute deliberately weakened COPIES. Build/sanitizer/fixture
// errors never count as a killed behavioral mutant. Restore each exact source
// and run the same test green. The supplied daemon is read-only throughout.
func TestBinaryBehavioralMutants(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("test source path unavailable")
	}
	source := filepath.Dir(filepath.Dir(file))
	root := t.TempDir()
	tests := filepath.Join(root, "tests")
	if err := os.Mkdir(tests, 0700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".go") && entry.Name() != "go.mod") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(source, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(root, entry.Name()), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"binary_fixture_test.go", "binary_wire_test.go", "binary_native_test.go", "binary_operations_test.go"} {
		body, err := os.ReadFile(filepath.Join(source, "tests", name))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(tests, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(t *testing.T, selector string, red bool, diagnostic string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "go", "test", "./tests", "-count=1", "-timeout=20s", "-run", selector, "-v")
		command.Dir = root
		output, err := command.CombinedOutput()
		text := string(output)
		if ctx.Err() != nil {
			t.Fatal("mutant infrastructure deadline", ctx.Err())
		}
		for _, bad := range []string{"[build failed]", "undefined:", "panic:", "Sanitizer", "runtime error:", "fixture:", "peer did not join", "native shutdown:", "native initialize failed", "binary listener missing"} {
			if strings.Contains(text, bad) {
				t.Fatalf("invalid mutant evidence (%s): %s", bad, text)
			}
		}
		if red {
			if err == nil || !strings.Contains(text, "--- FAIL:") || !strings.Contains(text, diagnostic) {
				t.Fatalf("mutant survived or failed for wrong reason: %v\n%s", err, text)
			}
		} else if err != nil || !strings.Contains(text, "PASS\n") {
			t.Fatalf("restored behavioral green failed: %v\n%s", err, text)
		}
	}
	cases := []struct{ name, file, old, new, selector, diagnostic string }{
		{"operation-count", "binary_operations.go", "count != len(operations)", "false", "^TestBinaryOperationMalformedModeAndTransactionCount$/^transaction-count$", "unvalidated transaction receipt accepted"},
		{"operation-identity", "binary_operations.go", `(r.collection != "" && r.collection != op.collection) || (r.document != "" && r.document != op.document)`, "false", "^TestBinaryOperationMalformedModeAndTransactionCount$/^wrong-identity$", "unvalidated transaction receipt accepted"},
		{"wrong-stream", "binary_wire.go", "if f.stream != 1 || n == 0 || n > 2048", "if (f.stream != 1 && f.stream != 3) || n == 0 || n > 2048", "^TestBinaryHostileVerifiedPeer$/^wrong-stream$", "expected original typed uncertainty"},
		{"missing-id", "binary_reply.go", "r.id != id || ", "", "^TestBinaryHostileVerifiedPeer$/^missing-id$", "expected original typed uncertainty"},
		{"receipt-etag", "binary_reply.go", ` || values["etag"] != r.etag`, "", "^TestBinaryHostileVerifiedPeer$/^etag$", "expected original typed uncertainty"},
		{"receipt-revision", "binary_reply.go", ` || values["revision"] != r.revision`, "", "^TestBinaryHostileVerifiedPeer$/^revision$", "expected original typed uncertainty"},
		{"receipt-status", "binary_reply.go", "r.status != 200 && r.status != 201", "r.status != 200 && r.status != 201 && r.status != 202", "^TestBinaryHostileVerifiedPeer$/^wrong-status$", "expected original typed uncertainty"},
		{"ack-cap", "binary_reply.go", " || r.length > 4096", "", "^TestBinaryHostileVerifiedPeer$/^ack-limit$", "expected original typed uncertainty"},
		{"terminal-end", "binary_reply.go", "r.body = append(r.body, f.payload...)", "r.body = append(r.body, f.payload...)\nif uint64(len(r.body))==r.length && method==3 {if err:=r.receipt(collection,document);err!=nil{return r,err};return r,nil}", "^TestBinaryHostileVerifiedPeer$/^partial-end$", "expected original typed uncertainty"},
		{"source-ownership", "binary.go", "source = bytes.Clone(source)", "source = source", "^TestBinaryUncertaintyOwnsSourceAfterReturn$", "uncertainty retained caller-owned source"},
		{"mandatory-alpn", "binary.go", "state.NegotiatedProtocol != binaryALPN || ", "", "^TestBinaryRejectsAbsentALPNAndIncompatibleHello$/^absent-alpn$", "unsupported peer accepted"},
		{"single-deadline", "binary.go", "context.WithTimeout(parent, c.timeout)", "context.WithTimeout(parent, c.timeout*2)", "^TestBinaryContextOneDeadlineAndCancellation$/^response$/^cancel=false$", "deadline was reset by a phase"},
		{"prompt-cancel", "binary.go", "context.AfterFunc(ctx,", "context.AfterFunc(context.Background(),", "^TestBinaryContextOneDeadlineAndCancellation$/^hello$/^cancel=true$", "cancellation did not promptly close its own socket"},
		{"large-source", "binary.go", "len(source) > MaxDocumentBytes", "len(source) > 256*1024", "^TestBinaryNativeSixteenMiBAndLegacyProfile$", "invalid document size or UTF-8"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(root, test.file)
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(original), test.old) != 1 {
				t.Fatal("mutant substitution is stale; not behavioral evidence")
			}
			if err = os.WriteFile(path, []byte(strings.Replace(string(original), test.old, test.new, 1)), 0600); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.WriteFile(path, original, 0600); err != nil {
					t.Error(err)
				}
			}()
			run(t, test.selector, true, test.diagnostic)
			if err = os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			run(t, test.selector, false, "")
		})
	}
}
