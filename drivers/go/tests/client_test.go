package yamora_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	y "github.com/Andromeda1957/yamoraDB/drivers/go"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testClient(t *testing.T, handler http.HandlerFunc) *y.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	address, err := netip.ParseAddrPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	client, err := y.New(y.Config{Address: address, ReadToken: strings.Repeat("r", 32), WriteToken: strings.Repeat("w", 32)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func jsonResponse(w http.ResponseWriter, value string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-YamlDB-Revision", "0123456789abcdef")
	fmt.Fprint(w, value)
}

func TestReplicationSourceGuard(t *testing.T) {
	ctx := context.Background()
	for _, capability := range []string{"false", "null", `"false"`, `"true"`, "0", "1", "[]", "{}"} {
		t.Run(capability, func(t *testing.T) {
			var targetCalls atomic.Int32
			source := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/readyz" {
					t.Errorf("guard read outside readiness: %s %s", r.Method, r.URL.Path)
				}
				jsonResponse(w, `{"revision":"0123456789abcdef","replication_policy_free":`+capability+`}`)
			})
			target := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				targetCalls.Add(1)
				w.WriteHeader(500)
			})
			check := func(err error) {
				t.Helper()
				if err == nil || errors.Is(err, y.ErrSchemaPolicyReplicationUnsupported) != (capability == "false") {
					t.Fatalf("wrong source refusal: %v", err)
				}
			}
			_, err := source.RequireReplicationSource(ctx)
			check(err)
			_, err = target.ReplicateFrom(ctx, source)
			check(err)
			_, err = target.FollowReplication(ctx, source, y.FollowOptions{}, nil)
			check(err)
			_, err = target.StreamReplication(ctx, source, y.StreamOptions{}, nil)
			check(err)
			if targetCalls.Load() != 0 {
				t.Fatal("refused source reached destination")
			}
		})
	}
	for _, field := range []string{"", `,"replication_policy_free":true`, `,"nested":{"replication_policy_free":false}`} {
		source := testClient(t, func(w http.ResponseWriter, r *http.Request) {
			jsonResponse(w, `{"revision":"0123456789abcdef"`+field+`}`)
		})
		if _, err := source.RequireReplicationSource(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReplicationSourceGuardRechecksBeforeFollowStage(t *testing.T) {
	ctx := context.Background()
	start := "v1." + strings.Repeat("a", 32) + ".0000000000000001"
	next := "v1." + strings.Repeat("a", 32) + ".0000000000000002"
	for _, capability := range []string{"false", "null", `"false"`} {
		var reads atomic.Int32
		source := testClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/readyz" {
				value := "true"
				if reads.Add(1) > 1 {
					value = capability
				}
				jsonResponse(w, `{"revision":"0123456789abcdef","replication_policy_free":`+value+`}`)
				return
			}
			jsonResponse(w, `{"revision":"0123456789abcdef","transactions":[{"token":"`+next+`","previous_revision":"0123456789abcdef","revision":"0123456789abcdef","resnapshot_required":false,"operations":[{"collection":"examples","document":"one","put":"n: 1"}]}],"next_after":"`+next+`","checkpoint":"`+next+`","oldest_after":"`+start+`","has_more":false}`)
		})
		var writes atomic.Int32
		target := testClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				writes.Add(1)
			}
			jsonResponse(w, `{"status":"following","revision":"0123456789abcdef","after":"`+start+`"}`)
		})
		result, err := target.FollowReplication(ctx, source, y.FollowOptions{}, nil)
		if err == nil || errors.Is(err, y.ErrSchemaPolicyReplicationUnsupported) != (capability == "false") || writes.Load() != 0 || result.Commits != 0 || reads.Load() != 2 {
			t.Fatalf("follow guard failed: %+v %v writes=%d reads=%d", result, err, writes.Load(), reads.Load())
		}
	}
}

func TestReplicationSourceGuardRechecksBeforeBootstrapPublication(t *testing.T) {
	ctx := context.Background()
	token := "v1." + strings.Repeat("a", 32) + ".0000000000000001"
	var reads atomic.Int32
	source := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/readyz":
			allowed := reads.Add(1) == 1
			jsonResponse(w, fmt.Sprintf(`{"revision":"0123456789abcdef","storage":"native-disk-v2","revision_scheme":"xor-fnv-v2","change_feed":true,"replication_policy_free":%t}`, allowed))
		case "/v1/changes":
			jsonResponse(w, `{"revision":"0123456789abcdef","transactions":[],"next_after":"`+token+`","checkpoint":"`+token+`","oldest_after":"`+token+`","has_more":false}`)
		case "/v1/collections":
			jsonResponse(w, `{"collections":[]}`)
		default:
			t.Errorf("unexpected source read: %s", r.URL.Path)
			w.WriteHeader(500)
		}
	})
	paths := make(chan string, 8)
	target := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		paths <- r.URL.Path
		if r.URL.Path == "/v1/replication/begin" {
			jsonResponse(w, `{"session":"stage-one","revision":"0123456789abcdef"}`)
		} else {
			jsonResponse(w, `{"status":"uninitialized","revision":"0123456789abcdef","after":null}`)
		}
	})
	_, err := target.ReplicateFrom(ctx, source)
	var observed []string
	for len(paths) > 0 {
		observed = append(observed, <-paths)
	}
	if !errors.Is(err, y.ErrSchemaPolicyReplicationUnsupported) || strings.Join(observed, ",") != "/v1/replication/status,/v1/replication/begin,/v1/replication/abort" || reads.Load() != 2 {
		t.Fatalf("bootstrap published after policy change: %v %v ready=%d", observed, err, reads.Load())
	}
}

func TestAggregateReadContract(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/aggregate/examples" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("r", 32) {
			t.Error("invalid aggregation request or credential")
		}
		jsonResponse(w, `{"documents":[{"n":9007199254740993}],"revision":"0123456789abcdef","documents_examined":3}`)
	})
	result, err := client.Aggregate(context.Background(), "examples", []map[string]any{{"$count": "n"}}, "0123456789abcdef")
	if err != nil || result.DocumentsExamined != 3 || len(result.Documents) != 1 || string(result.Documents[0]) != `{"n":9007199254740993}` {
		t.Fatalf("%+v %v", result, err)
	}
	for _, response := range []string{
		`{"documents":null,"revision":"0123456789abcdef","documents_examined":3}`,
		`{"documents":[1],"revision":"0123456789abcdef","documents_examined":3}`,
		`{"documents":[],"revision":"0123456789abcdef"}`,
		`{"documents":[],"revision":"0123456789abcdef","documents_examined":-1}`,
		`{"documents":[],"revision":"1111111111111111","documents_examined":3}`,
	} {
		broken := testClient(t, func(w http.ResponseWriter, r *http.Request) { jsonResponse(w, response) })
		if _, err := broken.Aggregate(context.Background(), "examples", []map[string]any{{"$count": "n"}}, ""); err == nil {
			t.Errorf("accepted malformed aggregation response: %s", response)
		}
	}
}

func TestIndexBuildContract(t *testing.T) {
	id := strings.Repeat("a", 32)
	valid := `{"id":"` + id + `","status":"succeeded","phase":"done","documents_scanned":4,"transactions_replayed":2,"revision":"1111111111111111","error":"","cancel_requested":false}`
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			if r.URL.Path != "/v1/index-builds" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("w", 32) || r.Header.Get("If-Match") != `"0123456789abcdef"` {
				t.Error("invalid guarded build submission")
			}
		} else if r.URL.Path != "/v1/index-builds/"+id {
			t.Error("invalid job path")
		}
		if r.Method == "DELETE" && r.Header.Get("Authorization") != "Bearer "+strings.Repeat("w", 32) {
			t.Error("cancel must use the write credential")
		}
		if r.Method == "POST" || r.Method == "DELETE" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-YamlDB-Revision", "0123456789abcdef")
			w.WriteHeader(202)
		}
		jsonResponse(w, valid)
	})
	job, err := client.StartIndexBuild(context.Background(), []y.Index{}, "0123456789abcdef")
	if err != nil || job.ID != id || job.Revision != "1111111111111111" {
		t.Fatalf("%+v %v", job, err)
	}
	if _, err = client.WaitIndexBuild(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err = client.CancelIndexBuild(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	for _, response := range []string{
		strings.Replace(valid, `"transactions_replayed":2,`, ``, 1),
		strings.Replace(valid, `"transactions_replayed":2`, `"transactions_replayed":null`, 1),
		strings.Replace(valid, `"documents_scanned":4`, `"documents_scanned":-1`, 1),
		strings.Replace(valid, `"cancel_requested":false`, `"cancel_requested":1`, 1),
		strings.Replace(valid, `"phase":"done"`, `"phase":"scanning"`, 1),
		strings.Replace(valid, `"error":""`, `"error":"secret"`, 1),
		strings.Replace(valid, `"revision":"1111111111111111"`, `"revision":"bad"`, 1),
		strings.Replace(valid, id, strings.Repeat("b", 32), 1),
	} {
		broken := testClient(t, func(w http.ResponseWriter, r *http.Request) { jsonResponse(w, response) })
		if _, err = broken.IndexBuild(context.Background(), id); err == nil {
			t.Errorf("accepted malformed job: %s", response)
		}
	}
	for _, invalid := range []string{"", "../escape", strings.Repeat("A", 32)} {
		if _, err = client.IndexBuild(context.Background(), invalid); err == nil {
			t.Errorf("accepted job ID %q", invalid)
		}
	}
}

func TestSearchReadContractAndTextCatalog(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/indexes" {
			jsonResponse(w, `{"indexes":[{"collection":"examples","name":"words","fields":["$source"],"type":"text"}],"revision":"0123456789abcdef"}`)
			return
		}
		if r.Method != "POST" || r.URL.Path != "/v1/search/examples" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("r", 32) {
			t.Error("invalid search request")
		}
		jsonResponse(w, `{"documents":[{"id":"one","score":1,"value":{"n":9007199254740993}}],"revision":"0123456789abcdef","next_after":null,"documents_examined":1,"index_entries_examined":1}`)
	})
	result, err := client.Search(context.Background(), "examples", y.Search{Index: "words", Text: "guide"})
	if err != nil || len(result.Documents) != 1 || string(result.Documents[0].Value) != `{"n":9007199254740993}` {
		t.Fatalf("%+v %v", result, err)
	}
	catalog, err := client.Indexes(context.Background())
	if err != nil || len(catalog.Indexes) != 1 || catalog.Indexes[0].Type != "text" {
		t.Fatalf("%+v %v", catalog, err)
	}
}

func TestSearchRejectsMalformedResults(t *testing.T) {
	valid := `{"documents":[{"id":"one","score":1,"value":{}}],"revision":"0123456789abcdef","next_after":null,"documents_examined":1,"index_entries_examined":1}`
	for _, response := range []string{
		strings.Replace(valid, `"score":1`, `"score":0`, 1),
		strings.Replace(valid, `"score":1`, `"score":33`, 1),
		strings.Replace(valid, `"score":1`, `"score":1.5`, 1),
		strings.Replace(valid, `"value":{}`, `"other":{}`, 1),
		strings.Replace(valid, `"next_after":null`, `"next_after":"other"`, 1),
		strings.Replace(valid, `"next_after":null,`, ``, 1),
		strings.Replace(valid, `"documents_examined":1`, `"documents_examined":0`, 1),
		strings.Replace(valid, `"index_entries_examined":1`, `"index_entries_examined":null`, 1),
		strings.Replace(valid, `0123456789abcdef`, `1111111111111111`, 1),
		strings.Replace(valid, `[{"id":"one","score":1,"value":{}}]`, `[{"id":"two","score":1,"value":{}},{"id":"one","score":1,"value":{}}]`, 1),
	} {
		client := testClient(t, func(w http.ResponseWriter, r *http.Request) { jsonResponse(w, response) })
		if _, err := client.Search(context.Background(), "examples", y.Search{Index: "words", Text: "guide"}); err == nil {
			t.Errorf("accepted invalid search response: %s", response)
		}
	}
}

func TestCredentialsAndExactSource(t *testing.T) {
	var calls atomic.Int64
	source := "# retain comment\r\nvalue: 007\r\n"
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		token := strings.Repeat("r", 32)
		if r.Method == "PUT" {
			token = strings.Repeat("w", 32)
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("wrong credential")
		}
		if r.Method == "PUT" {
			if r.Header.Get("If-None-Match") != "*" {
				t.Error("create precondition missing")
			}
			jsonResponse(w, `{"status":"stored","etag":"fedcba9876543210","revision":"0123456789abcdef"}`)
			return
		}
		w.Header().Set("X-YamlDB-Revision", "0123456789abcdef")
		w.Header().Set("ETag", `"fedcba9876543210"`)
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		fmt.Fprint(w, source)
	})
	ctx := context.Background()
	result, err := client.Put(ctx, "examples", "one", []byte(source), y.WriteOptions{CreateOnly: true})
	if err != nil || result.ETag != "fedcba9876543210" {
		t.Fatalf("%+v %v", result, err)
	}
	doc, err := client.Get(ctx, "examples", "one", "")
	if err != nil || string(doc.Source) != source || doc.ETag != result.ETag {
		t.Fatalf("%+v %v", doc, err)
	}
	if calls.Load() != 2 {
		t.Fatal(calls.Load())
	}
}

func TestRejectsUnsafeConfiguration(t *testing.T) {
	for _, address := range []string{"0.0.0.0:80", "169.254.169.254:80", "8.8.8.8:80", "[::1]:80", "127.0.0.1:0", "100.64.0.1:80"} {
		if _, err := y.New(y.Config{Address: netip.MustParseAddrPort(address)}); err == nil {
			t.Error(address)
		}
	}
	for _, token := range []string{"short", strings.Repeat("x", 513), strings.Repeat("x", 32) + "\r\n"} {
		if _, err := y.New(y.Config{Address: netip.MustParseAddrPort("127.0.0.1:8765"), ReadToken: token}); err == nil {
			t.Error("invalid token accepted")
		}
	}
}

func TestRedirectAndUnknownWriteOutcomeNeverRetry(t *testing.T) {
	var calls atomic.Int64
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Location", "http://169.254.169.254/")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	_, err := client.Put(context.Background(), "a", "b", []byte("x: 1\n"), y.WriteOptions{})
	var remote *y.HTTPError
	if !errors.As(err, &remote) || remote.Status != 307 || calls.Load() != 1 {
		t.Fatalf("%v calls=%d", err, calls.Load())
	}
	calls.Store(0)
	broken := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		connection, _, _ := w.(http.Hijacker).Hijack()
		connection.Close()
	})
	if _, err := broken.Put(context.Background(), "a", "b", []byte("x: 1\n"), y.WriteOptions{}); err == nil || calls.Load() != 1 {
		t.Fatalf("%v calls=%d", err, calls.Load())
	}
}

func TestDocumentPaginationPinsRevisionAndRejectsStalePage(t *testing.T) {
	var calls atomic.Int64
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if calls.Load() == 1 {
			jsonResponse(w, `{"collection":"a","documents":["first"],"next_after":"first"}`)
		} else {
			if r.URL.Query().Get("after") != "first" {
				t.Error("cursor missing")
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-YamlDB-Revision", "fedcba9876543210")
			fmt.Fprint(w, `{"collection":"a","documents":["second"],"next_after":null}`)
		}
	})
	var seen []string
	err := client.Documents(context.Background(), "a", "", func(id string) error { seen = append(seen, id); return nil })
	if err == nil || len(seen) != 1 || seen[0] != "first" {
		t.Fatalf("%v %v", seen, err)
	}
}

func TestBoundedResponsesAndContextCancellation(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(y.MaxDocumentBytes+1))
		w.Header().Set("Content-Type", "application/yaml")
		w.Header().Set("X-YamlDB-Revision", "0123456789abcdef")
	})
	if _, err := client.Get(context.Background(), "a", "b", ""); err == nil {
		t.Fatal("oversized document accepted")
	}
	blocked := testClient(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := blocked.Ready(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestMalformedQueryResponseAndPrecision(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"documents":[{"id":"a","value":{"n":9223372036854775807}}],"matched":1,"next_after":null,"revision":"0123456789abcdef"}`)
	})
	result, err := client.Query(context.Background(), "a", y.Query{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(result.Documents[0].Value); !strings.Contains(got, "9223372036854775807") {
		t.Fatal(got)
	}
	bad := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"documents":[],"matched":0,"next_after":"../escape","revision":"0123456789abcdef"}`)
	})
	if _, err := bad.Query(context.Background(), "a", y.Query{}); err == nil {
		t.Fatal("invalid cursor accepted")
	}
}

func TestChangeFeedRejectsBrokenProgress(t *testing.T) {
	token := "v1." + strings.Repeat("a", 32) + ".0000000000000001"
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, fmt.Sprintf(`{"transactions":[],"next_after":%q,"checkpoint":%q,"oldest_after":%q,"revision":"0123456789abcdef","has_more":true}`, token, token, token))
	})
	if _, err := client.Changes(context.Background(), token, 100); err == nil {
		t.Fatal("non-progressing page accepted")
	}
}

func TestCompoundSortRetainsRequestedPriority(t *testing.T) {
	encoded, err := json.Marshal(y.Sort{{Path: "z", Descending: true}, {Path: "a"}})
	if err != nil || string(encoded) != `{"z":-1,"a":1}` {
		t.Fatalf("%s %v", encoded, err)
	}
}

func TestStructuredWritesRejectInvalidUTF8WithoutSending(t *testing.T) {
	var calls atomic.Int64
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		jsonResponse(w, `{"status":"stored","etag":"fedcba9876543210","revision":"0123456789abcdef"}`)
	})
	_, err := client.Patch(context.Background(), "a", "b", map[string]any{"$set": map[string]any{"value": string([]byte{0xff})}}, "")
	if err == nil || calls.Load() != 0 {
		t.Fatalf("invalid UTF-8 was sent: calls=%d err=%v", calls.Load(), err)
	}
}

func TestReplicaLostAcknowledgementResumesAtDurablePosition(t *testing.T) {
	before := "v1." + strings.Repeat("a", 32) + ".0000000000000000"
	after := "v1." + strings.Repeat("a", 32) + ".0000000000000001"
	oldRevision := "0000000000000000"
	newRevision := "0123456789abcdef"
	source := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		transactions := "[]"
		if r.URL.Query().Get("after") == before {
			transactions = fmt.Sprintf(`[{"token":%q,"previous_revision":%q,"revision":%q,"resnapshot_required":false,"operations":[{"collection":"examples","document":"one","put":"value: 1\n"}]}]`, after, oldRevision, newRevision)
		}
		jsonResponse(w, fmt.Sprintf(`{"transactions":%s,"next_after":%q,"checkpoint":%q,"oldest_after":%q,"revision":%q,"has_more":false}`, transactions, after, after, before, newRevision))
	})
	var applied atomic.Bool
	var begins, commits atomic.Int64
	destination := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		revision, position := oldRevision, before
		if applied.Load() {
			revision, position = newRevision, after
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-YamlDB-Revision", revision)
		switch r.URL.Path {
		case "/v1/replication/status":
			json.NewEncoder(w).Encode(map[string]any{"status": "following", "revision": revision, "after": position})
		case "/v1/replication/follow/begin":
			begins.Add(1)
			json.NewEncoder(w).Encode(map[string]any{"session": "test-session", "revision": revision})
		case "/v1/replication/follow/apply", "/v1/replication/follow/abort":
			json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
		case "/v1/replication/follow/commit":
			commits.Add(1)
			applied.Store(true)
			connection, _, _ := w.(http.Hijacker).Hijack()
			connection.Close()
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			w.WriteHeader(404)
		}
	})
	if _, err := destination.ReplicateChangesFrom(context.Background(), source); err == nil {
		t.Fatal("lost acknowledgement must be reported")
	}
	result, err := destination.ReplicateChangesFrom(context.Background(), source)
	if err != nil || result.Commits != 0 || result.After == nil || *result.After != after || begins.Load() != 1 || commits.Load() != 1 {
		t.Fatalf("%+v %v begin=%d commit=%d", result, err, begins.Load(), commits.Load())
	}
}

func TestMutationAndListingRejectIncompleteMetadata(t *testing.T) {
	for _, kind := range []string{"missing-revision", "wrong-media", "missing-cursor"} {
		t.Run(kind, func(t *testing.T) {
			client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if kind == "missing-cursor" {
					jsonResponse(w, `{"collection":"a","documents":["b"]}`)
				} else if kind == "missing-revision" {
					jsonResponse(w, `{"status":"stored","etag":"0123456789abcdef"}`)
				} else {
					w.Header().Set("Content-Type", "text/plain")
					w.Header().Set("X-YamlDB-Revision", "0123456789abcdef")
					fmt.Fprint(w, `{"status":"stored","etag":"0123456789abcdef","revision":"0123456789abcdef"}`)
				}
			})
			var err error
			if kind == "missing-cursor" {
				err = client.Documents(context.Background(), "a", "", func(string) error { return nil })
			} else {
				_, err = client.Put(context.Background(), "a", "b", []byte("value: x\n"), y.WriteOptions{})
			}
			if err == nil {
				t.Fatal("incomplete metadata accepted")
			}
		})
	}
}

func TestContinuousStreamFramingTerminalAndCallbackProgress(t *testing.T) {
	before := "v1." + strings.Repeat("a", 32) + ".0000000000000000"
	one := before[:36] + "0000000000000001"
	two := before[:36] + "0000000000000002"
	frame := func(token, prior, revision string, reset bool) string {
		operations := `[{"collection":"items","document":"one","put":"v: 1\r\n"}]`
		if reset {
			operations = `[]`
		}
		return fmt.Sprintf(`{"token":%q,"previous_revision":%q,"revision":%q,"resnapshot_required":%t,"operations":%s}`, token, prior, revision, reset, operations)
	}
	page := func(token, revision, frame string) string {
		return fmt.Sprintf(`{"transactions":[%s],"next_after":%q,"oldest_after":%q,"checkpoint":%q,"revision":%q,"has_more":false}`+"\n", frame, token, before, token, revision)
	}
	first := page(one, "0000000000000001", frame(one, "0000000000000000", "0000000000000001", false))
	stop := errors.New("consumer failed")
	for _, tc := range []struct {
		name, body, after string
		callbacks         int
		want              error
		terminal          int
	}{
		{"complete", first, one, 1, nil, 0},
		{"partial", strings.TrimSuffix(first, "\n"), before, 0, errors.New("invalid"), 0},
		{"chain", first + page(two, "0000000000000002", frame(two, "0000000000000000", "0000000000000002", false)), one, 1, errors.New("invalid"), 0},
		{"terminal", first + fmt.Sprintf(`{"terminal":true,"status":410,"after":%q,"detail":{"error":"change_token_expired"}}`+"\n", one), one, 1, nil, 410},
		{"callback", first, before, 1, stop, 0},
		{"reset", page(one, "0000000000000001", frame(one, "0000000000000000", "0000000000000001", true)), before, 0, y.ErrResnapshotRequired, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("r", 32) {
					t.Error("wrong read credential")
				}
				w.Header().Set("Content-Type", "application/x-ndjson")
				w.Header().Set("X-YamlDB-Revision", "0000000000000001")
				w.WriteHeader(200)
				w.(http.Flusher).Flush()
				fmt.Fprint(w, tc.body)
				w.(http.Flusher).Flush()
			})
			calls := 0
			after, err := client.StreamChanges(context.Background(), before, y.StreamOptions{Duration: 100 * time.Millisecond}, func(y.Change) error {
				calls++
				if tc.name == "callback" {
					return stop
				}
				return nil
			})
			if after != tc.after || calls != tc.callbacks {
				t.Fatalf("progress=%s calls=%d err=%v", after, calls, err)
			}
			if tc.terminal != 0 {
				var status *y.HTTPError
				if !errors.As(err, &status) || status.Status != tc.terminal {
					t.Fatal(err)
				}
			} else if tc.want == nil {
				if err != nil {
					t.Fatal(err)
				}
			} else if tc.want == stop || tc.want == y.ErrResnapshotRequired {
				if !errors.Is(err, tc.want) {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("accepted malformed stream")
			}
		})
	}
}

func TestContinuousStreamCancellationInterruptsSlowDrip(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("X-YamlDB-Revision", "0000000000000001")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(20 * time.Millisecond):
				fmt.Fprint(w, " ")
				w.(http.Flusher).Flush()
			}
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	token := "v1." + strings.Repeat("a", 32) + ".0000000000000000"
	after, err := client.StreamChanges(ctx, token, y.StreamOptions{}, func(y.Change) error { t.Error("unexpected callback"); return nil })
	if after != token || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%s %v", after, err)
	}
}
