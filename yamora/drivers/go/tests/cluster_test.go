package yamora_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	y "github.com/Andromeda1957/yamoraDB/yamora/drivers/go"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func clusterServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}
func clusterConfig(servers ...*httptest.Server) y.Config {
	pool := x509.NewCertPool()
	config := y.Config{ReadToken: strings.Repeat("r", 32), WriteToken: strings.Repeat("w", 32), Timeout: 300 * time.Millisecond, RetryTimeout: 2 * time.Second, TLSConfig: &tls.Config{RootCAs: pool}}
	for _, server := range servers {
		pool.AddCert(server.Certificate())
		config.Seeds = append(config.Seeds, netip.MustParseAddrPort(strings.TrimPrefix(server.URL, "https://")))
	}
	return config
}
func routedClient(t *testing.T, config y.Config) *y.Client {
	t.Helper()
	client, err := y.New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}
func leaderReply(w http.ResponseWriter, node, leader int64) {
	role := "follower"
	if node == leader {
		role = "leader"
	}
	jsonResponse(w, fmt.Sprintf(`{"node":%d,"leader":%d,"term":1,"role":%q}`, node, leader, role))
}

const mutationReply = `{"status":"stored","etag":"fedcba9876543210","revision":"0123456789abcdef"}`

func TestClusterLostReplyPreservesIdentityPayloadAndPreconditions(t *testing.T) {
	var leader atomic.Int64
	leader.Store(1)
	var mu sync.Mutex
	var firstID string
	var original []byte
	count, attempts := 0, 0
	handler := func(node int64) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/cluster/leader" {
				if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("r", 32) {
					t.Error("discovery credential")
				}
				leaderReply(w, node, leader.Load())
				return
			}
			if node != leader.Load() {
				w.WriteHeader(503)
				return
			}
			if r.Method != "PATCH" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("w", 32) || r.Header.Get("If-Match") != `"fedcba9876543210"` {
				t.Error("mutation contract")
			}
			body, _ := io.ReadAll(r.Body)
			id := r.Header.Get("X-Yamora-Request-Id")
			mu.Lock()
			defer mu.Unlock()
			attempts++
			if firstID == "" {
				firstID, original = id, body
				if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(id) || id == strings.Repeat("0", 32) {
					t.Error("missing generated ID")
				}
				count++
				leader.Store(2)
				conn, _, _ := w.(http.Hijacker).Hijack()
				conn.Close()
				return
			}
			if id != firstID || !bytes.Equal(body, original) {
				count++
				t.Error("retry changed logical request")
			}
			jsonResponse(w, mutationReply)
		}
	}
	client := routedClient(t, clusterConfig(clusterServer(t, handler(1)), clusterServer(t, handler(2))))
	result, err := client.Patch(context.Background(), "a", "b", map[string]any{"$inc": map[string]any{"count": 1}}, "fedcba9876543210")
	if err != nil || result.Status != "stored" {
		t.Fatalf("%+v %v", result, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if count != 1 || attempts != 2 {
		t.Fatalf("effects=%d attempts=%d", count, attempts)
	}
}
func TestClusterAuthenticationAfterLostReplyRetainsID(t *testing.T) {
	var committed atomic.Bool
	var id string
	server := clusterServer(t, func(w http.ResponseWriter, r *http.Request) {
		if committed.Load() {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/v1/cluster/leader" {
			leaderReply(w, 1, 1)
			return
		}
		id = r.Header.Get("X-Yamora-Request-Id")
		committed.Store(true)
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close()
	})
	client := routedClient(t, clusterConfig(server))
	_, err := client.Patch(context.Background(), "a", "b", map[string]any{"$inc": map[string]any{"n": 1}}, "")
	var uncertain *y.UncertainWriteError
	if !errors.As(err, &uncertain) || id == "" || uncertain.RequestID != id {
		t.Fatalf("%v id=%q", err, id)
	}
}
func TestClusterStaleAndSlowSeedsCannotStarveOthers(t *testing.T) {
	for _, slow := range []bool{false, true} {
		t.Run(fmt.Sprint(slow), func(t *testing.T) {
			first := clusterServer(t, func(w http.ResponseWriter, r *http.Request) {
				if slow {
					<-r.Context().Done()
					return
				}
				if r.URL.Path == "/v1/cluster/leader" {
					leaderReply(w, 1, 1)
					return
				}
				w.WriteHeader(503)
			})
			second := clusterServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/cluster/leader" {
					leaderReply(w, 2, 2)
					return
				}
				jsonResponse(w, mutationReply)
			})
			config := clusterConfig(first, second)
			config.Timeout, config.RetryTimeout = 2*time.Second, 600*time.Millisecond
			client := routedClient(t, config)
			if _, err := client.Put(context.Background(), "a", "b", []byte("n: 1\n"), y.WriteOptions{}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestClusterNeverRoutesCredentialsToRedirectsOrAdvertisedURLs(t *testing.T) {
	var leaks atomic.Int64
	trap := clusterServer(t, func(w http.ResponseWriter, r *http.Request) { leaks.Add(1); w.WriteHeader(401) })
	for _, redirect := range []bool{false, true} {
		seed := clusterServer(t, func(w http.ResponseWriter, r *http.Request) {
			if redirect {
				w.Header().Set("Location", trap.URL)
				w.WriteHeader(307)
				return
			}
			jsonResponse(w, `{"node":1,"leader":1,"term":1,"role":"leader","url":"`+trap.URL+`"}`)
		})
		config := clusterConfig(seed)
		config.RetryTimeout = 100 * time.Millisecond
		if _, err := routedClient(t, config).Health(context.Background()); err == nil {
			t.Fatal("accepted untrusted routing metadata")
		}
	}
	if leaks.Load() != 0 {
		t.Fatal("credentials reached an unconfigured endpoint")
	}
}
func TestClusterMalformedSuccessKeepsExplicitAndGeneratedWriteIDs(t *testing.T) {
	for _, reply := range []string{`{`, `[]`, `null`, `{}`, strings.Replace(mutationReply, `"stored"`, `"other"`, 1)} {
		t.Run(reply, func(t *testing.T) {
			var id string
			server := clusterServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/cluster/leader" {
					leaderReply(w, 1, 1)
					return
				}
				id = r.Header.Get("X-Yamora-Request-Id")
				jsonResponse(w, reply)
			})
			client := routedClient(t, clusterConfig(server))
			for _, explicit := range []bool{false, true} {
				ctx := context.Background()
				if explicit {
					var err error
					ctx, err = y.WithRequestID(ctx, strings.Repeat("a", 32))
					if err != nil {
						t.Fatal(err)
					}
				}
				_, err := client.Patch(ctx, "a", "b", map[string]any{"$inc": map[string]any{"n": 1}}, "")
				var uncertain *y.UncertainWriteError
				if !errors.As(err, &uncertain) || uncertain.RequestID != id || id == "" {
					t.Fatalf("%v id=%q", err, id)
				}
				if explicit && id != strings.Repeat("a", 32) {
					t.Fatal("explicit ID changed")
				}
			}
		})
	}
}
func TestClusterShortRepliesRetryAndContextBoundsSlowBytes(t *testing.T) {
	var count atomic.Int64
	var firstID string
	server := clusterServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/cluster/leader" {
			leaderReply(w, 1, 1)
			return
		}
		id := r.Header.Get("X-Yamora-Request-Id")
		if count.Add(1) == 1 {
			firstID = id
			w.Header().Set("Content-Length", fmt.Sprint(len(mutationReply)+9))
		} else if id != firstID {
			t.Error("short-body retry changed ID")
		}
		jsonResponse(w, mutationReply)
	})
	client := routedClient(t, clusterConfig(server))
	if _, err := client.Put(context.Background(), "a", "b", []byte("n: 1\n"), y.WriteOptions{}); err != nil || count.Load() != 2 {
		t.Fatalf("%v attempts=%d", err, count.Load())
	}
	slow := clusterServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/cluster/leader" {
			leaderReply(w, 1, 1)
			return
		}
		w.Header().Set("Content-Length", "100")
		for i := 0; i < 100; i++ {
			if _, err := w.Write([]byte(" ")); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(30 * time.Millisecond):
			}
		}
	})
	config := clusterConfig(slow)
	config.RetryTimeout = 200 * time.Millisecond
	started := time.Now()
	_, err := routedClient(t, config).Health(context.Background())
	if err == nil || time.Since(started) > 700*time.Millisecond {
		t.Fatalf("%v elapsed=%s", err, time.Since(started))
	}
}
func TestClusterConfigurationAndRequestIDsFailBeforeNetworking(t *testing.T) {
	valid := y.Config{Seeds: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:8765")}, TLSConfig: &tls.Config{}}
	invalid := []y.Config{
		{Seeds: []netip.AddrPort{}, TLSConfig: &tls.Config{}}, {Seeds: valid.Seeds},
		{Seeds: valid.Seeds, TLSConfig: &tls.Config{InsecureSkipVerify: true}},
		{Seeds: valid.Seeds, TLSConfig: &tls.Config{}, Address: valid.Seeds[0]},
		{Seeds: append(valid.Seeds, valid.Seeds[0]), TLSConfig: &tls.Config{}},
		{Seeds: []netip.AddrPort{netip.MustParseAddrPort("8.8.8.8:443")}, TLSConfig: &tls.Config{}},
		{Seeds: valid.Seeds, TLSConfig: &tls.Config{}, RetryTimeout: 31 * time.Second},
	}
	for _, config := range invalid {
		if client, err := y.New(config); err == nil {
			client.Close()
			t.Fatal("accepted unsafe configuration")
		}
	}
	for _, id := range []string{"", strings.Repeat("0", 32), strings.Repeat("A", 32), "../x", strings.Repeat("a", 33)} {
		if _, err := y.WithRequestID(context.Background(), id); err == nil {
			t.Fatal("accepted invalid ID")
		}
	}
}

func TestClusterLeaderWarmingDoesNotExhaustAttemptsInABusyLoop(t *testing.T) {
	var mu sync.Mutex
	var ready time.Time
	var ids []string
	server := clusterServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/cluster/leader" {
			leaderReply(w, 1, 1)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		ids = append(ids, r.Header.Get("X-Yamora-Request-Id"))
		if ready.IsZero() {
			ready = time.Now().Add(700 * time.Millisecond)
		}
		if time.Now().Before(ready) {
			w.WriteHeader(503)
			return
		}
		jsonResponse(w, mutationReply)
	})
	client := routedClient(t, clusterConfig(server))
	if _, err := client.Put(context.Background(), "a", "b", []byte("n: 1\n"), y.WriteOptions{}); err != nil {
		t.Fatalf("%v cause=%v", err, errors.Unwrap(err))
	}
	mu.Lock()
	defer mu.Unlock()
	for _, id := range ids {
		if id == "" || id != ids[0] {
			t.Fatal("warming changed retry ID")
		}
	}
}

func TestClusterAmbiguousStatusesKeepTheGeneratedIdentity(t *testing.T) {
	for _, status := range []int{202, 207, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var id atomic.Value
			server := clusterServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/cluster/leader" {
					leaderReply(w, 1, 1)
					return
				}
				id.Store(r.Header.Get("X-Yamora-Request-Id"))
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-YamlDB-Revision", "0123456789abcdef")
				w.WriteHeader(status)
				fmt.Fprint(w, mutationReply)
			})
			_, err := routedClient(t, clusterConfig(server)).Patch(context.Background(), "a", "b", map[string]any{"$inc": map[string]any{"n": 1}}, "")
			var uncertain *y.UncertainWriteError
			if !errors.As(err, &uncertain) || id.Load() == nil || uncertain.RequestID != id.Load().(string) {
				t.Fatalf("%v lost request identity", err)
			}
		})
	}
}
func TestClusterStalledCachedLeaderLeavesTimeForFailover(t *testing.T) {
	var stall atomic.Bool
	first := clusterServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/cluster/leader" {
			leaderReply(w, 1, 1)
			return
		}
		if stall.Load() {
			<-r.Context().Done()
			return
		}
		jsonResponse(w, `{"status":"ok"}`)
	})
	second := clusterServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/cluster/leader" {
			leaderReply(w, 2, 2)
			return
		}
		jsonResponse(w, `{"status":"ok"}`)
	})
	config := clusterConfig(first, second)
	config.Timeout, config.RetryTimeout = 2*time.Second, 600*time.Millisecond
	client := routedClient(t, config)
	if _, err := client.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	stall.Store(true)
	if _, err := client.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
}
