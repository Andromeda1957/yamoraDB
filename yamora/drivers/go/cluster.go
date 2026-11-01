package yamora

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var requestIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type requestIDKey struct{}

// WithRequestID assigns a caller-persisted identity to one primitive mutation.
// Reuse this context only to recover the same exact request and preconditions.
// A standalone endpoint forwards this ID without gaining automatic retries.
func WithRequestID(ctx context.Context, id string) (context.Context, error) {
	if !requestIDPattern.MatchString(id) || id == strings.Repeat("0", 32) {
		return nil, errors.New("yamora: request ID requires a nonzero 32-digit lowercase hex value")
	}
	return context.WithValue(ctx, requestIDKey{}, id), nil
}

// UncertainWriteError retains the identity needed to recover a possibly committed
// mutation. Persist the exact request as well; never invent a new ID for a retry.
type UncertainWriteError struct {
	RequestID string
	cause     error
}

func (e *UncertainWriteError) Error() string {
	return "yamora: replica-set write outcome is uncertain; recover the same request ID and bytes"
}
func (e *UncertainWriteError) Unwrap() error { return e.cause }

type transportError struct{ cause error }

func (e *transportError) Error() string { return "yamora: request transport failed" }
func (e *transportError) Unwrap() error { return e.cause }

type clusterRouting struct {
	clients        []*Client
	retryTimeout   time.Duration
	mu             sync.Mutex
	leader, cursor int
}

func newCluster(config Config) (*Client, error) {
	if len(config.Seeds) < 1 || len(config.Seeds) > 9 || config.Address.IsValid() || config.TLSConfig == nil {
		return nil, errors.New("yamora: replica sets require 1..9 distinct private HTTPS seeds and no standalone address")
	}
	if config.RetryTimeout == 0 {
		config.RetryTimeout = 30 * time.Second
	}
	if config.RetryTimeout < 0 || config.RetryTimeout > 30*time.Second {
		return nil, errors.New("yamora: retry timeout must be at most 30 seconds")
	}
	routing := &clusterRouting{retryTimeout: config.RetryTimeout, leader: -1}
	seen := make(map[netip.AddrPort]bool)
	for _, seed := range config.Seeds {
		if seen[seed] {
			return nil, errors.New("yamora: duplicate replica-set seed")
		}
		seen[seed] = true
		endpointConfig := config
		endpointConfig.Address, endpointConfig.Seeds, endpointConfig.RetryTimeout = seed, nil, 0
		endpoint, err := New(endpointConfig)
		if err != nil {
			return nil, err
		}
		routing.clients = append(routing.clients, endpoint)
	}
	client := *routing.clients[0]
	client.cluster = routing
	return &client, nil
}

func leaderMetadata(payload []byte) bool {
	var fields map[string]json.RawMessage
	if !utf8.Valid(payload) || json.Unmarshal(payload, &fields) != nil || len(fields) != 4 {
		return false
	}
	var node, leader, term uint64
	var role string
	if json.Unmarshal(fields["node"], &node) != nil || json.Unmarshal(fields["leader"], &leader) != nil || json.Unmarshal(fields["term"], &term) != nil || json.Unmarshal(fields["role"], &role) != nil {
		return false
	}
	return node >= 1 && node <= 9 && leader == node && term > 0 && role == "leader"
}

func (routing *clusterRouting) discover(ctx context.Context) (int, error) {
	routing.mu.Lock()
	start := routing.cursor
	routing.mu.Unlock()
	deadline, _ := ctx.Deadline()
	for offset := 0; offset < len(routing.clients); offset++ {
		if ctx.Err() != nil {
			return -1, ctx.Err()
		}
		index := (start + offset) % len(routing.clients)
		// Give later trusted seeds time even if the first one accepts TCP but stalls.
		share := time.Until(deadline) / time.Duration(len(routing.clients)-offset)
		attempt, cancel := context.WithTimeout(ctx, share)
		payload, headers, err := routing.clients[index].endpointRequest(attempt, "GET", "/v1/cluster/leader", nil, "", nil, false, 512, 200)
		cancel()
		if err != nil {
			var remote *HTTPError
			if errors.As(err, &remote) && (remote.Status == 401 || remote.Status == 403) {
				return -1, err
			}
			continue
		}
		media, _, err := mime.ParseMediaType(headers.Get("Content-Type"))
		if err == nil && media == "application/json" && leaderMetadata(payload) {
			routing.mu.Lock()
			routing.leader = index
			routing.mu.Unlock()
			return index, nil
		}
	}
	return -1, nil
}

func clusterWritePath(method, path string) bool {
	if path == "/v1/transactions" {
		return method == "POST"
	}
	if path == "/v1/indexes" {
		return method == "PUT"
	}
	return strings.HasPrefix(path, "/v1/collections/") && strings.Contains(path, "/documents/") && (method == "PUT" || method == "PATCH" || method == "DELETE")
}

// Validate every accepted mutation receipt before leaving the request ID's error
// boundary. The public typed methods must not discover malformed success later
// and lose an automatically generated identity.
func validateClusterReceipt(method, path string, body, payload []byte, header http.Header) error {
	invalid := errors.New("yamora: invalid replica-set mutation receipt")
	if checkRevision(header.Get("X-YamlDB-Revision"), "") != nil {
		return invalid
	}
	if method == "DELETE" {
		if len(payload) != 0 {
			return invalid
		}
		return nil
	}
	media, _, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil || media != "application/json" || !utf8.Valid(payload) {
		return invalid
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(payload, &object) != nil || object == nil {
		return invalid
	}
	if path == "/v1/transactions" {
		var receipt TransactionResult
		var request struct {
			Operations []json.RawMessage `json:"operations"`
		}
		if json.Unmarshal(payload, &receipt) != nil || json.Unmarshal(body, &request) != nil || revisionFromBody(header, receipt.Revision) != nil || receipt.Status != "committed" || receipt.Operations != len(request.Operations) {
			return invalid
		}
	} else {
		var receipt Mutation
		if json.Unmarshal(payload, &receipt) != nil || revisionFromBody(header, receipt.Revision) != nil {
			return invalid
		}
		if path != "/v1/indexes" && (receipt.Status != "stored" || !revisionPattern.MatchString(receipt.ETag)) {
			return invalid
		}
	}
	return nil
}

func (routing *clusterRouting) request(ctx context.Context, method, path string, body []byte, contentType string, headers http.Header, write bool, maximum int, statuses ...int) ([]byte, http.Header, error) {
	if write && !clusterWritePath(method, path) {
		return nil, nil, &HTTPError{Status: 405}
	}
	// Each logical operation owns these bytes and preconditions across retries.
	body = bytes.Clone(body)
	headers = headers.Clone()
	if headers == nil {
		headers = make(http.Header)
	}
	id := ""
	if write {
		id, _ = ctx.Value(requestIDKey{}).(string)
		if id == "" {
			var random [16]byte
			for id == "" || id == strings.Repeat("0", 32) {
				if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
					return nil, nil, errors.New("yamora: request identity unavailable")
				}
				id = hex.EncodeToString(random[:])
			}
		}
		headers.Set("X-Yamora-Request-Id", id)
	}
	session, cancel := context.WithTimeout(ctx, routing.retryTimeout)
	defer cancel()
	uncertain := false
	var last error
	delay := 50 * time.Millisecond
	pause := func() bool {
		timer := time.NewTimer(delay)
		select {
		case <-session.Done():
		case <-timer.C:
		}
		timer.Stop()
		delay = min(time.Second, delay*2)
		return session.Err() == nil
	}
	for attempts := 0; attempts < 32 && session.Err() == nil; attempts++ {
		routing.mu.Lock()
		leader := routing.leader
		routing.mu.Unlock()
		if leader < 0 {
			var err error
			leader, err = routing.discover(session)
			if err != nil {
				if write && uncertain {
					return nil, nil, &UncertainWriteError{RequestID: id, cause: err}
				}
				var remote *HTTPError
				if errors.As(err, &remote) {
					return nil, nil, err
				}
				last = err
				break
			}
		}
		if leader < 0 {
			if !pause() {
				break
			}
			continue
		}
		deadline, _ := session.Deadline()
		budget := time.Until(deadline)
		if len(routing.clients) > 1 {
			budget /= 2
		}
		attempt, stopAttempt := context.WithTimeout(session, budget)
		payload, response, err := routing.clients[leader].endpointRequest(attempt, method, path, body, contentType, headers, write, maximum, statuses...)
		if err == nil && attempt.Err() != nil {
			err = &transportError{attempt.Err()}
		}
		stopAttempt()
		if err == nil && write {
			err = validateClusterReceipt(method, path, body, payload, response)
		}
		if err == nil && session.Err() != nil {
			err = &transportError{session.Err()}
		}
		if err == nil {
			return payload, response, nil
		}
		last = err
		var remote *HTTPError
		var transport *transportError
		retry := errors.As(err, &transport) || (errors.As(err, &remote) && remote.Status == 503)
		if !retry {
			definitive := remote != nil && remote.Status >= 400 && remote.Status < 500 && remote.Status != 408
			if write && (uncertain || !definitive) {
				return nil, nil, &UncertainWriteError{RequestID: id, cause: err}
			}
			return nil, nil, err
		}
		uncertain = write
		routing.mu.Lock()
		if routing.leader == leader {
			routing.leader = -1
			routing.cursor = (leader + 1) % len(routing.clients)
		}
		routing.mu.Unlock()
		if !pause() {
			break
		}
	}
	if session.Err() != nil {
		last = session.Err()
	}
	if write {
		return nil, nil, &UncertainWriteError{RequestID: id, cause: last}
	}
	if last != nil {
		return nil, nil, last
	}
	return nil, nil, &HTTPError{Status: 503}
}
