// Package yamora provides a dependency-free client for the YamoraDB HTTP API.
// Calls accept a context and bound request/response sizes. Explicit replica-set
// configuration enables retries with durable request identities.
package yamora

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaxDocumentBytes = 16 * 1024 * 1024
	MaxRequestBytes  = 64 * 1024 * 1024
	MaxResponseBytes = 64 * 1024 * 1024
)

var (
	identifier      = regexp.MustCompile(`^[a-z0-9-]{1,128}$`)
	revisionPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)
	tokenPattern    = regexp.MustCompile(`^v1\.[0-9a-f]{32}\.[0-9a-f]{16}$`)
)

// Config accepts only a numeric IPv4 loopback or RFC1918 endpoint. Tokens are
// printable ASCII, 32–512 bytes; load them through the application's secret store.
// Use Address for standalone calls or Seeds with verified TLS for replica sets.
// RetryTimeout applies only to replica sets and is bounded by the caller context.
type Config struct {
	Address      netip.AddrPort
	Seeds        []netip.AddrPort
	RetryTimeout time.Duration
	ReadToken    string
	WriteToken   string
	Timeout      time.Duration
	TLSConfig    *tls.Config
}

// Client is safe for concurrent calls. The configuration is copied at creation.
type Client struct {
	base       string
	readToken  string
	writeToken string
	http       *http.Client
	cluster    *clusterRouting
}

// HTTPError retains the response status without exposing remote bodies or tokens.
// A transport failure during mutation has an uncertain commit outcome. Reconcile
// with a read/precondition before submitting a new mutation.
type HTTPError struct{ Status int }

func (e *HTTPError) Error() string { return fmt.Sprintf("yamora: HTTP %d", e.Status) }

func New(config Config) (*Client, error) {
	if config.Seeds != nil {
		return newCluster(config)
	}
	if config.RetryTimeout != 0 {
		return nil, errors.New("yamora: retry timeout requires replica-set seeds")
	}
	address := config.Address.Addr()
	if !config.Address.IsValid() || config.Address.Port() == 0 || !address.Is4() || !(address.IsLoopback() || address.IsPrivate()) {
		return nil, errors.New("yamora: numeric IPv4 loopback or RFC1918 address required")
	}
	for _, token := range []string{config.ReadToken, config.WriteToken} {
		if token == "" {
			continue
		}
		if len(token) < 32 || len(token) > 512 {
			return nil, errors.New("yamora: invalid credential")
		}
		for _, b := range []byte(token) {
			if b < 33 || b > 126 {
				return nil, errors.New("yamora: invalid credential")
			}
		}
	}
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second
	}
	if config.Timeout < 0 || config.Timeout > 30*time.Second {
		return nil, errors.New("yamora: timeout must be at most 30 seconds")
	}
	scheme := "http://"
	var secure *tls.Config
	if config.TLSConfig != nil {
		secure = config.TLSConfig.Clone()
		if secure.InsecureSkipVerify || (secure.MinVersion != 0 && secure.MinVersion != tls.VersionTLS13) || (secure.MaxVersion != 0 && secure.MaxVersion != tls.VersionTLS13) {
			return nil, errors.New("yamora: TLS requires peer verification and TLS 1.3")
		}
		secure.MinVersion, secure.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
		secure.NextProtos = []string{"http/1.1"}
		scheme = "https://"
	}
	transport := &http.Transport{
		// Never consult proxy environment variables or reuse a connection on
		// which net/http could transparently replay an idempotent request.
		Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
		DialContext:            (&net.Dialer{Timeout: config.Timeout}).DialContext,
		MaxResponseHeaderBytes: 16 * 1024, ResponseHeaderTimeout: config.Timeout,
		TLSClientConfig: secure, TLSHandshakeTimeout: config.Timeout,
	}
	return &Client{
		base: scheme + config.Address.String(), readToken: config.ReadToken, writeToken: config.WriteToken,
		http: &http.Client{Transport: transport, Timeout: config.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}

func (c *Client) Close() {
	if c.cluster != nil {
		for _, endpoint := range c.cluster.clients {
			endpoint.Close()
		}
		return
	}
	c.http.CloseIdleConnections()
}

func checkRevision(actual, expected string) error {
	if !revisionPattern.MatchString(actual) || (expected != "" && actual != expected) {
		return errors.New("yamora: invalid or changed revision")
	}
	return nil
}

func (c *Client) request(ctx context.Context, method, path string, body []byte, contentType string, headers http.Header, write bool, maximum int, statuses ...int) ([]byte, http.Header, error) {
	if len(body) > MaxRequestBytes {
		return nil, nil, errors.New("yamora: request exceeds limit")
	}
	if c.cluster != nil {
		return c.cluster.request(ctx, method, path, body, contentType, headers, write, maximum, statuses...)
	}
	if write {
		if id, ok := ctx.Value(requestIDKey{}).(string); ok {
			headers = headers.Clone()
			if headers == nil {
				headers = make(http.Header)
			}
			headers.Set("X-Yamora-Request-Id", id)
		}
	}
	return c.endpointRequest(ctx, method, path, body, contentType, headers, write, maximum, statuses...)
}

func (c *Client) endpointRequest(ctx context.Context, method, path string, body []byte, contentType string, headers http.Header, write bool, maximum int, statuses ...int) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header = headers.Clone()
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("Accept", "application/json, application/yaml")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	token := c.readToken
	if write {
		token = c.writeToken
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := c.http.Do(req)
	if err != nil {
		return nil, nil, &transportError{err}
	}
	defer response.Body.Close()
	expected := false
	for _, status := range statuses {
		expected = expected || response.StatusCode == status
	}
	if !expected {
		return nil, nil, &HTTPError{Status: response.StatusCode}
	}
	if response.ContentLength > int64(maximum) || response.Header.Get("Content-Encoding") != "" {
		return nil, nil, errors.New("yamora: oversized or unexpected encoding")
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, int64(maximum)+1))
	if err != nil {
		return nil, nil, &transportError{err}
	}
	if len(payload) > maximum {
		return nil, nil, errors.New("yamora: response exceeds limit")
	}
	return payload, response.Header, nil
}

func encode(value any) ([]byte, error) {
	budget := 100000
	if !validStrings(reflect.ValueOf(value), 0, &budget) {
		return nil, errors.New("yamora: structured input requires bounded UTF-8 JSON values")
	}
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	// LibYAML treats literal NEL as a line break even inside JSON strings.
	body = bytes.ReplaceAll(body, []byte("\u0085"), []byte(`\u0085`))
	if len(body) > MaxRequestBytes || !utf8.Valid(body) {
		return nil, errors.New("yamora: request exceeds limit")
	}
	return body, nil
}

// encoding/json replaces invalid UTF-8 in strings. Reject it before encoding so
// a successful patch cannot silently store replacement characters instead.
func validStrings(value reflect.Value, depth int, budget *int) bool {
	*budget--
	if depth > 64 || *budget < 0 {
		return false
	}
	if !value.IsValid() {
		return true
	}
	switch value.Kind() {
	case reflect.Interface, reflect.Pointer:
		return value.IsNil() || validStrings(value.Elem(), depth+1, budget)
	case reflect.String:
		return utf8.ValidString(value.String())
	case reflect.Map:
		if value.Type().Key().Kind() != reflect.String {
			return false
		}
		entries := value.MapRange()
		for entries.Next() {
			if !validStrings(entries.Key(), depth+1, budget) || !validStrings(entries.Value(), depth+1, budget) {
				return false
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < value.Len(); i++ {
			if !validStrings(value.Index(i), depth+1, budget) {
				return false
			}
		}
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			field := value.Type().Field(i)
			if field.PkgPath == "" && field.Tag.Get("json") != "-" && !validStrings(value.Field(i), depth+1, budget) {
				return false
			}
		}
	}
	return true
}

func (c *Client) structured(ctx context.Context, method, path string, value any, headers http.Header, write bool, maximum int, out any, expected ...int) (http.Header, error) {
	var body []byte
	var err error
	if value != nil {
		body, err = encode(value)
		if err != nil {
			return nil, err
		}
	}
	if len(expected) == 0 {
		expected = []int{200}
	}
	payload, response, err := c.request(ctx, method, path, body, "application/json", headers, write, maximum, expected...)
	if err != nil {
		return nil, err
	}
	media, _, err := mime.ParseMediaType(response.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return nil, errors.New("yamora: expected JSON response")
	}
	if err = checkRevision(response.Get("X-YamlDB-Revision"), ""); err != nil {
		return nil, err
	}
	if !utf8.Valid(payload) {
		return nil, errors.New("yamora: invalid UTF-8 JSON response")
	}
	if err = json.Unmarshal(payload, out); err != nil {
		return nil, errors.New("yamora: invalid JSON response")
	}
	return response, nil
}

// Metadata preserves numeric JSON tokens exactly in health and statistics data.
type Metadata map[string]json.RawMessage

func (c *Client) Health(ctx context.Context) (Metadata, error) { return c.metadata(ctx, "/healthz") }
func (c *Client) Ready(ctx context.Context) (Metadata, error)  { return c.metadata(ctx, "/readyz") }
func (c *Client) Stats(ctx context.Context) (Metadata, error)  { return c.metadata(ctx, "/v1/stats") }
func (c *Client) Metrics(ctx context.Context) (string, error) {
	body, header, err := c.request(ctx, "GET", "/metrics", nil, "", nil, false, MaxDocumentBytes, 200)
	if err != nil {
		return "", err
	}
	media, _, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil || media != "text/plain" || !utf8.Valid(body) {
		return "", errors.New("yamora: invalid metrics response")
	}
	if err = checkRevision(header.Get("X-YamlDB-Revision"), ""); err != nil {
		return "", err
	}
	return string(body), nil
}

func (c *Client) metadata(ctx context.Context, path string) (Metadata, error) {
	var result Metadata
	_, err := c.structured(ctx, "GET", path, nil, nil, false, MaxDocumentBytes, &result)
	if err == nil && result == nil {
		err = errors.New("yamora: expected metadata object")
	}
	return result, err
}

func documentPath(collection, document string) (string, error) {
	if !identifier.MatchString(collection) || !identifier.MatchString(document) {
		return "", errors.New("yamora: invalid collection or document identifier")
	}
	return "/v1/collections/" + collection + "/documents/" + document, nil
}

func checkMedia(header http.Header) bool {
	media, _, err := mime.ParseMediaType(header.Get("Content-Type"))
	return err == nil && (media == "application/yaml" || media == "text/yaml")
}

// WriteOptions guards a document mutation with an unquoted ETag or create-only.
type WriteOptions struct {
	ETag       string
	CreateOnly bool
}

func (options WriteOptions) headers() (http.Header, error) {
	result := make(http.Header)
	if options.ETag != "" {
		if !revisionPattern.MatchString(options.ETag) || options.CreateOnly {
			return nil, errors.New("yamora: invalid or conflicting write preconditions")
		}
		result.Set("If-Match", `"`+options.ETag+`"`)
	} else if options.CreateOnly {
		result.Set("If-None-Match", "*")
	}
	return result, nil
}

// Document contains exact YAML source, its content ETag, and the snapshot revision.
type Document struct {
	Source   []byte
	ETag     string
	Revision string
}
type Mutation struct {
	Status   string `json:"status"`
	ETag     string `json:"etag"`
	Revision string `json:"revision"`
}

func (c *Client) Get(ctx context.Context, collection, document, revision string) (Document, error) {
	path, err := documentPath(collection, document)
	if err != nil {
		return Document{}, err
	}
	body, header, err := c.request(ctx, "GET", path, nil, "", nil, false, MaxDocumentBytes, 200)
	if err != nil {
		return Document{}, err
	}
	actual := header.Get("X-YamlDB-Revision")
	if err = checkRevision(actual, revision); err != nil {
		return Document{}, err
	}
	etag := header.Get("ETag")
	if !checkMedia(header) || len(etag) != 18 || etag[0] != '"' || etag[17] != '"' || !revisionPattern.MatchString(etag[1:17]) {
		return Document{}, errors.New("yamora: invalid document metadata")
	}
	return Document{Source: body, ETag: etag[1:17], Revision: actual}, nil
}

func (c *Client) Put(ctx context.Context, collection, document string, source []byte, options WriteOptions) (Mutation, error) {
	path, err := documentPath(collection, document)
	if err != nil {
		return Mutation{}, err
	}
	if len(source) == 0 || len(source) > MaxDocumentBytes || !utf8.Valid(source) {
		return Mutation{}, errors.New("yamora: invalid document size")
	}
	headers, err := options.headers()
	if err != nil {
		return Mutation{}, err
	}
	body, response, err := c.request(ctx, "PUT", path, source, "application/yaml", headers, true, MaxDocumentBytes, 200, 201)
	if err != nil {
		return Mutation{}, err
	}
	var result Mutation
	media, _, err := mime.ParseMediaType(response.Get("Content-Type"))
	if err != nil || media != "application/json" || !utf8.Valid(body) {
		return Mutation{}, errors.New("yamora: expected UTF-8 JSON mutation result")
	}
	if err = json.Unmarshal(body, &result); err != nil {
		return Mutation{}, errors.New("yamora: invalid mutation result")
	}
	if err = revisionFromBody(response, result.Revision); err != nil {
		return Mutation{}, err
	}
	if !revisionPattern.MatchString(result.ETag) || result.Status != "stored" {
		return Mutation{}, errors.New("yamora: invalid mutation result")
	}
	return result, nil
}

func (c *Client) Delete(ctx context.Context, collection, document, etag string) error {
	path, err := documentPath(collection, document)
	if err != nil {
		return err
	}
	headers, err := (WriteOptions{ETag: etag}).headers()
	if err != nil {
		return err
	}
	_, response, err := c.request(ctx, "DELETE", path, nil, "", headers, true, 0, 204)
	if err != nil {
		return err
	}
	return checkRevision(response.Get("X-YamlDB-Revision"), "")
}

func namesValid(names []string, maximum int) bool {
	if names == nil || len(names) > maximum {
		return false
	}
	for i, name := range names {
		if !identifier.MatchString(name) || (i > 0 && names[i-1] >= name) {
			return false
		}
	}
	return true
}

func (c *Client) Collections(ctx context.Context, revision string) ([]string, string, error) {
	var result struct {
		Collections []string `json:"collections"`
	}
	headers, err := c.structured(ctx, "GET", "/v1/collections", nil, nil, false, MaxResponseBytes, &result)
	if err != nil {
		return nil, "", err
	}
	actual := headers.Get("X-YamlDB-Revision")
	if err = checkRevision(actual, revision); err != nil {
		return nil, "", err
	}
	if !namesValid(result.Collections, 65536) {
		return nil, "", errors.New("yamora: invalid collection index")
	}
	return result.Collections, actual, nil
}

// Documents visits bounded pages, pins their revision, and stops on callback error.
// The callback must finish its effects before returning; earlier visits cannot be
// undone if a later page reports a concurrent source revision change.
func (c *Client) Documents(ctx context.Context, collection, revision string, visit func(string) error) error {
	if !identifier.MatchString(collection) || visit == nil {
		return errors.New("yamora: invalid collection or visitor")
	}
	after := ""
	for {
		path := "/v1/collections/" + collection + "/documents?limit=1000"
		if after != "" {
			path += "&after=" + after
		}
		var page struct {
			Collection string   `json:"collection"`
			Documents  []string `json:"documents"`
			NextAfter  *string  `json:"next_after"`
		}
		var raw json.RawMessage
		headers, err := c.structured(ctx, "GET", path, nil, nil, false, MaxDocumentBytes, &raw)
		if err != nil {
			return err
		}
		if json.Unmarshal(raw, &page) != nil || !hasJSONKey(raw, "next_after") {
			return errors.New("yamora: incomplete document page")
		}
		actual := headers.Get("X-YamlDB-Revision")
		if err = checkRevision(actual, revision); err != nil {
			return err
		}
		revision = actual
		if page.Collection != collection || !namesValid(page.Documents, 1000) || (len(page.Documents) > 0 && page.Documents[0] <= after) {
			return errors.New("yamora: invalid document page")
		}
		if page.NextAfter != nil && (len(page.Documents) == 0 || *page.NextAfter != page.Documents[len(page.Documents)-1]) {
			return errors.New("yamora: non-progressing document page")
		}
		for _, id := range page.Documents {
			if err = visit(id); err != nil {
				return err
			}
		}
		if page.NextAfter == nil {
			return nil
		}
		after = *page.NextAfter
	}
}

func quotedRevision(revision string) (http.Header, error) {
	headers := make(http.Header)
	if revision != "" {
		if !revisionPattern.MatchString(revision) {
			return nil, errors.New("yamora: invalid revision")
		}
		headers.Set("If-Match", `"`+revision+`"`)
	}
	return headers, nil
}

func revisionFromBody(header http.Header, revision string) error {
	if !revisionPattern.MatchString(revision) {
		return errors.New("yamora: missing body revision")
	}
	return checkRevision(header.Get("X-YamlDB-Revision"), revision)
}

func hasJSONKey(raw json.RawMessage, key string) bool {
	var object map[string]json.RawMessage
	return json.Unmarshal(raw, &object) == nil && object != nil && object[key] != nil
}

// Avoid treating whitespace-only returned revisions as meaningful.
func validRevisionOption(revision string) bool {
	return revision == "" || (strings.TrimSpace(revision) == revision && revisionPattern.MatchString(revision))
}
