package yamora

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"time"
	"unicode/utf8"
)

// StreamOptions bounds one continuously delivered CDC session. Zero values use
// 30 seconds, a 1 second heartbeat and 100 complete commits per page.
type StreamOptions struct {
	Duration  time.Duration
	Heartbeat time.Duration
	Limit     int
}

// StreamChanges returns the last token whose callback succeeded. A reset marker
// or terminal frame stops the session; no automatic reconnection or write retry
// occurs. The caller persists each frame's effects and token atomically.
func (c *Client) StreamChanges(ctx context.Context, after string, options StreamOptions, visit func(Change) error) (string, error) {
	if c.cluster != nil {
		return after, &HTTPError{Status: 405}
	}
	if options.Duration == 0 {
		options.Duration = 30 * time.Second
	}
	if options.Heartbeat == 0 {
		options.Heartbeat = time.Second
	}
	if options.Limit == 0 {
		options.Limit = 100
	}
	if !tokenPattern.MatchString(after) || visit == nil || options.Duration < 100*time.Millisecond || options.Duration > 30*time.Second || options.Heartbeat < 100*time.Millisecond || options.Heartbeat > 5*time.Second || options.Duration%time.Millisecond != 0 || options.Heartbeat%time.Millisecond != 0 || options.Limit < 1 || options.Limit > 100 {
		return after, errors.New("yamora: invalid change stream options")
	}
	session, cancel := context.WithTimeout(ctx, options.Duration+c.http.Timeout)
	defer cancel()
	path := fmt.Sprintf("/v1/changes/stream?after=%s&duration_ms=%d&heartbeat_ms=%d&limit=%d", after, options.Duration.Milliseconds(), options.Heartbeat.Milliseconds(), options.Limit)
	request, err := http.NewRequestWithContext(session, "GET", c.base+path, nil)
	if err != nil {
		return after, err
	}
	request.Header.Set("Accept", "application/x-ndjson")
	if c.readToken != "" {
		request.Header.Set("Authorization", "Bearer "+c.readToken)
	}
	client := *c.http
	// Transport/header/TLS policy remains unchanged. The session context bounds
	// the entire body independently of the normal short-request timeout.
	client.Timeout = 0
	response, err := client.Do(request)
	if err != nil {
		return after, fmt.Errorf("yamora: change stream failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return after, &HTTPError{Status: response.StatusCode}
	}
	media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || media != "application/x-ndjson" || response.Header.Get("Content-Encoding") != "" || response.ContentLength != -1 || len(response.TransferEncoding) != 1 || response.TransferEncoding[0] != "chunked" {
		return after, errors.New("yamora: invalid change stream framing")
	}
	initial := response.Header.Get("X-YamlDB-Revision")
	if err = checkRevision(initial, ""); err != nil {
		return after, err
	}
	scan := bufio.NewScanner(response.Body)
	scan.Buffer(make([]byte, 64*1024), MaxResponseBytes+2)
	scan.Split(func(data []byte, end bool) (int, []byte, error) {
		if at := bytes.IndexByte(data, '\n'); at >= 0 {
			return at + 1, data[:at], nil
		}
		if end && len(data) > 0 {
			return 0, nil, errors.New("yamora: incomplete change stream page")
		}
		return 0, nil, nil
	})
	first, previousRevision := true, ""
	for scan.Scan() {
		if err = session.Err(); err != nil {
			return after, err
		}
		raw := scan.Bytes()
		if len(raw) > MaxResponseBytes || !utf8.Valid(raw) {
			return after, errors.New("yamora: oversized or invalid stream page")
		}
		var envelope struct {
			Terminal *bool  `json:"terminal"`
			Status   int    `json:"status"`
			After    string `json:"after"`
			Revision string `json:"revision"`
		}
		if err = json.Unmarshal(raw, &envelope); err != nil {
			return after, errors.New("yamora: invalid stream JSON")
		}
		if envelope.Terminal != nil {
			if !*envelope.Terminal || envelope.Status < 400 || envelope.Status > 599 || envelope.After != after {
				return after, errors.New("yamora: invalid terminal stream page")
			}
			return after, &HTTPError{Status: envelope.Status}
		}
		header := make(http.Header)
		header.Set("X-YamlDB-Revision", envelope.Revision)
		if first && envelope.Revision != initial {
			return after, errors.New("yamora: inconsistent initial stream revision")
		}
		first = false
		page, err := decodeChangePage(raw, header, after, options.Limit)
		if err != nil {
			return after, err
		}
		for _, frame := range page.Transactions {
			if err = session.Err(); err != nil {
				return after, err
			}
			if previousRevision != "" && frame.PreviousRevision != previousRevision {
				return after, errors.New("yamora: discontinuous change stream")
			}
			if frame.ResnapshotRequired {
				return after, ErrResnapshotRequired
			}
			if err = visit(frame); err != nil {
				return after, err
			}
			previousRevision, after = frame.Revision, frame.Token
		}
	}
	if err = scan.Err(); err != nil {
		return after, fmt.Errorf("yamora: incomplete change stream: %w", err)
	}
	if first {
		return after, errors.New("yamora: empty change stream")
	}
	return after, nil
}
