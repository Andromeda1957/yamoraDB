package yamora

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"
)

// ErrBinaryUnsupported means HELLO did not negotiate operation protocol 2.
// No REQUEST has been sent and no HTTP fallback or automatic retry occurs.
var ErrBinaryUnsupported = errors.New("yamora: binary operation protocol unavailable")

// BinaryOperationResponse owns raw JSON bytes; numeric tokens are never decoded
// through floating point. Feed returns metadata and the last delivered cursor.
type BinaryOperationResponse struct {
	RepresentationLength                                uint64
	Status                                              int
	ContentType, Revision, ETag, RequestID, ResumeAfter string
	Body                                                []byte
}
type binaryOperation struct {
	source                              []byte
	method                              byte
	target, media, collection, document string
	conditions                          map[string]string
	mutation                            bool
	page                                func([]byte) error
	after                               string
}

func copyBinaryConditions(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for k, v := range input {
		result[k] = v
	}
	return result
}

var binaryQueryTarget = regexp.MustCompile(`^/v1/(query|aggregate|search)/([a-z0-9-]{1,128})$`)
var binaryDocumentTarget = regexp.MustCompile(`^/v1/collections/([a-z0-9-]{1,128})/documents/([a-z0-9-]{1,128})$`)

func operationInput(method, target, media string, source []byte, conditions map[string]string, page func([]byte) error) (*binaryOperation, error) {
	invalid := errors.New("yamora: invalid binary operation")
	if len(target) > 1024 || !binaryASCII([]byte(target), 1024) || len(source) > MaxDocumentBytes || !utf8.Valid(source) {
		return nil, invalid
	}
	op := &binaryOperation{target: target, media: media, conditions: copyBinaryConditions(conditions), page: page}
	for key, value := range op.conditions {
		if (key != "If-Match" && key != "If-None-Match") || !binaryASCII([]byte(value), 31) {
			return nil, invalid
		}
	}
	doc, query := binaryDocumentTarget.FindStringSubmatch(target), binaryQueryTarget.FindStringSubmatch(target)
	switch {
	case method == "PATCH" && doc != nil:
		op.method = 6
		op.mutation = true
		op.collection = doc[1]
		op.document = doc[2]
	case method == "POST" && (query != nil || target == "/v1/transactions"):
		op.method = 5
		op.mutation = target == "/v1/transactions"
		if query != nil {
			op.collection = query[2]
		}
	case method == "GET" && (target == "/v1/changes" || strings.HasPrefix(target, "/v1/changes?") || strings.HasPrefix(target, "/v1/changes/stream?")):
		op.method = 1
		feed := strings.HasPrefix(target, "/v1/changes/stream?")
		if feed != (page != nil) || media != "" || len(source) != 0 {
			return nil, invalid
		}
		parts := strings.SplitN(target, "?", 2)
		seen := map[string]bool{}
		if len(parts) == 2 {
			for _, part := range strings.Split(parts[1], "&") {
				kv := strings.SplitN(part, "=", 2)
				if len(kv) != 2 || seen[kv[0]] {
					return nil, invalid
				}
				seen[kv[0]] = true
				switch kv[0] {
				case "after":
					if !tokenPattern.MatchString(kv[1]) {
						return nil, invalid
					}
					op.after = kv[1]
				case "limit", "duration_ms", "heartbeat_ms":
					if !feed && kv[0] != "limit" {
						return nil, invalid
					}
					if kv[1] == "" {
						return nil, invalid
					}
					for _, c := range kv[1] {
						if c < '0' || c > '9' {
							return nil, invalid
						}
					}
				default:
					return nil, invalid
				}
			}
		}
		if feed && op.after == "" {
			return nil, invalid
		}
	default:
		return nil, invalid
	}
	if op.method != 1 {
		base, _, err := mime.ParseMediaType(media)
		if err != nil || !binaryASCII([]byte(media), 95) || (base != "application/json" && base != "application/yaml" && base != "text/yaml") {
			return nil, invalid
		}
		if page != nil {
			return nil, invalid
		}
	}
	return op, nil
}

// Operation executes only native query/aggregate/search, transaction, document
// PATCH and paged changes. Conditions preserve absent versus present-empty.
// WithRequestID supplies an identity; otherwise an owned identity is generated.
func (c *BinaryClient) Operation(ctx context.Context, method, target, contentType string, source []byte, conditions map[string]string) (BinaryOperationResponse, error) {
	return c.operation(ctx, method, target, contentType, source, conditions, nil)
}

// Feed synchronously transfers each complete validated native NDJSON page,
// including its LF and terminal records, to consume. The callback owns its bytes.
// Return an error or cancel ctx to stop. No incomplete page is exposed.
func (c *BinaryClient) Feed(ctx context.Context, target string, consume func([]byte) error, conditions ...map[string]string) (BinaryOperationResponse, error) {
	if consume == nil {
		return BinaryOperationResponse{}, errors.New("yamora: feed callback required")
	}
	if len(conditions) > 1 {
		return BinaryOperationResponse{}, errors.New("yamora: one conditions map permitted")
	}
	var selected map[string]string
	if len(conditions) == 1 {
		selected = conditions[0]
	}
	return c.operation(ctx, "GET", target, "", nil, selected, consume)
}
func (c *BinaryClient) operation(parent context.Context, method, target, media string, source []byte, conditions map[string]string, page func([]byte) error) (BinaryOperationResponse, error) {
	ctx, cancel := context.WithTimeout(parent, c.timeout)
	defer cancel()
	op, err := operationInput(method, target, media, source, conditions, page)
	if err != nil {
		return BinaryOperationResponse{}, err
	}
	r, err := c.exchange(ctx, op.method, op.collection, op.document, source, WriteOptions{}, "", op)
	if err != nil {
		if !r.operationValid {
			r = binaryReply{}
		} else {
			var status *HTTPError
			if !errors.As(err, &status) {
				r.body = nil
			}
		}
	}
	return BinaryOperationResponse{Status: r.status, RepresentationLength: r.representation, ContentType: r.media, Revision: r.revision, ETag: r.etag, RequestID: r.id, ResumeAfter: op.after, Body: r.body}, err
}
func (op *binaryOperation) metadata(source []byte, token, id string, timeout int) []byte {
	fields := []byte{0, 2, 0, 0}
	count := uint16(4)
	fields = binaryTLV(fields, 1, []byte{op.method})
	fields = binaryTLV(fields, 2, []byte(op.target))
	fields = binaryTLV(fields, 3, []byte(op.media))
	fields = binaryTLV(fields, 4, binary.BigEndian.AppendUint64(nil, uint64(len(source))))
	if token != "" {
		fields = binaryTLV(fields, 5, []byte("Bearer "+token))
		count++
	}
	for i, key := range []string{"If-Match", "If-None-Match"} {
		if value, ok := op.conditions[key]; ok {
			fields = binaryTLV(fields, uint16(6+i), []byte(value))
			count++
		}
	}
	fields = binaryTLV(fields, 8, binaryIDBytes(id))
	count++
	fields = binaryTLV(fields, 9, binary.BigEndian.AppendUint32(nil, uint32(timeout)))
	count++
	binary.BigEndian.PutUint16(fields[2:4], count)
	return fields
}

// Token validation never converts a JSON number to float64. Duplicate keys and
// excessive nesting fail before an untrusted page reaches a callback.
func binaryRawObject(body []byte, ctx context.Context, maxDepth int) (map[string]json.RawMessage, error) {
	if !utf8.Valid(body) {
		return nil, errBinaryProtocol
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > maxDepth {
			return errBinaryProtocol
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		v, err := d.Token()
		if err != nil {
			return errBinaryProtocol
		}
		if delim, ok := v.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, err := d.Token()
					key, ok := k.(string)
					if err != nil || !ok || seen[key] {
						return errBinaryProtocol
					}
					seen[key] = true
					if err = walk(depth + 1); err != nil {
						return err
					}
				}
				end, err := d.Token()
				if err != nil || end != json.Delim('}') {
					return errBinaryProtocol
				}
			case '[':
				for d.More() {
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
				end, err := d.Token()
				if err != nil || end != json.Delim(']') {
					return errBinaryProtocol
				}
			default:
				return errBinaryProtocol
			}
		}
		return nil
	}
	if err := walk(0); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errBinaryProtocol
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(body, &object) != nil || object == nil {
		return nil, errBinaryProtocol
	}
	return object, nil
}
func (w *binaryWire) operationResponse(ctx context.Context, op *binaryOperation, id string) (r binaryReply, err error) {
	started := false
	var partial []byte
	total := 0
	terminal := false
	for {
		if err = ctx.Err(); err != nil {
			return r, err
		}
		f, e := w.receive()
		if e != nil {
			return r, e
		}
		if control, e := w.control(f); control {
			if e != nil {
				return r, e
			}
			continue
		}
		switch f.kind {
		case 3:
			if started {
				return r, errBinaryProtocol
			}
			r, err = binaryMetadataSchema(f.payload, 2)
			if err != nil {
				return r, err
			}
			started = true
			base, _, e := mime.ParseMediaType(r.media)
			if e != nil || r.id != id || r.length != r.representation {
				return r, errBinaryProtocol
			}
			if (r.collection != "" && r.collection != op.collection) || (r.document != "" && r.document != op.document) {
				return r, errBinaryProtocol
			}
			if r.status >= 400 {
				if r.streaming || r.length > 4096 || base != "application/json" {
					return r, errBinaryProtocol
				}
			} else {
				if r.status != 200 || r.streaming != (op.page != nil) || (!r.streaming && base != "application/json") || (r.streaming && base != "application/x-ndjson") {
					return r, errBinaryProtocol
				}
				if op.mutation && (r.length == 0 || r.length > 4096) {
					return r, errBinaryProtocol
				}
				if op.method == 6 && r.etag == "" {
					return r, errBinaryProtocol
				}
			}
			r.operationValid = true
		case 4:
			if !started || terminal {
				return r, errBinaryProtocol
			}
			total += len(f.payload)
			if total > MaxDocumentBytes {
				return r, errBinaryProtocol
			}
			if !r.streaming {
				if uint64(len(r.body)+len(f.payload)) > r.length {
					return r, errBinaryProtocol
				}
				r.body = append(r.body, f.payload...)
				continue
			}
			for len(f.payload) > 0 {
				n := bytes.IndexByte(f.payload, '\n')
				end := len(f.payload)
				if n >= 0 {
					end = n + 1
				}
				partial = append(partial, f.payload[:end]...)
				f.payload = f.payload[end:]
				if n >= 0 {
					page := partial
					partial = nil
					after, ended, e := binaryFeedPage(page, op.after, ctx)
					if e != nil {
						return r, e
					}
					if e = op.page(page); e != nil {
						return r, e
					}
					op.after = after
					terminal = ended
					if terminal && len(f.payload) > 0 {
						return r, errBinaryProtocol
					}
				}
			}
		case 5:
			if !started || len(partial) != 0 || (!r.streaming && uint64(len(r.body)) != r.length) {
				return r, errBinaryProtocol
			}
			if !r.streaming {
				if err = binaryOperationReceipt(&r, op, ctx); err != nil {
					return r, err
				}
			}
			if r.status >= 400 {
				return r, &HTTPError{Status: r.status}
			}
			return r, ctx.Err()
		case 7:
			if binary.BigEndian.Uint32(f.payload) == 0 {
				return r, errBinaryProtocol
			}
			return r, errBinaryTransport
		default:
			return r, errBinaryProtocol
		}
	}
}
func binaryOperationReceipt(r *binaryReply, op *binaryOperation, ctx context.Context) error {
	// Responses wrap native depth64 values in query/facet envelopes.
	object, err := binaryRawObject(r.body, ctx, 80)
	if err != nil {
		return err
	}
	if r.status >= 400 {
		return nil
	}
	var revision string
	if json.Unmarshal(object["revision"], &revision) != nil || revision != r.revision {
		return errBinaryProtocol
	}
	if op.method == 6 {
		return r.receipt(op.collection, op.document)
	}
	if op.mutation {
		var status string
		var count int
		if len(object) != 3 || json.Unmarshal(object["status"], &status) != nil || status != "committed" || json.Unmarshal(object["operations"], &count) != nil || count < 1 || count > 128 {
			return errBinaryProtocol
		}

		if strings.EqualFold(strings.Split(op.media, ";")[0], "application/json") {
			request, e := binaryRawObject(op.source, ctx, 64)
			if e != nil {
				return e
			}
			var operations []json.RawMessage
			if json.Unmarshal(request["operations"], &operations) != nil || count != len(operations) {
				return errBinaryProtocol
			}
		}
	}
	return nil
}
func binaryFeedPage(body []byte, after string, ctx context.Context) (string, bool, error) {
	object, err := binaryRawObject(body, ctx, 80)
	if err != nil {
		return after, false, err
	}
	if raw, ok := object["terminal"]; ok {
		var terminal bool
		var status int
		var cursor string
		var detail map[string]json.RawMessage
		if json.Unmarshal(raw, &terminal) != nil || !terminal || json.Unmarshal(object["status"], &status) != nil || status < 400 || status > 599 || json.Unmarshal(object["after"], &cursor) != nil || cursor != after || json.Unmarshal(object["detail"], &detail) != nil || detail == nil {
			return after, false, errBinaryProtocol
		}
		return after, true, nil
	}
	var revision string
	if json.Unmarshal(object["revision"], &revision) != nil {
		return after, false, errBinaryProtocol
	}
	header := http.Header{"X-Yamldb-Revision": []string{revision}}
	page, err := decodeChangePage(body, header, after, 100)
	if err != nil {
		return after, false, errBinaryProtocol
	}
	return page.NextAfter, false, nil
}
