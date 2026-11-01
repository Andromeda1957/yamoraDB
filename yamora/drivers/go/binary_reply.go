package yamora

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"unicode/utf8"
)

type binaryReply struct {
	operationValid                                  bool
	status                                          int
	media, revision, etag, collection, document, id string
	length, representation                          uint64
	body                                            []byte
	streaming                                       bool
	mutation                                        Mutation
}

func binaryIDBytes(id string) []byte { value, _ := hex.DecodeString(id); return value }
func binaryASCII(b []byte, maxLen int) bool {
	if len(b) > maxLen {
		return false
	}
	for _, c := range b {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}
func binaryMetadata(payload []byte) (r binaryReply, err error) {
	return binaryMetadataSchema(payload, 1)
}
func binaryMetadataSchema(payload []byte, schema uint16) (r binaryReply, err error) {
	if len(payload) < 4 || len(payload) > 2048 || binary.BigEndian.Uint16(payload[:2]) != schema {
		return r, errBinaryProtocol
	}
	count := int(binary.BigEndian.Uint16(payload[2:4]))
	maximum := 12
	if schema == 2 {
		maximum = 13
	}
	if count < 5 || count > maximum {
		return r, errBinaryProtocol
	}
	var fields [14][]byte
	last := 0
	tail := payload[4:]
	for i := 0; i < count; i++ {
		if len(tail) < 4 {
			return r, errBinaryProtocol
		}
		id, n := int(binary.BigEndian.Uint16(tail[:2])), int(binary.BigEndian.Uint16(tail[2:4]))
		tail = tail[4:]
		if id <= last || id > maximum || n > len(tail) {
			return r, errBinaryProtocol
		}
		fields[id], tail, last = tail[:n], tail[n:], id
	}
	if len(tail) != 0 || len(fields[1]) != 2 || len(fields[2]) == 0 || !binaryASCII(fields[2], 95) || len(fields[3]) != 8 || len(fields[4]) != 8 || !revisionPattern.Match(fields[5]) {
		return r, errBinaryProtocol
	}
	r.status = int(binary.BigEndian.Uint16(fields[1]))
	r.media, r.revision = string(fields[2]), string(fields[5])
	r.length, r.representation = binary.BigEndian.Uint64(fields[3]), binary.BigEndian.Uint64(fields[4])
	if r.status < 200 || r.status > 599 || r.length > MaxDocumentBytes || r.representation > MaxDocumentBytes || (r.length != 0 && r.length != r.representation) || (r.status == 204 && (r.length != 0 || r.representation != 0)) || (r.status == 304 && r.length != 0) {
		return r, errBinaryProtocol
	}
	for id := 6; id <= 12; id++ {
		b := fields[id]
		if b == nil {
			continue
		}
		switch id {
		case 6:
			if len(b) != 18 || b[0] != '"' || b[17] != '"' || !revisionPattern.Match(b[1:17]) {
				return r, errBinaryProtocol
			}
			r.etag = string(b[1:17])
		case 7, 8:
			if !identifier.Match(b) {
				return r, errBinaryProtocol
			}
			if id == 7 {
				r.collection = string(b)
			} else {
				r.document = string(b)
			}
		case 9:
			if len(b) != 1 || b[0] == 0 || b[0] > byte(map[bool]int{true: 63, false: 15}[schema == 2]) || r.status != 405 {
				return r, errBinaryProtocol
			}
		case 10:
			if len(b) != 1 || b[0] != 1 || r.status != 401 {
				return r, errBinaryProtocol
			}
		case 11:
			if len(b) != 4 || (r.status != 429 && r.status != 503) {
				return r, errBinaryProtocol
			}
		case 12:
			if len(b) != 16 || bytes.Equal(b, make([]byte, 16)) {
				return r, errBinaryProtocol
			}
			r.id = hex.EncodeToString(b)
		}
	}
	if schema == 2 {
		if len(fields[13]) != 1 || fields[13][0] > 1 {
			return r, errBinaryProtocol
		}
		r.streaming = fields[13][0] == 1
		if r.streaming && (r.status != 200 || r.length != 0 || r.representation != 0) {
			return r, errBinaryProtocol
		}
	}
	return r, nil
}
func (r *binaryReply) correlate(method byte, collection, document, revision, id string) error {
	if r.id != id || (r.collection != "" && r.collection != collection) || (r.document != "" && r.document != document) {
		return errBinaryProtocol
	}
	if method == 2 {
		if r.length != 0 {
			return errBinaryProtocol
		}
	} else if r.length != r.representation {
		return errBinaryProtocol
	}
	media, _, err := mime.ParseMediaType(r.media)
	if err != nil {
		return errBinaryProtocol
	}
	if r.status >= 400 {
		if media != "application/json" || r.representation > 4096 {
			return errBinaryProtocol
		}
		return nil
	}
	switch method {
	case 1, 2:
		if r.status != 200 || (media != "application/yaml" && media != "text/yaml") || r.etag == "" || r.collection != collection || r.document != document || checkRevision(r.revision, revision) != nil {
			return errBinaryProtocol
		}
	case 3:
		if (r.status != 200 && r.status != 201) || media != "application/json" || r.length == 0 || r.length > 4096 || r.etag == "" {
			return errBinaryProtocol
		}
	case 4:
		if r.status != 204 || r.length != 0 || r.representation != 0 || media != "application/json" || r.etag != "" {
			return errBinaryProtocol
		}
	}
	return nil
}
func (w *binaryWire) response(method byte, collection, document, revision, id string) (r binaryReply, err error) {
	started := false
	for {
		f, err := w.receive()
		if err != nil {
			return r, err
		}
		if control, err := w.control(f); control {
			if err != nil {
				return r, err
			}
			continue
		}
		switch f.kind {
		case 3:
			if started {
				return r, errBinaryProtocol
			}
			r, err = binaryMetadata(f.payload)
			if err != nil {
				return r, err
			}
			if err = r.correlate(method, collection, document, revision, id); err != nil {
				return r, err
			}
			started = true
			r.body = make([]byte, 0, int(r.length))
		case 4:
			if !started || uint64(len(r.body)+len(f.payload)) > r.length {
				return r, errBinaryProtocol
			}
			r.body = append(r.body, f.payload...)
		case 5:
			if !started || uint64(len(r.body)) != r.length {
				return r, errBinaryProtocol
			}
			if r.status >= 400 {
				return r, &HTTPError{Status: r.status}
			}
			if method == 1 && !utf8.Valid(r.body) {
				return r, errBinaryProtocol
			}
			if method == 3 {
				if err = r.receipt(collection, document); err != nil {
					return r, err
				}
			}
			return r, nil
		case 7:
			// Generic nonzero ERROR codes cannot establish rejection or replay safety.
			if binary.BigEndian.Uint32(f.payload) == 0 {
				return r, errBinaryProtocol
			}
			return r, errBinaryTransport
		default:
			return r, errBinaryProtocol
		}
	}
}
func (r *binaryReply) receipt(collection, document string) error {
	if !utf8.Valid(r.body) {
		return errBinaryProtocol
	}
	// Decode exactly five distinct receipt keys; encoding/json's permissive
	// struct decoder alone would accept duplicate keys and missing identities.
	decoder := json.NewDecoder(bytes.NewReader(r.body))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return errBinaryProtocol
	}
	values := make(map[string]string, 5)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || len(values) >= 5 {
			return errBinaryProtocol
		}
		if _, exists := values[key]; exists {
			return errBinaryProtocol
		}
		var value string
		if decoder.Decode(&value) != nil {
			return errBinaryProtocol
		}
		values[key] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return errBinaryProtocol
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || len(values) != 5 || values["status"] != "stored" || values["collection"] != collection || values["document"] != document || values["revision"] != r.revision || values["etag"] != r.etag {
		return errBinaryProtocol
	}
	r.mutation = Mutation{Status: values["status"], ETag: r.etag, Revision: r.revision}
	return nil
}
