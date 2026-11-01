package yamora

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"
	"unicode/utf8"
)

const binaryALPN = "yamora-binary/1"

// BinaryConfig selects one numeric loopback/RFC1918 IPv4 TLS endpoint. No DNS,
// discovery, proxy, routing or replay is performed. MaxConcurrentCalls is 1..4
// (default 4); MaxFrameBytes is 4096..65536 (default 65536). Timeout defaults to
// five seconds and cannot exceed 30 seconds. Each call owns its connection.
// TLSConfig requires verification; dynamic callbacks/key logging are unsupported.
// Credentials, certificates, private keys and trust roots are copied by NewBinary.
// RootCAPEM is required: at most 64 KiB and 32 CERTIFICATE PEM blocks, freshly
// parsed into owned roots. TLSConfig.RootCAs must be nil; opaque pools can retain
// caller-owned certificates and constraints. No system/fallback roots are used.
type BinaryConfig struct {
	Address               netip.AddrPort
	TLSConfig             *tls.Config
	RootCAPEM             []byte
	ReadToken, WriteToken string
	Timeout               time.Duration
	MaxFrameBytes         int
	MaxConcurrentCalls    int
}

// BinaryClient is safe for concurrent calls. Source CRUD uses schema 1; explicit
// operations and page feeds negotiate the additive native schema 2.
// No persistent connections or background workers need closing.
type BinaryClient struct {
	address               string
	secure                *tls.Config
	readToken, writeToken string
	timeout               time.Duration
	frame                 int
	slots                 chan struct{}
}

// BinaryHead describes a representation without transferring its YAML body.
type BinaryHead struct {
	Length         uint64
	ETag, Revision string
}

// BinaryMutationEnvelope is an owned original request without credentials.
// Source returns a defensive copy. Persist sensitive source separately with care.
type BinaryMutationEnvelope struct {
	Method, Collection, Document string
	Target, ContentType          string
	Conditions                   map[string]string
	Options                      WriteOptions
	source                       []byte
}

func (e BinaryMutationEnvelope) Source() []byte { return bytes.Clone(e.source) }
func (e BinaryMutationEnvelope) String() string {
	return "yamora: binary mutation envelope (source redacted)"
}
func (e BinaryMutationEnvelope) GoString() string { return e.String() }

// BinaryUncertainWriteError means a dispatched mutation lacks a validated terminal
// receipt. The original ID does not imply standalone deduplication. No retry is
// automatic. Envelope returns a defensive copy of the frozen primitive request.
type BinaryUncertainWriteError struct {
	RequestID string
	envelope  BinaryMutationEnvelope
	cause     error
}

func (e *BinaryUncertainWriteError) Error() string {
	return "yamora: binary write outcome uncertain; retain original request ID and envelope"
}
func (e *BinaryUncertainWriteError) GoString() string { return e.Error() }
func (e *BinaryUncertainWriteError) Unwrap() error    { return e.cause }
func (e *BinaryUncertainWriteError) Envelope() BinaryMutationEnvelope {
	result := e.envelope
	result.source = bytes.Clone(result.source)
	result.Conditions = copyBinaryConditions(result.Conditions)
	return result
}

var errBinaryProtocol = errors.New("yamora: invalid binary response")
var errBinaryTransport = errors.New("yamora: binary transport failed")

// ErrBinaryProtocol identifies an invalid binary peer response. Use errors.Is;
// dispatched mutation failures may wrap it in BinaryUncertainWriteError.
var ErrBinaryProtocol = errBinaryProtocol

// ErrBinaryTransport identifies a failed binary exchange without exposing peer
// text. Deadline and cancellation failures retain the standard context errors.
// Use errors.Is, including through BinaryUncertainWriteError.
var ErrBinaryTransport = errBinaryTransport

func NewBinary(config BinaryConfig) (*BinaryClient, error) {
	addr := config.Address.Addr()
	if !config.Address.IsValid() || config.Address.Port() == 0 || !addr.Is4() || !(addr.IsLoopback() || addr.IsPrivate()) {
		return nil, errors.New("yamora: numeric IPv4 loopback or RFC1918 address required")
	}
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second
	}
	if config.Timeout < 0 || config.Timeout > 30*time.Second {
		return nil, errors.New("yamora: invalid binary timeout")
	}
	if config.MaxFrameBytes == 0 {
		config.MaxFrameBytes = 65536
	}
	if config.MaxFrameBytes < 4096 || config.MaxFrameBytes > 65536 {
		return nil, errors.New("yamora: invalid binary frame limit")
	}
	if config.MaxConcurrentCalls == 0 {
		config.MaxConcurrentCalls = 4
	}
	if config.MaxConcurrentCalls < 1 || config.MaxConcurrentCalls > 4 {
		return nil, errors.New("yamora: invalid binary concurrency limit")
	}
	for _, token := range []string{config.ReadToken, config.WriteToken} {
		if len(token) > 512 {
			return nil, errors.New("yamora: invalid credential")
		}
		for i := range token {
			if token[i] < 33 || token[i] > 126 {
				return nil, errors.New("yamora: invalid credential")
			}
		}
	}
	secure, err := binaryTLSConfig(config.TLSConfig, config.RootCAPEM)
	if err != nil {
		return nil, err
	}
	return &BinaryClient{address: config.Address.String(), secure: secure,
		readToken: config.ReadToken, writeToken: config.WriteToken, timeout: config.Timeout,
		frame: config.MaxFrameBytes, slots: make(chan struct{}, config.MaxConcurrentCalls)}, nil
}

func binaryTLSConfig(input *tls.Config, rootCAPEM []byte) (*tls.Config, error) {
	invalid := errors.New("yamora: binary TLS requires copied static identity, verified peers and TLS 1.3")
	if input == nil || input.InsecureSkipVerify || (input.MinVersion != 0 && input.MinVersion != tls.VersionTLS13) || (input.MaxVersion != 0 && input.MaxVersion != tls.VersionTLS13) || input.GetClientCertificate != nil || input.GetCertificate != nil || input.GetConfigForClient != nil || input.VerifyConnection != nil || input.VerifyPeerCertificate != nil || input.Time != nil || input.Rand != nil || input.KeyLogWriter != nil || input.ClientSessionCache != nil {
		return nil, invalid
	}
	if input.RootCAs != nil {
		return nil, errors.New("yamora: binary TLS rejects opaque RootCAs pools; supply RootCAPEM")
	}
	roots, err := binaryRootCAs(rootCAPEM)
	if err != nil {
		return nil, err
	}
	// Construct from the supported fields; do not retain mutable caller slices,
	// maps, roots, keys, session caches or callback closures through Config.Clone.
	result := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		ServerName: input.ServerName, NextProtos: []string{binaryALPN}, SessionTicketsDisabled: true, RootCAs: roots}
	if len(input.Certificates) > 1 {
		return nil, invalid
	}
	for _, identity := range input.Certificates {
		if len(identity.Certificate) == 0 {
			return nil, invalid
		}
		var copied tls.Certificate
		for _, der := range identity.Certificate {
			copied.Certificate = append(copied.Certificate, bytes.Clone(der))
		}
		encoded, err := x509.MarshalPKCS8PrivateKey(identity.PrivateKey)
		if err != nil {
			return nil, invalid
		}
		copied.PrivateKey, err = x509.ParsePKCS8PrivateKey(encoded)
		clear(encoded)
		if err != nil {
			return nil, invalid
		}
		copied.OCSPStaple = bytes.Clone(identity.OCSPStaple)
		for _, stamp := range identity.SignedCertificateTimestamps {
			copied.SignedCertificateTimestamps = append(copied.SignedCertificateTimestamps, bytes.Clone(stamp))
		}
		result.Certificates = append(result.Certificates, copied)
	}
	return result, nil
}

func binaryRootCAs(rootCAPEM []byte) (*x509.CertPool, error) {
	invalid := errors.New("yamora: binary RootCAPEM requires 1..32 certificate PEM blocks within 64 KiB")
	if len(rootCAPEM) == 0 || len(rootCAPEM) > 64*1024 {
		return nil, invalid
	}
	// Neither a caller's pool nor its Certificate objects/callbacks are retained.
	// Parsing only owned bytes also freezes Raw, validity and public-key fields.
	remaining := bytes.Clone(rootCAPEM)
	roots := x509.NewCertPool()
	count := 0
	for len(bytes.TrimSpace(remaining)) != 0 {
		remaining = bytes.TrimSpace(remaining)
		if count == 32 || !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, invalid
		}
		end := bytes.Index(remaining, []byte("-----END CERTIFICATE-----"))
		if end < 0 {
			return nil, invalid
		}
		end += len("-----END CERTIFICATE-----")
		// Decode one exact block: pem.Decode otherwise skips malformed blocks
		// while searching for a later valid one, silently changing the input.
		chunk := remaining[:end]
		if bytes.Count(chunk, []byte("-----BEGIN ")) != 1 {
			return nil, invalid
		}
		block, tail := pem.Decode(chunk)
		if block == nil || len(tail) != 0 || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, invalid
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, invalid
		}
		roots.AddCert(certificate)
		count++
		remaining = remaining[end:]
	}
	if count == 0 {
		return nil, invalid
	}
	return roots, nil
}

func (c *BinaryClient) Get(ctx context.Context, collection, document, revision string) (Document, error) {
	response, err := c.call(ctx, 1, collection, document, nil, WriteOptions{}, revision)
	if err != nil {
		return Document{}, err
	}
	return Document{Source: response.body, ETag: response.etag, Revision: response.revision}, nil
}
func (c *BinaryClient) Head(ctx context.Context, collection, document, revision string) (BinaryHead, error) {
	response, err := c.call(ctx, 2, collection, document, nil, WriteOptions{}, revision)
	if err != nil {
		return BinaryHead{}, err
	}
	return BinaryHead{Length: response.representation, ETag: response.etag, Revision: response.revision}, nil
}
func (c *BinaryClient) Put(ctx context.Context, collection, document string, source []byte, options WriteOptions) (Mutation, error) {
	response, err := c.call(ctx, 3, collection, document, source, options, "")
	if err != nil {
		return Mutation{}, err
	}
	return response.mutation, nil
}
func (c *BinaryClient) Delete(ctx context.Context, collection, document, etag string) error {
	_, err := c.call(ctx, 4, collection, document, nil, WriteOptions{ETag: etag}, "")
	return err
}

func (c *BinaryClient) call(parent context.Context, method byte, collection, document string, source []byte, options WriteOptions, revision string) (reply binaryReply, err error) {
	return c.exchange(parent, method, collection, document, source, options, revision, nil)
}
func (c *BinaryClient) exchange(parent context.Context, method byte, collection, document string, source []byte, options WriteOptions, revision string, operation *binaryOperation) (reply binaryReply, err error) {
	// A single monotonic deadline includes local validation/admission, dial, TLS,
	// negotiation, all fragments, semantic decoding and the terminal END.
	ctx, cancel := context.WithTimeout(parent, c.timeout)
	defer cancel()
	path, err := documentPath(collection, document)
	if operation != nil {
		path, err = operation.target, nil
	}
	if err != nil {
		return reply, err
	}
	if !validRevisionOption(revision) {
		return reply, errors.New("yamora: invalid revision")
	}
	headers, err := options.headers()
	if err != nil {
		return reply, err
	}
	if method == 3 && (len(source) == 0 || len(source) > MaxDocumentBytes || !utf8.Valid(source)) {
		return reply, errors.New("yamora: invalid document size or UTF-8")
	}
	write := method >= 3
	if operation != nil {
		write = operation.mutation
	}
	id, _ := parent.Value(requestIDKey{}).(string)
	if (write || operation != nil) && id == "" {
		var random [16]byte
		for id == "" || id == "00000000000000000000000000000000" {
			if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
				return reply, errors.New("yamora: request identity unavailable")
			}
			id = hex.EncodeToString(random[:])
		}
	}
	token := c.readToken
	if write {
		token = c.writeToken
	}
	if ctx.Err() != nil {
		return reply, ctx.Err()
	}
	select {
	case c.slots <- struct{}{}:
	case <-ctx.Done():
		return reply, ctx.Err()
	}
	defer func() { <-c.slots }()
	// Waiting callers retain only their caller-owned input; at most four calls
	// allocate a frozen 16 MiB upload and a bounded response at a time.
	source = bytes.Clone(source)
	if operation != nil {
		operation.source = source
	}
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp4", c.address)
	if err != nil {
		return reply, binaryIOError(ctx)
	}
	defer raw.Close()
	// Cancellation touches only this call's socket. Join the callback before any
	// owners leave scope, even when it races with a successful terminal receipt.
	joined := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { raw.Close(); close(joined) })
	defer func() {
		if !stop() {
			<-joined
		}
	}()
	deadline, _ := ctx.Deadline()
	if raw.SetDeadline(deadline) != nil {
		return reply, binaryIOError(ctx)
	}
	secure := c.secure.Clone()
	if secure.ServerName == "" {
		secure.ServerName = netip.MustParseAddrPort(c.address).Addr().String()
	}
	conn := tls.Client(raw, secure)
	// Close the raw socket, avoiding TLS close_notify's independent write budget.
	if conn.HandshakeContext(ctx) != nil {
		return reply, binaryIOError(ctx)
	}
	state := conn.ConnectionState()
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != binaryALPN || len(state.VerifiedChains) == 0 {
		return reply, errBinaryProtocol
	}
	wire := binaryWire{conn: conn, cap: c.frame}
	protocol := uint16(1)
	if operation != nil {
		protocol = 2
	}
	if err = wire.helloProtocol(protocol); err != nil {
		return reply, binaryCallError(ctx, err)
	}
	remaining := time.Until(deadline)
	if ctx.Err() != nil {
		return reply, ctx.Err()
	}
	if remaining <= 0 {
		return reply, context.DeadlineExceeded
	}
	timeoutMS := max(1, min(30000, int(remaining/time.Millisecond)))
	metadata := binaryRequest(method, path, source, token, headers.Get("If-Match"), headers.Get("If-None-Match"), id, timeoutMS)
	if operation != nil {
		metadata = operation.metadata(source, token, id, timeoutMS)
	}
	// Set uncertainty BEFORE the first request-frame write: a failed TLS write
	// can have transmitted bytes even when the API reports no progress.
	dispatched := false
	defer func() {
		if err == nil && (ctx.Err() != nil || !time.Now().Before(deadline)) {
			err = binaryIOError(ctx)
			if err == errBinaryTransport {
				err = context.DeadlineExceeded
			}
		}
		if err != nil && write && dispatched {
			var rejected *HTTPError
			if !errors.As(err, &rejected) || rejected.Status == 408 || rejected.Status >= 500 {
				names := [...]string{"", "GET", "HEAD", "PUT", "DELETE", "POST", "PATCH"}
				env := BinaryMutationEnvelope{Method: names[method], Collection: collection, Document: document, Options: options, source: source}
				if operation != nil {
					env.Target = path
					env.ContentType = operation.media
					env.Conditions = copyBinaryConditions(operation.conditions)
				}
				err = &BinaryUncertainWriteError{RequestID: id, envelope: env, cause: err}
			}
		}
	}()
	dispatched = true
	if err = wire.send(2, 1, metadata); err != nil {
		return reply, binaryCallError(ctx, err)
	}
	for offset := 0; offset < len(source); {
		end := min(len(source), offset+wire.cap)
		if err = wire.send(4, 1, source[offset:end]); err != nil {
			return reply, binaryCallError(ctx, err)
		}
		offset = end
	}
	if err = wire.send(5, 1, nil); err != nil {
		return reply, binaryCallError(ctx, err)
	}
	if operation != nil {
		reply, err = wire.operationResponse(ctx, operation, id)
	} else {
		reply, err = wire.response(method, collection, document, revision, id)
	}
	if err != nil {
		return reply, binaryCallError(ctx, err)
	}
	return reply, nil
}
func binaryIOError(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return errBinaryTransport
}
func binaryCallError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, errBinaryTransport) {
		return binaryIOError(ctx)
	}
	return err
}

// Format deliberately avoids reflecting the retained private source in errors.
func (e *BinaryUncertainWriteError) Format(s fmt.State, verb rune) { io.WriteString(s, e.Error()) }
