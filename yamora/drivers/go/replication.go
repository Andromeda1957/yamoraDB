package yamora

import (
	"bytes"
	"context"
	"errors"
	"time"
	"unicode/utf8"
)

// ErrSchemaPolicyReplicationUnsupported is a definite preflight refusal, before
// any destination stage is opened. Native transfer admission is authoritative.
var ErrSchemaPolicyReplicationUnsupported = errors.New("yamora: schema_policy_replication_unsupported")

// RequireReplicationSource reads source readiness for applications orchestrating
// low-level stages. An absent field supports older policy-free servers only.
func (c *Client) RequireReplicationSource(ctx context.Context) (Metadata, error) {
	ready, err := c.Ready(ctx)
	if err != nil {
		return nil, err
	}
	if value, advertised := ready["replication_policy_free"]; advertised {
		switch string(bytes.TrimSpace(value)) {
		case "true":
		case "false":
			return nil, ErrSchemaPolicyReplicationUnsupported
		default:
			return nil, errors.New("yamora: invalid replication source capability")
		}
	}
	return ready, nil
}

type ReplicaPosition struct {
	Status   string  `json:"status"`
	After    *string `json:"after"`
	Revision string  `json:"revision"`
}
type ReplicationResult struct {
	ReplicaPosition
	Commits int
}

func (c *Client) ReplicationStatus(ctx context.Context) (ReplicaPosition, error) {
	var position ReplicaPosition
	header, err := c.structured(ctx, "GET", "/v1/replication/status", nil, nil, false, MaxDocumentBytes, &position)
	if err != nil {
		return ReplicaPosition{}, err
	}
	if err = revisionFromBody(header, position.Revision); err != nil {
		return ReplicaPosition{}, err
	}
	if (position.Status != "uninitialized" && position.Status != "following") || (position.Status == "uninitialized" && position.After != nil) || (position.Status == "following" && (position.After == nil || !tokenPattern.MatchString(*position.After))) {
		return ReplicaPosition{}, errors.New("yamora: invalid replica position")
	}
	return position, nil
}

type replicaSession struct {
	Session  string  `json:"session"`
	Revision string  `json:"revision"`
	Status   string  `json:"status"`
	After    *string `json:"after"`
}

func (c *Client) replicaCall(ctx context.Context, path string, request, out any) error {
	_, err := c.structured(ctx, "POST", "/v1/replication/"+path, request, nil, true, MaxDocumentBytes, out)
	return err
}

func (c *Client) abortReplica(ctx context.Context, path, session string) {
	// Cleanup has its own bounded deadline, including when the transfer context
	// was cancelled. Abort cannot undo an already published transaction.
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	var ignored Metadata
	_ = c.replicaCall(cleanup, path+"abort", map[string]string{"session": session}, &ignored)
}

type replicaBatch struct {
	Session    string            `json:"session"`
	Operations []ChangeOperation `json:"operations"`
}
type replicaSender struct {
	client  *Client
	context context.Context
	path    string
	batch   replicaBatch
}

func (sender *replicaSender) flush() error {
	if len(sender.batch.Operations) == 0 {
		return nil
	}
	var result Metadata
	if err := sender.client.replicaCall(sender.context, sender.path+"apply", sender.batch, &result); err != nil {
		return err
	}
	sender.batch.Operations = nil
	return nil
}
func (sender *replicaSender) append(op ChangeOperation) error {
	if len(sender.batch.Operations) == 128 {
		if err := sender.flush(); err != nil {
			return err
		}
	}
	candidate := replicaBatch{Session: sender.batch.Session, Operations: append(sender.batch.Operations, op)}
	encoded, err := encode(candidate)
	if err != nil || (len(encoded) > 2*1024*1024 && len(candidate.Operations) > 1) {
		if len(sender.batch.Operations) == 0 {
			return err
		}
		if err = sender.flush(); err != nil {
			return err
		}
		candidate = replicaBatch{Session: sender.batch.Session, Operations: []ChangeOperation{op}}
		if _, err = encode(candidate); err != nil {
			return err
		}
	}
	sender.batch = candidate
	return nil
}

// ReplicateFrom bootstraps a native replica with change-feed support from a stable native source.
// Git YAML and indexes are copied as exact source; source changes abort staging.
func (c *Client) ReplicateFrom(ctx context.Context, source *Client) (ReplicaPosition, error) {
	if source == nil || source.base == c.base {
		return ReplicaPosition{}, errors.New("yamora: distinct source and destination required")
	}
	ready, err := source.RequireReplicationSource(ctx)
	if err != nil {
		return ReplicaPosition{}, err
	}
	if string(ready["storage"]) != `"native-disk-v2"` || string(ready["revision_scheme"]) != `"xor-fnv-v2"` || string(ready["change_feed"]) != "true" {
		return ReplicaPosition{}, errors.New("yamora: native source with change-feed support required")
	}
	checkpoint, err := source.Changes(ctx, "", 100)
	if err != nil {
		return ReplicaPosition{}, err
	}
	names, _, err := source.Collections(ctx, checkpoint.Revision)
	if err != nil {
		return ReplicaPosition{}, err
	}
	destination, err := c.ReplicationStatus(ctx)
	if err != nil {
		return ReplicaPosition{}, err
	}
	request := struct {
		Revision    string   `json:"revision"`
		Collections []string `json:"collections"`
		Full        bool     `json:"full"`
		Scheme      string   `json:"revision_scheme"`
		After       string   `json:"source_after"`
	}{checkpoint.Revision, names, true, "xor-fnv-v2", checkpoint.Checkpoint}
	var begun replicaSession
	if err = c.replicaCall(ctx, "begin", request, &begun); err != nil {
		return ReplicaPosition{}, err
	}
	if !identifier.MatchString(begun.Session) {
		return ReplicaPosition{}, errors.New("yamora: invalid bootstrap session")
	}
	committed := false
	defer func() {
		if !committed {
			c.abortReplica(ctx, "", begun.Session)
		}
	}()
	if begun.Revision != destination.Revision {
		return ReplicaPosition{}, errors.New("yamora: destination changed before bootstrap")
	}
	sender := replicaSender{client: c, context: ctx, batch: replicaBatch{Session: begun.Session}}
	for _, collection := range names {
		err = source.Documents(ctx, collection, checkpoint.Revision, func(id string) error {
			document, err := source.Get(ctx, collection, id, checkpoint.Revision)
			if err != nil {
				return err
			}
			if !utf8.Valid(document.Source) {
				return errors.New("yamora: invalid UTF-8 source")
			}
			text := string(document.Source)
			return sender.append(ChangeOperation{Collection: collection, Document: id, Put: &text})
		})
		if err != nil {
			return ReplicaPosition{}, err
		}
	}
	if err = sender.flush(); err != nil {
		return ReplicaPosition{}, err
	}
	current, err := source.Changes(ctx, "", 100)
	if err != nil {
		return ReplicaPosition{}, err
	}
	if current.Checkpoint != checkpoint.Checkpoint || current.Revision != checkpoint.Revision {
		return ReplicaPosition{}, errors.New("yamora: source changed during bootstrap")
	}
	if _, err = source.RequireReplicationSource(ctx); err != nil {
		return ReplicaPosition{}, err
	}
	var receipt Mutation
	if err = c.replicaCall(ctx, "commit", map[string]string{"session": begun.Session, "revision": checkpoint.Revision}, &receipt); err != nil {
		return ReplicaPosition{}, err
	}
	if receipt.Revision != checkpoint.Revision {
		return ReplicaPosition{}, errors.New("yamora: unexpected bootstrap revision")
	}
	committed = true
	position, err := c.ReplicationStatus(ctx)
	if err != nil {
		return ReplicaPosition{}, err
	}
	if position.After == nil || *position.After != checkpoint.Checkpoint || position.Revision != checkpoint.Revision {
		return ReplicaPosition{}, errors.New("yamora: inconsistent bootstrap checkpoint")
	}
	return position, nil
}

func (c *Client) replicateChange(ctx context.Context, after string, frame Change) (ReplicaPosition, error) {
	request := struct {
		After      string `json:"after"`
		Token      string `json:"token"`
		Before     string `json:"previous_revision"`
		Revision   string `json:"revision"`
		Operations int    `json:"operations"`
	}{after, frame.Token, frame.PreviousRevision, frame.Revision, len(frame.Operations)}
	var begun replicaSession
	if err := c.replicaCall(ctx, "follow/begin", request, &begun); err != nil {
		return ReplicaPosition{}, err
	}
	if begun.Status == "already_applied" {
		if begun.After == nil || *begun.After != frame.Token || begun.Revision != frame.Revision {
			return ReplicaPosition{}, errors.New("yamora: inconsistent duplicate receipt")
		}
		return ReplicaPosition{Status: "following", After: begun.After, Revision: begun.Revision}, nil
	}
	if !identifier.MatchString(begun.Session) {
		return ReplicaPosition{}, errors.New("yamora: invalid follow session")
	}
	committed := false
	defer func() {
		if !committed {
			c.abortReplica(ctx, "follow/", begun.Session)
		}
	}()
	sender := replicaSender{client: c, context: ctx, path: "follow/", batch: replicaBatch{Session: begun.Session}}
	for _, op := range frame.Operations {
		if err := sender.append(op); err != nil {
			return ReplicaPosition{}, err
		}
	}
	if err := sender.flush(); err != nil {
		return ReplicaPosition{}, err
	}
	var receipt ReplicaPosition
	if err := c.replicaCall(ctx, "follow/commit", map[string]string{"session": begun.Session}, &receipt); err != nil {
		return ReplicaPosition{}, err
	}
	if receipt.After == nil || *receipt.After != frame.Token || receipt.Revision != frame.Revision {
		return ReplicaPosition{}, errors.New("yamora: unexpected incremental checkpoint")
	}
	committed = true
	return receipt, nil
}

// FollowReplication starts from the destination's durable position. After a lost
// response, call it again: it reads the committed position without replaying an
// uncertain write. Reset/expired/foreign tokens require explicit ReplicateFrom.
func (c *Client) FollowReplication(ctx context.Context, source *Client, options FollowOptions, visit func(ReplicaPosition) error) (ReplicationResult, error) {
	return c.consumeReplication(ctx, source, func(after string, apply func(Change) error) (string, error) {
		return source.FollowChanges(ctx, after, options, apply)
	}, visit)
}

// StreamReplication applies one continuous source session from the destination's
// durable checkpoint. Data and progress publish before visit is called. A lost
// acknowledgement requires a new call, which reads the persisted checkpoint;
// writes are never retried and reset markers require explicit ReplicateFrom.
func (c *Client) StreamReplication(ctx context.Context, source *Client, options StreamOptions, visit func(ReplicaPosition) error) (ReplicationResult, error) {
	return c.consumeReplication(ctx, source, func(after string, apply func(Change) error) (string, error) {
		return source.StreamChanges(ctx, after, options, apply)
	}, visit)
}

func (c *Client) consumeReplication(ctx context.Context, source *Client, consume func(string, func(Change) error) (string, error), visit func(ReplicaPosition) error) (ReplicationResult, error) {
	if source == nil || source.base == c.base {
		return ReplicationResult{}, errors.New("yamora: distinct source and destination required")
	}
	if _, err := source.RequireReplicationSource(ctx); err != nil {
		return ReplicationResult{}, err
	}
	position, err := c.ReplicationStatus(ctx)
	if err != nil {
		return ReplicationResult{}, err
	}
	result := ReplicationResult{ReplicaPosition: position}
	if position.After == nil {
		return result, ErrResnapshotRequired
	}
	_, err = consume(*position.After, func(frame Change) error {
		if _, err := source.RequireReplicationSource(ctx); err != nil {
			return err
		}
		if frame.PreviousRevision != result.Revision {
			return errors.New("yamora: source history does not match replica")
		}
		next, err := c.replicateChange(ctx, *result.After, frame)
		if err != nil {
			return err
		}
		result.ReplicaPosition = next
		result.Commits++
		if visit != nil {
			// The visitor owns its receipt. Its pointer-valued checkpoint must
			// not alias the position used to prepare the next transfer.
			token := *next.After
			next.After = &token
			return visit(next)
		}
		return nil
	})
	return result, err
}

func (c *Client) ReplicateChangesFrom(ctx context.Context, source *Client) (ReplicationResult, error) {
	return c.FollowReplication(ctx, source, FollowOptions{}, nil)
}
