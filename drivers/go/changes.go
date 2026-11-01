package yamora

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

var ErrResnapshotRequired = errors.New("yamora: source requires a new snapshot")

type ChangeOperation struct {
	Collection       string  `json:"collection"`
	Document         string  `json:"document,omitempty"`
	Put              *string `json:"put,omitempty"`
	Delete           bool    `json:"delete,omitempty"`
	CreateCollection bool    `json:"create_collection,omitempty"`
}
type Change struct {
	Token              string            `json:"token"`
	PreviousRevision   string            `json:"previous_revision"`
	Revision           string            `json:"revision"`
	ResnapshotRequired bool              `json:"resnapshot_required"`
	Operations         []ChangeOperation `json:"operations"`
}
type ChangePage struct {
	Transactions []Change `json:"transactions"`
	NextAfter    string   `json:"next_after"`
	Checkpoint   string   `json:"checkpoint"`
	OldestAfter  string   `json:"oldest_after"`
	Revision     string   `json:"revision"`
	HasMore      bool     `json:"has_more"`
}

// Changes returns whole commits. Empty after obtains only the current checkpoint.
func (c *Client) Changes(ctx context.Context, after string, limit int) (ChangePage, error) {
	if limit == 0 {
		limit = 100
	}
	if limit < 1 || limit > 100 || (after != "" && !tokenPattern.MatchString(after)) {
		return ChangePage{}, errors.New("yamora: invalid change request")
	}
	path := "/v1/changes"
	if after != "" {
		path += fmt.Sprintf("?after=%s&limit=%d", after, limit)
	}
	var raw json.RawMessage
	header, err := c.structured(ctx, "GET", path, nil, nil, false, MaxResponseBytes, &raw)
	if err != nil {
		return ChangePage{}, err
	}
	return decodeChangePage(raw, header, after, limit)
}

func decodeChangePage(raw json.RawMessage, header http.Header, after string, limit int) (ChangePage, error) {
	var page ChangePage
	var err error
	if err = json.Unmarshal(raw, &page); err != nil {
		return ChangePage{}, errors.New("yamora: invalid change page")
	}
	invalid := func() (ChangePage, error) { return ChangePage{}, errors.New("yamora: invalid change page or progress") }
	for _, token := range []string{page.NextAfter, page.Checkpoint, page.OldestAfter} {
		if !tokenPattern.MatchString(token) {
			return invalid()
		}
	}
	if err = revisionFromBody(header, page.Revision); err != nil {
		return ChangePage{}, err
	}
	if page.Transactions == nil || len(page.Transactions) > limit || page.NextAfter[:36] != page.Checkpoint[:36] || page.OldestAfter[:36] != page.Checkpoint[:36] || page.OldestAfter > page.NextAfter || page.NextAfter > page.Checkpoint || page.HasMore != (page.NextAfter < page.Checkpoint) {
		return invalid()
	}
	if after != "" && (after[:36] != page.NextAfter[:36] || after > page.NextAfter) {
		return invalid()
	}
	var object struct {
		Transactions []json.RawMessage `json:"transactions"`
		HasMore      *bool             `json:"has_more"`
	}
	if json.Unmarshal(raw, &object) != nil || object.HasMore == nil {
		return invalid()
	}
	previous := after
	previousRevision := ""
	if after == "" && len(page.Transactions) > 0 {
		return invalid()
	}
	for i, frame := range page.Transactions {
		var rawFrame struct {
			Reset      *bool                        `json:"resnapshot_required"`
			Operations []map[string]json.RawMessage `json:"operations"`
		}
		if json.Unmarshal(object.Transactions[i], &rawFrame) != nil || rawFrame.Reset == nil {
			return invalid()
		}
		if !tokenPattern.MatchString(frame.Token) || frame.Token[:36] != page.Checkpoint[:36] || frame.Token <= previous || frame.Token > page.Checkpoint || !revisionPattern.MatchString(frame.PreviousRevision) || !revisionPattern.MatchString(frame.Revision) || (previousRevision != "" && previousRevision != frame.PreviousRevision) || frame.Operations == nil || len(frame.Operations) > 256 || (frame.ResnapshotRequired && len(frame.Operations) > 0) {
			return invalid()
		}
		seen := make(map[string]bool)
		sourceBytes := 0
		for j, op := range frame.Operations {
			key := op.Collection + "/" + op.Document
			if !identifier.MatchString(op.Collection) || seen[key] {
				return invalid()
			}
			seen[key] = true
			fields := rawFrame.Operations[j]
			if op.Document == "" {
				if !op.CreateCollection || op.Put != nil || op.Delete || len(fields) != 2 {
					return invalid()
				}
			} else {
				if !identifier.MatchString(op.Document) || op.CreateCollection || (op.Put != nil) == op.Delete || len(fields) != 3 {
					return invalid()
				}
				if op.Put != nil {
					sourceBytes += len(*op.Put)
					if len(*op.Put) == 0 || len(*op.Put) > MaxDocumentBytes {
						return invalid()
					}
				}
			}
		}
		if sourceBytes > MaxDocumentBytes {
			return invalid()
		}
		previous, previousRevision = frame.Token, frame.Revision
	}
	if len(page.Transactions) > 0 {
		if previous != page.NextAfter {
			return invalid()
		}
	} else if page.HasMore || (after != "" && after != page.NextAfter) {
		return invalid()
	}
	return page, nil
}

type FollowOptions struct {
	Continuous   bool
	PollInterval time.Duration
	Limit        int
}

// FollowChanges advances only after visit succeeds for a whole commit. Persist
// the callback's effects and token atomically in the consumer's own storage.
// A reset marker returns ErrResnapshotRequired without advancing past it.
func (c *Client) FollowChanges(ctx context.Context, after string, options FollowOptions, visit func(Change) error) (string, error) {
	if !tokenPattern.MatchString(after) || visit == nil {
		return after, errors.New("yamora: checkpoint and visitor required")
	}
	if options.PollInterval == 0 {
		options.PollInterval = 250 * time.Millisecond
	}
	if options.PollInterval < 0 || options.PollInterval > time.Minute {
		return after, errors.New("yamora: invalid polling interval")
	}
	for {
		page, err := c.Changes(ctx, after, options.Limit)
		if err != nil {
			return after, err
		}
		for _, frame := range page.Transactions {
			if frame.ResnapshotRequired {
				return after, ErrResnapshotRequired
			}
			if err = visit(frame); err != nil {
				return after, err
			}
			after = frame.Token
		}
		if page.HasMore {
			continue
		}
		if !options.Continuous {
			return after, nil
		}
		timer := time.NewTimer(options.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return after, ctx.Err()
		case <-timer.C:
		}
	}
}
