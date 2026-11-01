package yamora

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
)

// AggregateResult contains reduced objects rather than source document envelopes.
// RawMessage preserves signed 64-bit integers without a float64 conversion.
type AggregateResult struct {
	Documents         []json.RawMessage `json:"documents"`
	Revision          string            `json:"revision"`
	DocumentsExamined uint64            `json:"documents_examined"`
}

// Aggregate reduces a pinned native disk generation. The server validates all
// stages before scanning. Use Sort for ordered compound $sort specifications.
func (c *Client) Aggregate(ctx context.Context, collection string, pipeline []map[string]any, revision string) (AggregateResult, error) {
	if !identifier.MatchString(collection) || !validRevisionOption(revision) || len(pipeline) == 0 || len(pipeline) > 32 {
		return AggregateResult{}, errors.New("yamora: invalid aggregation arguments")
	}
	request := map[string]any{"pipeline": pipeline}
	if revision != "" {
		request["revision"] = revision
	}
	var raw json.RawMessage
	header, err := c.structured(ctx, "POST", "/v1/aggregate/"+collection, request, nil, false, MaxResponseBytes, &raw)
	if err != nil {
		return AggregateResult{}, err
	}
	var wire struct {
		Documents         []json.RawMessage `json:"documents"`
		Revision          string            `json:"revision"`
		DocumentsExamined *uint64           `json:"documents_examined"`
	}
	if err = json.Unmarshal(raw, &wire); err != nil || wire.Documents == nil || len(wire.Documents) > 65536 || wire.DocumentsExamined == nil {
		return AggregateResult{}, errors.New("yamora: invalid aggregation result")
	}
	result := AggregateResult{Documents: wire.Documents, Revision: wire.Revision, DocumentsExamined: *wire.DocumentsExamined}
	if err = revisionFromBody(header, result.Revision); err != nil {
		return AggregateResult{}, err
	}
	if err = checkRevision(result.Revision, revision); err != nil {
		return AggregateResult{}, err
	}
	for _, document := range result.Documents {
		if body := bytes.TrimSpace(document); len(body) == 0 || body[0] != '{' {
			return AggregateResult{}, errors.New("yamora: invalid aggregation row")
		}
	}
	return result, nil
}
