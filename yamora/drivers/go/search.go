package yamora

import (
	"context"
	"encoding/json"
	"errors"
)

type Search struct {
	Index    string         `json:"index"`
	Text     string         `json:"text"`
	Mode     string         `json:"mode,omitempty"`
	Filter   map[string]any `json:"filter,omitempty"`
	Limit    int            `json:"limit,omitempty"`
	After    string         `json:"after,omitempty"`
	Revision string         `json:"revision,omitempty"`
}
type SearchRow struct {
	ID    string          `json:"id"`
	Score uint32          `json:"score"`
	Value json.RawMessage `json:"value"`
}
type SearchResult struct {
	Documents            []SearchRow `json:"documents"`
	Revision             string      `json:"revision"`
	NextAfter            *string     `json:"next_after"`
	DocumentsExamined    uint64      `json:"documents_examined"`
	IndexEntriesExamined uint64      `json:"index_entries_examined"`
}

// Search merges native postings without scanning source documents. Results are
// ordered by ID; Score counts matched distinct terms, rather than a TF-IDF rank.
func (c *Client) Search(ctx context.Context, collection string, spec Search) (SearchResult, error) {
	if !identifier.MatchString(collection) || !identifier.MatchString(spec.Index) || spec.Text == "" || len(spec.Text) > 8192 || (spec.Mode != "" && spec.Mode != "all" && spec.Mode != "any") || spec.Limit < 0 || spec.Limit > 1000 || !validRevisionOption(spec.Revision) || (spec.After != "" && (!identifier.MatchString(spec.After) || spec.Revision == "")) {
		return SearchResult{}, errors.New("yamora: invalid search arguments")
	}
	var raw json.RawMessage
	header, err := c.structured(ctx, "POST", "/v1/search/"+collection, spec, nil, false, MaxResponseBytes, &raw)
	if err != nil {
		return SearchResult{}, err
	}
	var wire struct {
		Documents            []SearchRow `json:"documents"`
		Revision             string      `json:"revision"`
		NextAfter            *string     `json:"next_after"`
		DocumentsExamined    *uint64     `json:"documents_examined"`
		IndexEntriesExamined *uint64     `json:"index_entries_examined"`
	}
	limit := spec.Limit
	if limit == 0 {
		limit = 100
	}
	if err = json.Unmarshal(raw, &wire); err != nil || wire.Documents == nil || len(wire.Documents) > limit || wire.DocumentsExamined == nil || wire.IndexEntriesExamined == nil || !hasJSONKey(raw, "next_after") {
		return SearchResult{}, errors.New("yamora: invalid search result")
	}
	result := SearchResult{Documents: wire.Documents, Revision: wire.Revision, NextAfter: wire.NextAfter, DocumentsExamined: *wire.DocumentsExamined, IndexEntriesExamined: *wire.IndexEntriesExamined}
	if err = revisionFromBody(header, result.Revision); err != nil {
		return SearchResult{}, err
	}
	if err = checkRevision(result.Revision, spec.Revision); err != nil {
		return SearchResult{}, err
	}
	if result.DocumentsExamined < uint64(len(result.Documents)) || result.IndexEntriesExamined < result.DocumentsExamined {
		return SearchResult{}, errors.New("yamora: invalid search statistics")
	}
	previous := spec.After
	for _, row := range result.Documents {
		if !identifier.MatchString(row.ID) || row.ID <= previous || row.Score == 0 || row.Score > 32 || len(row.Value) == 0 {
			return SearchResult{}, errors.New("yamora: invalid search row")
		}
		previous = row.ID
	}
	if result.NextAfter != nil && (len(result.Documents) == 0 || *result.NextAfter != previous) {
		return SearchResult{}, errors.New("yamora: invalid search cursor")
	}
	return result, nil
}
