package yamora

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"unicode/utf8"
)

// Sort preserves the caller's compound ordering. A Go map cannot express it.
type SortField struct {
	Path       string
	Descending bool
}
type Sort []SortField

func (fields Sort) MarshalJSON() ([]byte, error) {
	if len(fields) > 8 {
		return nil, errors.New("yamora: at most eight sort fields")
	}
	var output bytes.Buffer
	output.WriteByte('{')
	seen := make(map[string]bool)
	for i, field := range fields {
		if field.Path == "" || seen[field.Path] {
			return nil, errors.New("yamora: invalid sort field")
		}
		seen[field.Path] = true
		key, err := json.Marshal(field.Path)
		if err != nil {
			return nil, err
		}
		if i > 0 {
			output.WriteByte(',')
		}
		output.Write(key)
		if field.Descending {
			output.WriteString(`:-1`)
		} else {
			output.WriteString(`:1`)
		}
	}
	output.WriteByte('}')
	return output.Bytes(), nil
}

type Query struct {
	Filter       map[string]any `json:"filter,omitempty"`
	Sort         Sort           `json:"sort,omitempty"`
	Projection   []string       `json:"projection,omitempty"`
	Limit        int            `json:"limit,omitempty"`
	After        string         `json:"after,omitempty"`
	Revision     string         `json:"revision,omitempty"`
	CountOnly    bool           `json:"count_only,omitempty"`
	Explain      bool           `json:"explain,omitempty"`
	IncludeCount *bool          `json:"include_count,omitempty"`
}
type Row struct {
	ID    string          `json:"id"`
	Value json.RawMessage `json:"value"`
}
type QueryResult struct {
	Documents []Row           `json:"documents"`
	Matched   *uint64         `json:"matched"`
	NextAfter *string         `json:"next_after"`
	Revision  string          `json:"revision"`
	Explain   json.RawMessage `json:"explain,omitempty"`
}

func (c *Client) Query(ctx context.Context, collection string, query Query) (QueryResult, error) {
	if !identifier.MatchString(collection) || !validRevisionOption(query.Revision) || query.Limit < 0 || query.Limit > 1000 || len(query.Projection) > 64 || (query.After != "" && (!identifier.MatchString(query.After) || query.Revision == "" || query.CountOnly)) {
		return QueryResult{}, errors.New("yamora: invalid query arguments")
	}
	var raw json.RawMessage
	header, err := c.structured(ctx, "POST", "/v1/query/"+collection, query, nil, false, MaxResponseBytes, &raw)
	if err != nil {
		return QueryResult{}, err
	}
	var result QueryResult
	if err = json.Unmarshal(raw, &result); err != nil || result.Documents == nil || len(result.Documents) > 1000 || !hasJSONKey(raw, "next_after") || !hasJSONKey(raw, "matched") {
		return QueryResult{}, errors.New("yamora: invalid query result")
	}
	if err = revisionFromBody(header, result.Revision); err != nil {
		return QueryResult{}, err
	}
	if err = checkRevision(result.Revision, query.Revision); err != nil {
		return QueryResult{}, err
	}
	if (result.Matched == nil && (query.CountOnly || query.IncludeCount == nil || *query.IncludeCount)) || (result.Matched != nil && *result.Matched < uint64(len(result.Documents))) || (result.NextAfter != nil && !identifier.MatchString(*result.NextAfter)) {
		return QueryResult{}, errors.New("yamora: invalid query count or cursor")
	}
	for _, row := range result.Documents {
		if !identifier.MatchString(row.ID) || len(row.Value) == 0 {
			return QueryResult{}, errors.New("yamora: invalid query row")
		}
	}
	if query.Explain && (len(result.Explain) == 0 || result.Explain[0] != '{') {
		return QueryResult{}, errors.New("yamora: missing query explanation")
	}
	return result, nil
}

func (c *Client) Count(ctx context.Context, collection string, filter map[string]any, revision string) (uint64, error) {
	result, err := c.Query(ctx, collection, Query{Filter: filter, Revision: revision, CountOnly: true})
	if err != nil {
		return 0, err
	}
	return *result.Matched, nil
}

func (c *Client) Patch(ctx context.Context, collection, document string, operations map[string]any, etag string) (Mutation, error) {
	path, err := documentPath(collection, document)
	if err != nil {
		return Mutation{}, err
	}
	if len(operations) == 0 {
		return Mutation{}, errors.New("yamora: empty patch")
	}
	headers, err := (WriteOptions{ETag: etag}).headers()
	if err != nil {
		return Mutation{}, err
	}
	var result Mutation
	response, err := c.structured(ctx, "PATCH", path, operations, headers, true, MaxDocumentBytes, &result)
	if err != nil {
		return Mutation{}, err
	}
	if err = revisionFromBody(response, result.Revision); err != nil {
		return Mutation{}, err
	}
	if result.Status != "stored" || !revisionPattern.MatchString(result.ETag) {
		return Mutation{}, errors.New("yamora: invalid patch result")
	}
	return result, nil
}

type Index struct {
	Collection string   `json:"collection"`
	Name       string   `json:"name"`
	Fields     []string `json:"fields"`
	Unique     bool     `json:"unique"`
	Type       string   `json:"type,omitempty"`
}
type IndexCatalog struct {
	Indexes  []Index `json:"indexes"`
	Revision string  `json:"revision"`
}

func validIndexes(indexes []Index) bool {
	if indexes == nil || len(indexes) > 64 {
		return false
	}
	seen := make(map[string]bool)
	for _, index := range indexes {
		key := index.Collection + "/" + index.Name
		if !identifier.MatchString(index.Collection) || !identifier.MatchString(index.Name) || len(index.Fields) == 0 || len(index.Fields) > 8 || seen[key] || (index.Type != "" && index.Type != "text") || (index.Type == "text" && index.Unique) {
			return false
		}
		seen[key] = true
		paths := make(map[string]bool)
		for _, path := range index.Fields {
			if path == "" || paths[path] || (path == "$source" && (index.Type != "text" || len(index.Fields) != 1)) {
				return false
			}
			paths[path] = true
		}
	}
	return true
}

func (c *Client) Indexes(ctx context.Context) (IndexCatalog, error) {
	var result IndexCatalog
	header, err := c.structured(ctx, "GET", "/v1/indexes", nil, nil, false, MaxResponseBytes, &result)
	if err != nil {
		return IndexCatalog{}, err
	}
	if !validIndexes(result.Indexes) {
		return IndexCatalog{}, errors.New("yamora: invalid index catalog")
	}
	actual := header.Get("X-YamlDB-Revision")
	if result.Revision != "" && result.Revision != actual {
		return IndexCatalog{}, errors.New("yamora: index revision mismatch")
	}
	result.Revision = actual
	return result, nil
}

func (c *Client) SetIndexes(ctx context.Context, indexes []Index, revision string) (Mutation, error) {
	if !validIndexes(indexes) {
		return Mutation{}, errors.New("yamora: invalid index definitions")
	}
	headers, err := quotedRevision(revision)
	if err != nil {
		return Mutation{}, err
	}
	var result Mutation
	response, err := c.structured(ctx, "PUT", "/v1/indexes", struct {
		Indexes []Index `json:"indexes"`
	}{indexes}, headers, true, MaxDocumentBytes, &result)
	if err != nil {
		return Mutation{}, err
	}
	if err = revisionFromBody(response, result.Revision); err != nil {
		return Mutation{}, err
	}
	return result, nil
}

// CreateIndex and DropIndex guard the complete catalog with the revision just
// read. A concurrent catalog edit returns HTTP 412; it is never overwritten.
func (c *Client) CreateIndex(ctx context.Context, index Index) (Mutation, error) {
	catalog, err := c.Indexes(ctx)
	if err != nil {
		return Mutation{}, err
	}
	for _, existing := range catalog.Indexes {
		if existing.Collection == index.Collection && existing.Name == index.Name {
			return Mutation{}, errors.New("yamora: index already exists")
		}
	}
	return c.SetIndexes(ctx, append(catalog.Indexes, index), catalog.Revision)
}

func (c *Client) DropIndex(ctx context.Context, collection, name string) (Mutation, error) {
	if !identifier.MatchString(collection) || !identifier.MatchString(name) {
		return Mutation{}, errors.New("yamora: invalid index identity")
	}
	catalog, err := c.Indexes(ctx)
	if err != nil {
		return Mutation{}, err
	}
	for i, index := range catalog.Indexes {
		if index.Collection == collection && index.Name == name {
			indexes := append(catalog.Indexes[:i:i], catalog.Indexes[i+1:]...)
			return c.SetIndexes(ctx, indexes, catalog.Revision)
		}
	}
	return Mutation{}, errors.New("yamora: index does not exist")
}

// Operation selects exactly one of Put, Patch, or Delete. Put points to exact YAML.
type Operation struct {
	Collection string         `json:"collection"`
	Document   string         `json:"document"`
	Put        *string        `json:"put,omitempty"`
	Patch      map[string]any `json:"patch,omitempty"`
	Delete     bool           `json:"delete,omitempty"`
	ETag       string         `json:"etag,omitempty"`
	CreateOnly bool           `json:"create_only,omitempty"`
}
type TransactionResult struct {
	Status     string `json:"status"`
	Revision   string `json:"revision"`
	Operations int    `json:"operations"`
}

func (c *Client) Transaction(ctx context.Context, operations []Operation, revision string) (TransactionResult, error) {
	if len(operations) == 0 || len(operations) > 128 || !validRevisionOption(revision) {
		return TransactionResult{}, errors.New("yamora: invalid transaction")
	}
	seen := make(map[string]bool)
	for _, op := range operations {
		path, err := documentPath(op.Collection, op.Document)
		count := 0
		if op.Put != nil {
			count++
		}
		if op.Patch != nil {
			count++
		}
		if op.Delete {
			count++
		}
		if err != nil || seen[path] || count != 1 || (op.CreateOnly && op.Put == nil) || (op.ETag != "" && (!revisionPattern.MatchString(op.ETag) || op.CreateOnly)) {
			return TransactionResult{}, errors.New("yamora: invalid transaction operation")
		}
		if op.Put != nil && (len(*op.Put) == 0 || len(*op.Put) > MaxDocumentBytes || !utf8.ValidString(*op.Put)) {
			return TransactionResult{}, errors.New("yamora: invalid transaction source")
		}
		if op.Patch != nil && len(op.Patch) == 0 {
			return TransactionResult{}, errors.New("yamora: empty transaction patch")
		}
		seen[path] = true
	}
	request := struct {
		Operations []Operation `json:"operations"`
		Revision   string      `json:"revision,omitempty"`
	}{operations, revision}
	var result TransactionResult
	header, err := c.structured(ctx, "POST", "/v1/transactions", request, nil, true, MaxDocumentBytes, &result)
	if err != nil {
		return TransactionResult{}, err
	}
	if err = revisionFromBody(header, result.Revision); err != nil {
		return TransactionResult{}, err
	}
	if result.Status != "committed" || result.Operations != len(operations) {
		return TransactionResult{}, errors.New("yamora: invalid transaction receipt")
	}
	return result, nil
}
