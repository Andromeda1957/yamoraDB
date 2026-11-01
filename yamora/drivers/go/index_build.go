package yamora

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"
)

var indexJobID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// IndexBuild is the latest in-process online catalog job. Revision is populated
// only after successful publication and may precede the current database head.
type IndexBuild struct {
	ID                   string `json:"id"`
	Status               string `json:"status"`
	Phase                string `json:"phase"`
	DocumentsScanned     uint64 `json:"documents_scanned"`
	TransactionsReplayed uint64 `json:"transactions_replayed"`
	Revision             string `json:"revision"`
	Error                string `json:"error"`
	CancelRequested      bool   `json:"cancel_requested"`
}

func (c *Client) indexBuild(ctx context.Context, method, path string, request any, headers http.Header, write bool, expected string) (IndexBuild, error) {
	var raw json.RawMessage
	expectedStatus := 200
	if method == "POST" || method == "DELETE" {
		expectedStatus = 202
	}
	_, err := c.structured(ctx, method, path, request, headers, write, MaxDocumentBytes, &raw, expectedStatus)
	if err != nil {
		return IndexBuild{}, err
	}
	var result IndexBuild
	if err = json.Unmarshal(raw, &result); err != nil {
		return IndexBuild{}, errors.New("yamora: invalid index build")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return IndexBuild{}, errors.New("yamora: invalid index build")
	}
	for _, key := range []string{"id", "status", "phase", "documents_scanned", "transactions_replayed", "revision", "error", "cancel_requested"} {
		if fields[key] == nil || string(fields[key]) == "null" {
			return IndexBuild{}, errors.New("yamora: incomplete index build")
		}
	}
	validStatus := result.Status == "idle" || result.Status == "running" || result.Status == "succeeded" || result.Status == "failed" || result.Status == "cancelled"
	validPhase := result.Phase == "idle" || result.Phase == "scanning" || result.Phase == "catching_up" || result.Phase == "publishing" || result.Phase == "done"
	validError := result.Error == "" || result.Error == "cancelled" || result.Error == "deadline_exceeded" || result.Error == "unique_constraint" || result.Error == "history_unavailable" || result.Error == "build_failed" || result.Error == "worker_unavailable" || result.Error == "publication_failed"
	if !validStatus || !validPhase || !validError || (!indexJobID.MatchString(result.ID) && !(result.ID == "" && result.Status == "idle")) || (expected != "" && expected != result.ID) ||
		(result.Status == "succeeded" && (!revisionPattern.MatchString(result.Revision) || result.Error != "")) || (result.Status != "succeeded" && result.Revision != "") ||
		((result.Status == "succeeded" || result.Status == "failed" || result.Status == "cancelled") && result.Phase != "done") || (result.Status == "running" && (result.Phase == "idle" || result.Phase == "done")) {
		return IndexBuild{}, errors.New("yamora: invalid index build")
	}
	return result, nil
}

// StartIndexBuild atomically replaces the entire catalog after a background
// scan and bounded change-log catch-up. It never retries a submission.
func (c *Client) StartIndexBuild(ctx context.Context, indexes []Index, revision string) (IndexBuild, error) {
	if !validIndexes(indexes) {
		return IndexBuild{}, errors.New("yamora: invalid index definitions")
	}
	headers, err := quotedRevision(revision)
	if err != nil {
		return IndexBuild{}, err
	}
	return c.indexBuild(ctx, "POST", "/v1/index-builds", struct {
		Indexes []Index `json:"indexes"`
	}{indexes}, headers, true, "")
}

func (c *Client) IndexBuild(ctx context.Context, id string) (IndexBuild, error) {
	if !indexJobID.MatchString(id) {
		return IndexBuild{}, errors.New("yamora: invalid index build ID")
	}
	return c.indexBuild(ctx, "GET", "/v1/index-builds/"+id, nil, nil, false, id)
}

func (c *Client) CancelIndexBuild(ctx context.Context, id string) (IndexBuild, error) {
	if !indexJobID.MatchString(id) {
		return IndexBuild{}, errors.New("yamora: invalid index build ID")
	}
	return c.indexBuild(ctx, "DELETE", "/v1/index-builds/"+id, nil, nil, true, id)
}

// WaitIndexBuild polls with a cancellable context. A cancelled local context
// leaves the remote job running; CancelIndexBuild explicitly requests its stop.
func (c *Client) WaitIndexBuild(ctx context.Context, id string) (IndexBuild, error) {
	for {
		job, err := c.IndexBuild(ctx, id)
		if err != nil || job.Status == "succeeded" || job.Status == "failed" || job.Status == "cancelled" {
			return job, err
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return IndexBuild{}, ctx.Err()
		case <-timer.C:
		}
	}
}
