package oathnet

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// JobError is a terminal job failure. A canceled job is not a completed result.
type JobError struct {
	JobID   string
	Status  string
	Message string
}

func (e *JobError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("job %s %s: %s", e.JobID, e.Status, e.Message)
	}
	return fmt.Sprintf("job %s %s", e.JobID, e.Status)
}

func decodeJobPayload[T any](raw map[string]interface{}) (bool, string, *T, error) {
	data, err := json.Marshal(raw)
	if err != nil {
		return false, "", nil, err
	}
	if raw == nil {
		return false, "", nil, fmt.Errorf("job response must be an object")
	}
	if _, wrapped := raw["success"]; wrapped {
		var envelope struct {
			Success bool   `json:"success"`
			Message string `json:"message"`
			Data    *T     `json:"data"`
		}
		if err := json.Unmarshal(data, &envelope); err != nil {
			return false, "", nil, err
		}
		if envelope.Success && envelope.Data == nil {
			return false, "", nil, fmt.Errorf("successful job response has no data")
		}
		if envelope.Success {
			payload, ok := raw["data"].(map[string]interface{})
			if !ok || !hasJobIdentity(payload) {
				return false, "", nil, fmt.Errorf("successful job response has no job_id")
			}
		}
		return envelope.Success, envelope.Message, envelope.Data, nil
	}
	if !hasJobIdentity(raw) {
		return false, "", nil, fmt.Errorf("unwrapped job response has no job_id")
	}
	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		return false, "", nil, err
	}
	return true, "", &result, nil
}

func hasJobIdentity(payload map[string]interface{}) bool {
	id, ok := payload["job_id"].(string)
	return ok && strings.TrimSpace(id) != ""
}

// pollJob applies one deadline to status requests and waits. The server's
// suggested delay is honored; a short client interval must not create a busy loop.
func pollJob[T any](c *Client, jobID string, interval, timeout time.Duration, fetch func(*Client) (*T, bool, string, string, int, error)) (*T, error) {
	if timeout <= 0 {
		return nil, fmt.Errorf("job timeout must be positive")
	}
	if interval <= 0 {
		return nil, fmt.Errorf("job poll interval must be positive")
	}
	ctx, cancel := context.WithTimeout(c.ctx, timeout)
	defer cancel()
	client := c.WithContext(ctx)
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("waiting for job %s: %w", jobID, err)
		}
		result, success, status, message, suggestedMS, err := fetch(client)
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("waiting for job %s: %w", jobID, err)
		}
		if !success || status == "" {
			return result, fmt.Errorf("job %s response has no successful status", jobID)
		}
		switch status {
		case "completed":
			return result, nil
		case "failed", "canceled", "cancelled", "expired":
			return result, &JobError{JobID: jobID, Status: status, Message: message}
		case "queued", "running", "pending", "processing":
		default:
			return result, fmt.Errorf("job %s returned unknown status %q", jobID, status)
		}
		delay := interval
		if suggestedMS > 0 {
			delay = time.Duration(suggestedMS) * time.Millisecond
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, fmt.Errorf("waiting for job %s: %w", jobID, ctx.Err())
		case <-timer.C:
		}
	}
}
