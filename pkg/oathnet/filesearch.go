package oathnet

import (
	"fmt"
	"net/url"
	"time"
)

// FileSearchService handles V2 file search operations.
type FileSearchService struct {
	client *Client
}

// FileSearchCreateOptions contains options for creating a file search job.
type FileSearchCreateOptions struct {
	SearchMode     string // literal, regex, wildcard
	LogIDs         []string
	IncludeMatches bool
	CaseSensitive  bool
	ContextLines   int
	// ContextLinesValue overrides ContextLines, including an explicit zero.
	// Leave nil to keep the default of two surrounding lines.
	ContextLinesValue *int
	FilePattern       string
	MaxMatches        int
}

// Create creates a file search job.
func (s *FileSearchService) Create(expression string, opts *FileSearchCreateOptions) (*FileSearchJobResponse, error) {
	body := map[string]interface{}{
		"expression":      expression,
		"search_mode":     "literal",
		"include_matches": true,
		"case_sensitive":  false,
		"context_lines":   2,
		"max_matches":     100,
	}

	if opts != nil {
		if opts.SearchMode != "" {
			body["search_mode"] = opts.SearchMode
		}
		if opts.LogIDs != nil {
			body["log_ids"] = opts.LogIDs
		}
		body["include_matches"] = opts.IncludeMatches
		body["case_sensitive"] = opts.CaseSensitive
		if opts.ContextLines > 0 {
			body["context_lines"] = opts.ContextLines
		}
		if opts.ContextLinesValue != nil {
			body["context_lines"] = *opts.ContextLinesValue
		}
		if opts.FilePattern != "" {
			body["file_pattern"] = opts.FilePattern
		}
		if opts.MaxMatches > 0 {
			body["max_matches"] = opts.MaxMatches
		}
	}

	var rawResp map[string]interface{}
	err := s.client.post("/service/v2/file-search", body, &rawResp)
	if err != nil {
		return nil, err
	}

	// Handle wrapped or unwrapped response
	success, message, data, err := decodeJobPayload[FileSearchJobData](rawResp)
	if err != nil {
		return nil, err
	}
	return &FileSearchJobResponse{Success: success, Message: message, Data: data}, nil
}

// CreateFileSearchV2 is an operation-id alias for Create.
func (s *FileSearchService) CreateFileSearchV2(expression string, opts *FileSearchCreateOptions) (*FileSearchJobResponse, error) {
	return s.Create(expression, opts)
}

// GetStatus gets file search job status.
func (s *FileSearchService) GetStatus(jobID string) (*FileSearchJobResponse, error) {
	var rawResp map[string]interface{}
	err := s.client.get(fileSearchJobPath(jobID), nil, &rawResp)
	if err != nil {
		return nil, err
	}

	success, message, data, err := decodeJobPayload[FileSearchJobData](rawResp)
	if err != nil {
		return nil, err
	}
	return &FileSearchJobResponse{Success: success, Message: message, Data: data}, nil
}

// GetFileSearchV2 is an operation-id alias for GetStatus.
func (s *FileSearchService) GetFileSearchV2(jobID string) (*FileSearchJobResponse, error) {
	return s.GetStatus(jobID)
}

// WaitForCompletion waits for a file search job to complete.
func (s *FileSearchService) WaitForCompletion(jobID string, pollInterval, timeout time.Duration) (*FileSearchJobResponse, error) {
	return pollJob(s.client, jobID, pollInterval, timeout, func(client *Client) (*FileSearchJobResponse, bool, string, string, int, error) {
		resp, err := client.FileSearch.GetStatus(jobID)
		if err != nil {
			return nil, false, "", "", 0, err
		}
		if resp.Data == nil {
			return resp, false, "", resp.Message, 0, nil
		}
		return resp, resp.Success, resp.Data.Status, resp.Message, resp.Data.NextPollAfterMs, nil
	})
}

// Search creates a file search and waits for results.
func (s *FileSearchService) Search(expression string, opts *FileSearchCreateOptions, timeout time.Duration) (*FileSearchJobResponse, error) {
	job, err := s.Create(expression, opts)
	if err != nil {
		return nil, err
	}

	if job.Data == nil || job.Data.JobID == "" {
		return nil, fmt.Errorf("failed to create file search job")
	}

	return s.WaitForCompletion(job.Data.JobID, 2*time.Second, timeout)
}

func fileSearchJobPath(jobID string) string {
	return fmt.Sprintf("/service/v2/file-search/%s", url.PathEscape(jobID))
}
