package oathnet

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const bulkSearchBasePath = "/service/v2/bulk-search"

// BulkService handles bulk search operations.
type BulkService struct {
	client *Client
}

// BulkSearchQueryConfig is the shared V2 search/filter configuration applied
// to every term in a bulk search job.
type BulkSearchQueryConfig map[string]interface{}

// BulkSearchCreateRequest is the canonical V2 bulk-search request body.
type BulkSearchCreateRequest struct {
	Terms       []string              `json:"terms,omitempty"`
	Service     string                `json:"service"`
	Format      string                `json:"format,omitempty"`
	DBNames     []string              `json:"dbnames,omitempty"`
	QueryConfig BulkSearchQueryConfig `json:"query_config,omitempty"`
	Limit       int                   `json:"limit,omitempty"`
	Fields      []string              `json:"fields,omitempty"`
}

func (r BulkSearchCreateRequest) MarshalJSON() ([]byte, error) {
	type alias BulkSearchCreateRequest
	fields := map[string]interface{}{}
	if r.QueryConfig != nil {
		fields["query_config"] = r.QueryConfig
	}
	return marshalRequestFields(alias(r), fields)
}

// BulkCreateOptions contains options for creating a bulk job.
type BulkCreateOptions struct {
	Format      string // csv, json, jsonl, txt, html
	DBNames     string // Deprecated: comma-separated legacy database filter. Use DBNameList.
	DBNameList  []string
	QueryConfig BulkSearchQueryConfig
	Limit       int
	Fields      []string
}

// Create creates a bulk search job.
func (s *BulkService) Create(terms []string, service string, opts *BulkCreateOptions) (*BulkJobResponse, error) {
	body := BulkSearchCreateRequest{
		Terms:   terms,
		Service: service,
	}

	if opts != nil {
		if opts.Format != "" {
			body.Format = opts.Format
		}
		if len(opts.DBNameList) > 0 {
			body.DBNames = append([]string(nil), opts.DBNameList...)
		} else if opts.DBNames != "" {
			body.DBNames = splitCommaList(opts.DBNames)
		}
		if opts.QueryConfig != nil {
			body.QueryConfig = opts.QueryConfig
		}
		if opts.Limit > 0 {
			body.Limit = opts.Limit
		}
		if opts.Fields != nil {
			body.Fields = opts.Fields
		}
	}

	var rawResp map[string]interface{}
	err := s.client.post(bulkSearchBasePath, body, &rawResp)
	if err != nil {
		return nil, err
	}

	return decodeBulkJobResponse(rawResp)
}

// GetStatus gets bulk job status.
func (s *BulkService) GetStatus(jobID string) (*BulkJobResponse, error) {
	var rawResp map[string]interface{}
	err := s.client.get(bulkSearchJobPath(jobID, ""), nil, &rawResp)
	if err != nil {
		return nil, err
	}

	return decodeBulkJobResponse(rawResp)
}

// List lists bulk search jobs.
func (s *BulkService) List(page, pageSize int) (*BulkJobListResponse, error) {
	params := url.Values{}
	if page > 0 {
		params.Set("page", strconv.Itoa(page))
	}
	if pageSize > 0 {
		params.Set("page_size", strconv.Itoa(pageSize))
	}

	var resp BulkJobListResponse
	err := s.client.get(bulkSearchBasePath+"/list", params, &resp)
	return &resp, err
}

// Download downloads bulk search results.
func (s *BulkService) Download(jobID, outputPath string) error {
	data, err := s.DownloadBytes(jobID)
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, data, 0644)
}

// DownloadBytes downloads a completed bulk job without writing to disk.
func (s *BulkService) DownloadBytes(jobID string) ([]byte, error) {
	return s.client.getRaw(bulkSearchJobPath(jobID, "/download"))
}

// DownloadResponse downloads a completed bulk job with its content headers.
func (s *BulkService) DownloadResponse(jobID string) (*DownloadResponse, error) {
	return s.client.getRawResponse(bulkSearchJobPath(jobID, "/download"), nil)
}

// WaitForCompletion waits for a bulk job to complete.
func (s *BulkService) WaitForCompletion(jobID string, pollInterval, timeout time.Duration) (*BulkJobResponse, error) {
	return pollJob(s.client, jobID, pollInterval, timeout, func(client *Client) (*BulkJobResponse, bool, string, string, int, error) {
		resp, err := client.Bulk.GetStatus(jobID)
		if err != nil {
			return nil, false, "", "", 0, err
		}
		if resp.Data == nil {
			return resp, false, "", resp.Message, 0, nil
		}
		return resp, resp.Success, resp.Data.Status, resp.Data.LastError, resp.Data.NextPollAfterMs, nil
	})
}

// Search creates a bulk search, waits for completion, and downloads.
func (s *BulkService) Search(terms []string, service, outputPath string, opts *BulkCreateOptions, timeout time.Duration) error {
	job, err := s.Create(terms, service, opts)
	if err != nil {
		return err
	}

	if job.Data == nil || job.Data.JobID == "" {
		return fmt.Errorf("failed to create bulk job")
	}

	_, err = s.WaitForCompletion(job.Data.JobID, 5*time.Second, timeout)
	if err != nil {
		return err
	}

	return s.Download(job.Data.JobID, outputPath)
}

func bulkSearchJobPath(jobID, suffix string) string {
	return fmt.Sprintf("%s/%s%s", bulkSearchBasePath, url.PathEscape(jobID), suffix)
}

func decodeBulkJobResponse(rawResp map[string]interface{}) (*BulkJobResponse, error) {
	success, message, data, err := decodeJobPayload[BulkJobData](rawResp)
	if err != nil {
		return nil, err
	}
	return &BulkJobResponse{Success: success, Message: message, Data: data}, nil
}

func splitCommaList(value string) []string {
	parts := strings.Split(value, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			items = append(items, item)
		}
	}
	return items
}
