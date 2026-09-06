package oathnet

import (
	"fmt"
	"net/url"
	"os"
	"time"
)

const exportsV2BasePath = "/service/v2/exports"

// ExportsService handles V2 export operations.
type ExportsService struct {
	client *Client
}

// ExportCreateOptions contains options for creating an export job.
type ExportCreateOptions struct {
	Format      string // json, jsonl, csv, txt, html
	Limit       int
	Fields      []string
	Search      interface{}
	Service     string // stealer, victims, breach
	QueryConfig interface{}
}

// Create creates an export job.
func (s *ExportsService) Create(exportType string, opts *ExportCreateOptions) (*ExportJobResponse, error) {
	body := map[string]interface{}{
		"type":   exportType,
		"format": "jsonl",
	}

	if opts != nil {
		if opts.Format != "" {
			body["format"] = opts.Format
		}
		if opts.Limit > 0 {
			body["limit"] = opts.Limit
		}
		if opts.Fields != nil {
			body["fields"] = opts.Fields
		}
		if opts.Search != nil {
			body["search"] = opts.Search
		}
		if opts.Service != "" {
			body["service"] = opts.Service
		}
		if opts.QueryConfig != nil {
			body["query_config"] = opts.QueryConfig
		}
	}

	var rawResp map[string]interface{}
	err := s.client.post(exportsV2BasePath, body, &rawResp)
	if err != nil {
		return nil, err
	}

	success, message, data, err := decodeJobPayload[ExportJobData](rawResp)
	if err != nil {
		return nil, err
	}
	return &ExportJobResponse{Success: success, Message: message, Data: data}, nil
}

// CreateExportV2 is an operation-id alias for Create.
func (s *ExportsService) CreateExportV2(exportType string, opts *ExportCreateOptions) (*ExportJobResponse, error) {
	return s.Create(exportType, opts)
}

// GetStatus gets export job status.
func (s *ExportsService) GetStatus(jobID string) (*ExportJobResponse, error) {
	var rawResp map[string]interface{}
	err := s.client.get(exportJobPath(jobID, ""), nil, &rawResp)
	if err != nil {
		return nil, err
	}

	success, message, data, err := decodeJobPayload[ExportJobData](rawResp)
	if err != nil {
		return nil, err
	}
	return &ExportJobResponse{Success: success, Message: message, Data: data}, nil
}

// GetExportV2 is an operation-id alias for GetStatus.
func (s *ExportsService) GetExportV2(jobID string) (*ExportJobResponse, error) {
	return s.GetStatus(jobID)
}

// List lists export jobs.
func (s *ExportsService) List(page, pageSize int) (*V2ExportJobListResponse, error) {
	params := url.Values{}
	addIntParam(params, "page", page)
	addIntParam(params, "page_size", pageSize)

	var resp V2ExportJobListResponse
	err := s.client.get(exportsV2BasePath+"/list", params, &resp)
	return &resp, err
}

// ListExportsV2 is an operation-id alias for List.
func (s *ExportsService) ListExportsV2(page, pageSize int) (*V2ExportJobListResponse, error) {
	return s.List(page, pageSize)
}

// DownloadBytes downloads export file bytes.
func (s *ExportsService) DownloadBytes(jobID string) ([]byte, error) {
	data, err := s.client.getRaw(exportJobPath(jobID, "/download"))
	if err != nil {
		return nil, err
	}

	return data, nil
}

// DownloadResponse downloads a completed export with its content headers.
func (s *ExportsService) DownloadResponse(jobID string) (*DownloadResponse, error) {
	return s.client.getRawResponse(exportJobPath(jobID, "/download"), nil)
}

// Download downloads the export file.
func (s *ExportsService) Download(jobID, outputPath string) error {
	data, err := s.DownloadBytes(jobID)
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0644)
}

// DownloadExportV2 is an operation-id alias for DownloadBytes.
func (s *ExportsService) DownloadExportV2(jobID string) ([]byte, error) {
	return s.DownloadBytes(jobID)
}

// WaitForCompletion waits for an export job to complete.
func (s *ExportsService) WaitForCompletion(jobID string, pollInterval, timeout time.Duration) (*ExportJobResponse, error) {
	return pollJob(s.client, jobID, pollInterval, timeout, func(client *Client) (*ExportJobResponse, bool, string, string, int, error) {
		resp, err := client.Exports.GetStatus(jobID)
		if err != nil {
			return nil, false, "", "", 0, err
		}
		if resp.Data == nil {
			return resp, false, "", resp.Message, 0, nil
		}
		return resp, resp.Success, resp.Data.Status, resp.Data.LastError, resp.Data.NextPollAfterMs, nil
	})
}

// Export creates an export, waits for completion, and downloads.
func (s *ExportsService) Export(exportType, outputPath string, opts *ExportCreateOptions, timeout time.Duration) error {
	job, err := s.Create(exportType, opts)
	if err != nil {
		return err
	}

	if job.Data == nil || job.Data.JobID == "" {
		return fmt.Errorf("failed to create export job")
	}

	_, err = s.WaitForCompletion(job.Data.JobID, 2*time.Second, timeout)
	if err != nil {
		return err
	}

	return s.Download(job.Data.JobID, outputPath)
}

func exportJobPath(jobID, suffix string) string {
	return fmt.Sprintf("%s/%s%s", exportsV2BasePath, url.PathEscape(jobID), suffix)
}
