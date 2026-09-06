// Package oathnet provides a Go SDK for the OathNet API.
package oathnet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is the main OathNet API client.
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
	ctx        context.Context

	// Services
	Search     *SearchService
	OSINT      *OSINTService
	Breach     *BreachV2Service
	Stealer    *StealerV2Service
	Victims    *VictimsService
	FileSearch *FileSearchService
	Exports    *ExportsService
	Bulk       *BulkService
	Utility    *UtilityService
	Scanners   *ScannerService
	AI         *AIService
}

// ClientOption is a function that configures the client.
type ClientOption func(*Client)

// WithBaseURL sets a custom base URL.
func WithBaseURL(url string) ClientOption {
	return func(c *Client) {
		c.baseURL = strings.TrimRight(url, "/")
	}
}

// WithHTTPClient uses a caller-owned transport and timeout. The SDK copies the
// client configuration so redirect protection does not mutate the caller's client.
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) {
		if client != nil {
			copy := *client
			c.httpClient = &copy
		}
	}
}

// WithTimeout sets a custom HTTP timeout.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.httpClient.Timeout = timeout
	}
}

// NewClient creates a new OathNet API client.
func NewClient(apiKey string, opts ...ClientOption) (*Client, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("API key is required")
	}

	c := &Client{
		apiKey:  apiKey,
		baseURL: "https://oathnet.org/api",
		ctx:     context.Background(),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	for _, opt := range opts {
		opt(c)
	}
	parsed, err := url.Parse(c.baseURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("base URL must be an HTTP(S) URL without credentials, query, or fragment")
	}
	redirect := c.httpClient.CheckRedirect
	c.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 0 && (req.URL.Host != via[0].URL.Host || req.URL.Scheme != via[0].URL.Scheme) {
			req.Header.Del("x-api-key")
		}
		if redirect != nil {
			return redirect(req, via)
		}
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	}
	c.initServices()
	return c, nil
}

// WithContext returns a client bound to ctx. Use it for cancellation or a deadline
// across a workflow; the original client remains usable with its own context.
func (c *Client) WithContext(ctx context.Context) *Client {
	copy := *c
	if ctx == nil {
		ctx = context.Background()
	}
	copy.ctx = ctx
	copy.initServices()
	return &copy
}

func (c *Client) initServices() {
	c.Search = &SearchService{client: c}
	c.OSINT = &OSINTService{client: c}
	c.Breach = &BreachV2Service{client: c}
	c.Stealer = &StealerV2Service{client: c}
	c.Victims = &VictimsService{client: c}
	c.FileSearch = &FileSearchService{client: c}
	c.Exports = &ExportsService{client: c}
	c.Bulk = &BulkService{client: c}
	c.Utility = &UtilityService{client: c}
	c.Scanners = &ScannerService{client: c}
	c.AI = &AIService{client: c}
}

// get performs a GET request.
func (c *Client) get(path string, params url.Values, result interface{}) error {
	reqURL := c.baseURL + path
	if len(params) > 0 {
		reqURL += "?" + params.Encode()
	}

	req, err := http.NewRequestWithContext(c.ctx, "GET", reqURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return c.handleResponse(resp, result)
}

// post performs a POST request.
func (c *Client) post(path string, body interface{}, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(c.ctx, "POST", c.baseURL+path, bodyReader)
	if err != nil {
		return err
	}

	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return c.handleResponse(resp, result)
}

// patch performs a PATCH request.
func (c *Client) patch(path string, body interface{}, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(c.ctx, "PATCH", c.baseURL+path, bodyReader)
	if err != nil {
		return err
	}

	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return c.handleResponse(resp, result)
}

// delete performs a DELETE request.
func (c *Client) delete(path string, result interface{}) error {
	req, err := http.NewRequestWithContext(c.ctx, "DELETE", c.baseURL+path, nil)
	if err != nil {
		return err
	}

	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return c.handleResponse(resp, result)
}

// getRaw performs a GET request and returns raw bytes.
func (c *Client) getRaw(path string) ([]byte, error) {
	return c.getRawWithHeaders(path, nil)
}

// getRawWithHeaders performs a GET request with optional headers and returns raw bytes.
func (c *Client) getRawWithHeaders(path string, headers map[string]string) ([]byte, error) {
	response, err := c.getRawResponse(path, headers)
	if err != nil {
		return nil, err
	}
	return response.Body, nil
}

// DownloadResponse retains content headers so callers can distinguish a limited
// JSON preview from original file bytes before writing a file.
type DownloadResponse struct {
	Body       []byte
	StatusCode int
	Header     http.Header
}

func (c *Client) getRawResponse(path string, headers map[string]string) (*DownloadResponse, error) {
	req, err := http.NewRequestWithContext(c.ctx, "GET", c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("x-api-key", c.apiKey)
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, c.parseError(resp.StatusCode, body, resp.Header)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if mediaType == "application/json" && resp.Header.Get("Content-Disposition") == "" {
		var envelope struct {
			Success *bool `json:"success"`
		}
		if json.Unmarshal(body, &envelope) == nil && envelope.Success != nil && !*envelope.Success {
			return nil, c.parseError(resp.StatusCode, body, resp.Header)
		}
	}
	return &DownloadResponse{Body: body, StatusCode: resp.StatusCode, Header: resp.Header.Clone()}, nil
}

func (c *Client) handleResponse(resp *http.Response, result interface{}) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return c.parseError(resp.StatusCode, body, resp.Header)
	}

	if result != nil {
		if len(bytes.TrimSpace(body)) == 0 || bytes.Equal(bytes.TrimSpace(body), []byte("null")) {
			return fmt.Errorf("API returned an empty JSON response (HTTP %d)", resp.StatusCode)
		}
		return json.Unmarshal(body, result)
	}

	return nil
}

func (c *Client) parseError(statusCode int, body []byte, headers ...http.Header) error {
	var response map[string]interface{}
	_ = json.Unmarshal(body, &response)
	message := ""
	for _, key := range []string{"message", "error", "detail"} {
		if value, ok := response[key].(string); ok && value != "" {
			message = value
			break
		}
	}
	if message == "" {
		message = string(body)
	}
	if message == "" {
		message = http.StatusText(statusCode)
	}
	code, _ := response["code"].(string)
	details, _ := response["errors"].(map[string]interface{})
	if details == nil {
		details, _ = response["detail"].(map[string]interface{})
	}
	if details == nil {
		details = response
	}
	retryAfter := ""
	if len(headers) > 0 {
		retryAfter = headers[0].Get("Retry-After")
	}
	switch statusCode {
	case 401:
		return &AuthenticationError{Message: message, StatusCode: statusCode, Code: code, Details: details, Response: response, RetryAfter: retryAfter}
	case 400:
		if containsAuthMessage(message) {
			return &AuthenticationError{Message: message, StatusCode: statusCode, Code: code, Details: details, Response: response, RetryAfter: retryAfter}
		}
		return &ValidationError{Message: message, StatusCode: statusCode, Code: code, Details: details, Response: response, RetryAfter: retryAfter}
	case 404:
		return &NotFoundError{Message: message, StatusCode: statusCode, Code: code, Details: details, Response: response, RetryAfter: retryAfter}
	case 429:
		return &RateLimitError{Message: message, StatusCode: statusCode, Code: code, Details: details, Response: response, RetryAfter: retryAfter}
	default:
		return &OathNetError{Message: message, StatusCode: statusCode, Code: code, Details: details, Response: response, RetryAfter: retryAfter}
	}
}

func containsAuthMessage(msg string) bool {
	message := strings.ToLower(strings.TrimSpace(msg))
	return strings.HasPrefix(message, "invalid api key") || strings.HasPrefix(message, "api key is required") || strings.HasPrefix(message, "missing api key")
}
