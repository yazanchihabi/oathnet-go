package oathnet

import "net/url"

// EnrichmentRequest selects public profile modules for one identifier. Modules
// must match Type, which is userid by default or username. Omit Modules to use
// the enabled modules for that type. Each selected module has its own outcome.
type EnrichmentRequest struct {
	Input           string   `json:"input"`
	Type            string   `json:"type,omitempty"`
	Modules         []string `json:"modules,omitempty"`
	IncludeFailures *bool    `json:"include_failures,omitempty"` // Nil uses true. True overrides OnlyFound.
	OnlyFound       *bool    `json:"only_found,omitempty"`
	Timeout         string   `json:"timeout,omitempty"` // Server execution duration, 1s through 120s.
	SearchID        string   `json:"search_id,omitempty"`
}

// EnrichIdentity runs selected public enrichment modules with GET. HTTP 200 can
// include failed, unknown, or rate-limited modules. Inspect Data.Results and the
// summary counters before using a profile result.
func (s *OSINTService) EnrichIdentity(req EnrichmentRequest) (*EnrichmentResponse, error) {
	params := url.Values{}
	params.Set("input", req.Input)
	addStringParam(params, "type", req.Type)
	addRepeatedParam(params, "modules", req.Modules)
	addBoolPtrParam(params, "include_failures", req.IncludeFailures)
	addBoolPtrParam(params, "only_found", req.OnlyFound)
	addStringParam(params, "timeout", req.Timeout)
	addStringParam(params, "search_id", req.SearchID)
	var resp EnrichmentResponse
	err := s.client.get("/service/enrichment/", params, &resp)
	return &resp, err
}

// EnrichIdentityPost runs the same lookup with a JSON body. It preserves module
// outcomes even when Success is false because no result was found.
func (s *OSINTService) EnrichIdentityPost(req EnrichmentRequest) (*EnrichmentResponse, error) {
	var resp EnrichmentResponse
	err := s.client.post("/service/enrichment/", req, &resp)
	return &resp, err
}

// EnrichmentResponse contains execution outcomes, not a guarantee that an
// identifier belongs to a particular person.
type EnrichmentResponse struct {
	Success bool            `json:"success"`
	Message string          `json:"message,omitempty"`
	Data    *EnrichmentData `json:"data,omitempty"`
	Meta    *ResponseMeta   `json:"_meta,omitempty"`
}

type EnrichmentData struct {
	Type             string                   `json:"type,omitempty"`
	Input            string                   `json:"input,omitempty"`
	ModuleType       string                   `json:"module_type,omitempty"`
	RequestedModules []string                 `json:"requested_modules,omitempty"`
	AllowedModules   []string                 `json:"allowed_modules,omitempty"`
	DisabledModules  []string                 `json:"disabled_modules,omitempty"`
	Skipped          bool                     `json:"skipped,omitempty"`
	Total            int                      `json:"total"`
	Found            int                      `json:"found"`
	NotFound         int                      `json:"not_found"`
	Unknown          int                      `json:"unknown"`
	Errors           int                      `json:"errors"`
	RateLimited      int                      `json:"rate_limited"`
	Illegal          int                      `json:"illegal"`
	DurationMS       int                      `json:"duration_ms"`
	Results          []EnrichmentModuleResult `json:"results,omitempty"`
	Timestamp        string                   `json:"timestamp,omitempty"`
}

type EnrichmentModuleResult struct {
	Module    string                 `json:"module"`
	Domain    string                 `json:"domain"`
	Input     string                 `json:"input"`
	Status    string                 `json:"status"`
	URL       string                 `json:"url,omitempty"`
	Metadata  map[string]string      `json:"metadata,omitempty"`
	Error     *EnrichmentModuleError `json:"error,omitempty"`
	LatencyMS int                    `json:"latency_ms"`
	Timestamp string                 `json:"timestamp"`
}

type EnrichmentModuleError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Code    int    `json:"code,omitempty"`
}
