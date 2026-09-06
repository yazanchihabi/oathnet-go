package oathnet

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
)

func TestEnrichmentAllParametersAndModuleOutcomes(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			includeFailures, onlyFound := false, false
			request := EnrichmentRequest{Input: "example+account", Type: "username", Modules: []string{"instagram", "twitter"}, IncludeFailures: &includeFailures, OnlyFound: &onlyFound, Timeout: "15s", SearchID: "00000000-0000-4000-8000-000000000001"}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != method || r.URL.Path != "/service/enrichment/" {
					t.Errorf("unexpected route: %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("x-api-key") != "test-key" {
					t.Error("API authentication header missing")
				}
				if method == http.MethodGet {
					want := url.Values{"input": {request.Input}, "type": {request.Type}, "modules": request.Modules, "include_failures": {"false"}, "only_found": {"false"}, "timeout": {"15s"}, "search_id": {request.SearchID}}
					if !reflect.DeepEqual(r.URL.Query(), want) {
						t.Errorf("query = %#v, want %#v", r.URL.Query(), want)
					}
				} else {
					var got EnrichmentRequest
					if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(got, request) {
						t.Errorf("body = %#v, want %#v", got, request)
					}
					if r.URL.RawQuery != "" {
						t.Error("POST must keep options in JSON")
					}
				}
				_, _ = w.Write([]byte(`{"success":false,"message":"No found profiles","data":{"type":"summary","module_type":"username","requested_modules":["instagram","twitter"],"total":2,"found":0,"unknown":1,"rate_limited":1,"results":[{"module":"instagram","domain":"instagram.com","input":"example+account","status":"unknown","latency_ms":10,"timestamp":"2026-01-01T00:00:00Z","error":{"type":"provider","message":"Unavailable","code":503}}]},"_meta":{"lookups":{"left_today":10}}}`))
			}))
			defer server.Close()
			client, _ := NewClient("test-key", WithBaseURL(server.URL))
			var result *EnrichmentResponse
			var err error
			if method == http.MethodGet {
				result, err = client.OSINT.EnrichIdentity(request)
			} else {
				result, err = client.OSINT.EnrichIdentityPost(request)
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.Success || result.Data == nil || result.Data.Total != 2 || result.Data.RateLimited != 1 || result.Data.Results[0].Error.Code != 503 || result.Meta.Lookups.LeftToday != 10 {
				t.Fatalf("module outcomes lost: %#v", result)
			}
		})
	}
}
