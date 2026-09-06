package oathnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBreachRawRoundTripPreservesSourceValues(t *testing.T) {
	fixture := `{"id":"fixture","email":["user@example.com"],"dbname":["example-source"],"age":"unknown","password":{"redacted":true},"extra":[1,true],"new_field":null,"large_number":9007199254740993}`
	var record V2BreachResult
	if err := json.Unmarshal([]byte(fixture), &record); err != nil {
		t.Fatal(err)
	}
	if string(record.Raw["email"]) != `["user@example.com"]` || string(record.Raw["large_number"]) != "9007199254740993" {
		t.Fatalf("raw fields changed: %v", record.Raw)
	}
	if record.Email != "" {
		t.Error("array source fields must not be silently stringified")
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	var before, after map[string]json.RawMessage
	if err := json.Unmarshal([]byte(fixture), &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &after); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("record changed on round-trip: %s", encoded)
	}
}

func TestClientContextCancelsWorkflowWithoutChangingOriginal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") == "wait" {
			<-r.Context().Done()
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"data":{"items":[]}}`))
	}))
	defer server.Close()
	client, _ := NewClient("test-key", WithBaseURL(server.URL+"/"))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := client.WithContext(ctx).Breach.Search("wait", nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline, got %v", err)
	}
	if _, err := client.Breach.Search("user@example.com", nil); err != nil {
		t.Fatalf("original client was changed: %v", err)
	}
}

func TestRedirectDoesNotForwardAPIKeyToAnotherOrigin(t *testing.T) {
	var calls atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("x-api-key") != "" {
			t.Error("API key was forwarded across origins")
		}
		_, _ = w.Write([]byte(`{"success":true,"data":{"items":[]}}`))
	}))
	defer receiver.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "test-key" {
			t.Error("origin API key missing")
		}
		http.Redirect(w, r, receiver.URL, http.StatusFound)
	}))
	defer origin.Close()
	custom := &http.Client{}
	client, _ := NewClient("test-key", WithHTTPClient(custom), WithBaseURL(origin.URL))
	if _, err := client.Breach.Search("user@example.com", nil); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || custom.CheckRedirect != nil {
		t.Fatal("redirect behavior or caller-owned client changed")
	}
}

func TestErrorsRetainStatusCodeDetailsAndRetryAfter(t *testing.T) {
	client, _ := NewClient("test-key")
	err := client.parseError(429, []byte(`{"message":"Slow down","code":"rate_limited","retry_after":5}`), http.Header{"Retry-After": {"5"}})
	rate, ok := err.(*RateLimitError)
	if !ok || rate.StatusCode != 429 || rate.Code != "rate_limited" || rate.RetryAfter != "5" || rate.Response["retry_after"] != float64(5) {
		t.Fatalf("lost error metadata: %#v", err)
	}
	err = client.parseError(400, []byte(`{"message":"API key mode is legacy only. Use signed_json.","errors":{"webhook_security_mode":["Invalid mode"]}}`))
	validation, ok := err.(*ValidationError)
	if !ok || validation.StatusCode != 400 || validation.Details["webhook_security_mode"] == nil {
		t.Fatalf("validation misclassified: %#v", err)
	}
}

func TestJobPollingDeadlineIncludesHTTPAndServerDelay(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"job_id":"fixture-job","status":"running","next_poll_after_ms":60000,"progress":{"percent":12.5}}`))
	}))
	defer server.Close()
	client, _ := NewClient("test-key", WithBaseURL(server.URL))
	start := time.Now()
	_, err := client.FileSearch.WaitForCompletion("fixture-job", time.Millisecond, 20*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected timeout, got %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("server delay ignored; made %d requests", calls.Load())
	}
	if time.Since(start) > time.Second {
		t.Fatal("polling exceeded deadline")
	}
}

func TestDownloadResponseRetainsPreviewContentType(t *testing.T) {
	client := responseTestClient(t, `{"policy_redacted":true,"content_preview":"example preview"}`)
	result, err := client.Victims.GetFileResponse("fixture-log", "fixture-file")
	if err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != 200 || result.Header.Get("Content-Type") != "application/json" || !strings.Contains(string(result.Body), `"policy_redacted":true`) {
		t.Fatalf("preview metadata lost: %#v", result)
	}
}

func TestDownloadJSONErrorAndAttachments(t *testing.T) {
	for _, tc := range []struct {
		name, body, disposition string
		wantError               bool
	}{
		{"API failure", `{"success":false,"code":"download_failed","message":"Fixture unavailable"}`, "", true},
		{"access preview", `{"success":true,"data":{"policy_redacted":true}}`, "", false},
		{"original JSON attachment", `{"success":false,"customer_field":123}`, `attachment; filename="fixture.json"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				if tc.disposition != "" {
					w.Header().Set("Content-Disposition", tc.disposition)
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			client, _ := NewClient("test-key", WithBaseURL(server.URL))
			result, err := client.Victims.GetFileResponse("fixture-log", "fixture-file")
			if tc.wantError {
				var apiError *OathNetError
				if !errors.As(err, &apiError) || apiError.Code != "download_failed" || apiError.StatusCode != 200 || result != nil {
					t.Fatalf("download failure was accepted or lost metadata: result=%#v error=%#v", result, err)
				}
			} else if err != nil || string(result.Body) != tc.body {
				t.Fatalf("valid download changed: result=%#v error=%v", result, err)
			}
		})
	}
}

func TestFileSearchContextLinesExplicitZero(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprint(explicit), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				want := float64(2)
				if explicit {
					want = 0
				}
				if body["context_lines"] != want {
					t.Errorf("context_lines=%v, want %v", body["context_lines"], want)
				}
				_, _ = w.Write([]byte(`{"job_id":"fixture-job","status":"queued"}`))
			}))
			defer server.Close()
			client, _ := NewClient("test-key", WithBaseURL(server.URL))
			opts := &FileSearchCreateOptions{LogIDs: []string{"fixture-log"}}
			if explicit {
				zero := 0
				opts.ContextLinesValue = &zero
			}
			if _, err := client.FileSearch.Create("fixture", opts); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMetadataExplicitZeroRangeOnGetAndPost(t *testing.T) {
	for _, method := range []string{"GET", "POST"} {
		t.Run(method, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != method {
					t.Errorf("method = %s, want %s", r.Method, method)
				}
				if method == "GET" {
					if r.URL.Query().Get("size_min") != "0" || r.URL.Query().Get("size_max") != "0" {
						t.Error("explicit zero range lost in GET")
					}
				} else {
					var body map[string]interface{}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					if body["size_min"] != float64(0) || body["size_max"] != float64(0) {
						t.Error("explicit zero range lost in POST")
					}
				}
				_, _ = w.Write([]byte(`{"success":true,"data":{"items":[]}}`))
			}))
			defer server.Close()
			client, _ := NewClient("test-key", WithBaseURL(server.URL))
			zero := 0
			request := &V2FileMetadataSearchRequest{SizeMinValue: &zero, SizeMaxValue: &zero}
			var err error
			if method == "GET" {
				_, err = client.Victims.SearchFilesMetadata(request)
			} else {
				_, err = client.Victims.SearchFilesMetadataPost(request)
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMinecraftHistoryRetainsDisabledMarkers(t *testing.T) {
	client := responseTestClient(t, `{"success":true,"data":{"username":"ReadinessFixture","history":[],"cached":false,"disabled":true,"skipped":true,"results_found":0}}`)
	result, err := client.OSINT.MinecraftHistory("ReadinessFixture")
	if err != nil || result.Data == nil || !result.Data.Disabled || !result.Data.Skipped || len(result.Data.History) != 0 {
		t.Fatalf("disabled response was changed: result=%#v error=%v", result, err)
	}
}

func TestMetadataSelectorsRetainMultipleValues(t *testing.T) {
	for _, method := range []string{"GET", "POST"} {
		t.Run(method, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				want := []interface{}{"Passwords.txt", "Notes.txt"}
				if method == "GET" {
					if !reflect.DeepEqual(r.URL.Query()["name"], []string{"Passwords.txt", "Notes.txt"}) || r.URL.Query().Has("name[]") {
						t.Error("GET selector lost values or emitted brackets")
					}
				} else {
					var body map[string]interface{}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(body["name"], want) {
						t.Error("POST selector was not an array")
					}
				}
				_, _ = w.Write([]byte(`{"success":true,"data":{"items":[]}}`))
			}))
			defer server.Close()
			client, _ := NewClient("test-key", WithBaseURL(server.URL))
			opts := &V2FileMetadataSearchRequest{Name: "Passwords.txt", Names: []string{"Notes.txt"}}
			var err error
			if method == "GET" {
				_, err = client.Victims.SearchFilesMetadata(opts)
			} else {
				_, err = client.Victims.SearchFilesMetadataPost(opts)
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestExplicitGETKeepsStructuredFiltersAndFalse(t *testing.T) {
	filter := map[string]interface{}{"field": "email", "operator": "eq", "value": "user@example.com"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.ContentLength > 0 {
			t.Error("explicit GET changed transport method")
		}
		var actual map[string]interface{}
		if json.Unmarshal([]byte(r.URL.Query().Get("filter")), &actual) != nil || !reflect.DeepEqual(actual, filter) {
			t.Error("structured filter lost in GET")
		}
		if r.URL.Query().Get("filter_id") != "fixture-context" || r.URL.Query().Get("wildcard") != "false" {
			t.Error("GET context or explicit false lost")
		}
		_, _ = w.Write([]byte(`{"success":true,"data":{"items":[]}}`))
	}))
	defer server.Close()
	client, _ := NewClient("test-key", WithBaseURL(server.URL))
	extra := map[string][]string{"wildcard": {"false"}}
	if _, err := client.Breach.SearchGet("", &BreachV2SearchOptions{Filter: filter, FilterID: "fixture-context", ExtraQuery: extra}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Stealer.SearchGet("", &StealerSearchOptions{Filter: filter, FilterID: "fixture-context", ExtraQuery: extra}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Victims.SearchGet("", &VictimsSearchOptions{Filter: filter, FilterID: "fixture-context", ExtraQuery: extra}); err != nil {
		t.Fatal(err)
	}
}

func TestPropertyOptionalValuesPreserveFalseZeroAndUnknown(t *testing.T) {
	for _, input := range []string{`{"property_id":"fixture"}`, `{"property_id":"fixture","active":false,"confidence":0,"confidence_score":0}`, `{"property_id":"fixture","active":true,"confidence":0.5,"confidence_score":0.5}`} {
		var item V2VictimPropertyResult
		if err := json.Unmarshal([]byte(input), &item); err != nil {
			t.Fatal(err)
		}
		var source map[string]interface{}
		if err := json.Unmarshal([]byte(input), &source); err != nil {
			t.Fatal(err)
		}
		_, present := source["active"]
		if present != (item.ActiveValue != nil) || present != (item.ConfidenceValue != nil) || present != (item.ConfidenceScoreValue != nil) {
			t.Fatal("optional property state was lost")
		}
		if present && (item.Active != *item.ActiveValue || item.Confidence != *item.ConfidenceValue || item.ConfidenceScore != *item.ConfidenceScoreValue) {
			t.Fatal("legacy scalar values changed")
		}
		encoded, err := json.Marshal(item)
		if err != nil {
			t.Fatal(err)
		}
		var output map[string]interface{}
		if err := json.Unmarshal(encoded, &output); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(source, output) {
			t.Fatalf("optional property state changed on round trip: %s", encoded)
		}
	}
}
