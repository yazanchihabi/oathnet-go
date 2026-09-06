package oathnet

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func responseTestClient(t *testing.T, body string) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	client, err := NewClient("test-key", WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestSearchUsesPlainRepeatedKeys(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for key := range r.URL.Query() {
			if strings.Contains(key, "[") {
				t.Errorf("unexpected bracketed key %q", key)
			}
		}
		if got := r.URL.Query()["fields"]; len(got) != 2 || got[0] != "email" || got[1] != "dbname" {
			t.Errorf("fields must be repeated, got %v", r.URL.Query())
		}
		_, _ = w.Write([]byte(`{"success":true,"data":{"items":[]}}`))
	}))
	defer server.Close()
	client, _ := NewClient("test-key", WithBaseURL(server.URL))
	fields := []string{"email", "dbname"}
	if _, err := client.Breach.Search("user@example.com", &BreachV2SearchOptions{Fields: fields}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Stealer.Search("user@example.com", &StealerSearchOptions{Fields: fields}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Victims.Search("user@example.com", &VictimsSearchOptions{Fields: fields}); err != nil {
		t.Fatal(err)
	}
}

func TestBreachSourceValuesDoNotFailDecoding(t *testing.T) {
	client := responseTestClient(t, `{"success":true,"data":{"items":[{"id":"fixture","email":["user@example.com"],"dbname":["example-source"],"age":"unknown","password":{"redacted":true},"extra":[1,true]}]}}`)
	response, err := client.Breach.Search("user@example.com", nil)
	if err != nil {
		t.Fatalf("valid dynamic source record failed: %v", err)
	}
	if response == nil || response.Data == nil || len(response.Data.Items) != 1 {
		t.Fatalf("missing record: %#v", response)
	}
}

func TestSearchRetainsCountAndAccessMetadata(t *testing.T) {
	client := responseTestClient(t, `{"success":true,"_meta":{"result_access":{"availability":"more_available","count_relation":"gte","revealed_count":1}},"data":{"items":[],"meta":{"count":0,"total":100,"total_relation":"gte"}}}`)
	response, err := client.Stealer.Search("user@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{`"total_relation":"gte"`, `"availability":"more_available"`} {
		if !strings.Contains(string(encoded), part) {
			t.Errorf("dropped metadata %s from %s", part, encoded)
		}
	}
}

func TestJobDecodersRejectInvalidData(t *testing.T) {
	for _, body := range []string{`{"success":true,"data":{"job_id":"fixture","status":17}}`, `{"success":true,"data":[]}`, `{"success":true,"data":{}}`, `{}`} {
		client := responseTestClient(t, body)
		for name, call := range map[string]func() error{
			"file-search": func() error { _, err := client.FileSearch.GetStatus("fixture-job"); return err },
			"export":      func() error { _, err := client.Exports.GetStatus("fixture-job"); return err },
			"bulk":        func() error { _, err := client.Bulk.GetStatus("fixture-job"); return err },
		} {
			t.Run(name+body, func(t *testing.T) {
				if err := call(); err == nil {
					t.Fatal("invalid job data was accepted")
				}
			})
		}
	}
}

func TestJobPollingStopsOnTerminalFailure(t *testing.T) {
	for _, status := range []string{"failed", "canceled"} {
		client := responseTestClient(t, fmt.Sprintf(`{"success":true,"data":{"job_id":"fixture-job","status":%q,"last_error":"fixture failure"}}`, status))
		for name, call := range map[string]func() error{
			"file-search": func() error {
				_, err := client.FileSearch.WaitForCompletion("fixture-job", time.Millisecond, 250*time.Millisecond)
				return err
			},
			"export": func() error {
				_, err := client.Exports.WaitForCompletion("fixture-job", time.Millisecond, 250*time.Millisecond)
				return err
			},
			"bulk": func() error {
				_, err := client.Bulk.WaitForCompletion("fixture-job", time.Millisecond, 250*time.Millisecond)
				return err
			},
		} {
			t.Run(name+status, func(t *testing.T) {
				err := call()
				if err == nil || !strings.Contains(err.Error(), status) {
					t.Fatalf("expected terminal %s error, got %v", status, err)
				}
			})
		}
	}
}
