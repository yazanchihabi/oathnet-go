package oathnet

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestScannerDestinationLifecycleRequests(t *testing.T) {
	uid := "00000000-0000-4000-8000-000000000001"
	seen := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen[r.Method+" "+r.URL.Path]++
		if r.Header.Get("x-api-key") != "test-key" {
			t.Error("missing authentication")
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /scanners/destinations":
			_, _ = w.Write([]byte(`[{"uid":"` + uid + `","name":"Example","notification_type":"webhook","target_hint":"alerts.example.com","webhook_security_mode":"signed_json","verified":true}]`))
		case "POST /scanners/destinations":
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"name", "notification_type", "webhook_url", "webhook_secret", "webhook_security_mode"} {
				if body[key] == nil {
					t.Errorf("missing %s", key)
				}
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"uid":"` + uid + `","name":"Example","verified":true}`))
		case "POST /scanners/create", "PATCH /scanners/" + uid + "/update":
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["destination_uid"] != uid {
				t.Errorf("destination was not serialized: %#v", body)
			}
			if body["notification_type"] != nil {
				t.Error("saved destination must be allowed to inherit the delivery type")
			}
			_, _ = w.Write([]byte(`{"uid":"` + uid + `","destination_uid":"` + uid + `","destination_name":"Example","destination_target_hint":"alerts.example.com"}`))
		case "DELETE /scanners/destinations/" + uid:
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected route %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	client, _ := NewClient("test-key", WithBaseURL(server.URL))
	list, err := client.Scanners.ListDestinations()
	if err != nil || len(list) != 1 || !list[0].Verified {
		t.Fatalf("list failed: %#v %v", list, err)
	}
	created, err := client.Scanners.CreateDestination(ScannerDestinationCreateRequest{Name: "Example", NotificationType: "webhook", WebhookURL: "https://alerts.example.com/events", WebhookSecret: "test-signing-secret", WebhookSecurityMode: "signed_json"})
	if err != nil || created.UID != uid {
		t.Fatalf("create failed: %#v %v", created, err)
	}
	scanner, err := client.Scanners.Create(ScannerCreateRequest{Name: "Example monitor", QueryConfig: ScannerQueryConfig{"q": "user@example.com"}, DestinationUID: uid})
	if err != nil || scanner.DestinationUID == nil || *scanner.DestinationUID != uid {
		t.Fatalf("monitor create failed: %#v %v", scanner, err)
	}
	if _, err := client.Scanners.Update(uid, ScannerUpdateRequest{DestinationUID: uid}); err != nil {
		t.Fatal(err)
	}
	if err := client.Scanners.DeleteDestination(uid); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 5 {
		t.Fatalf("expected 5 distinct operations, got %v", seen)
	}
}
