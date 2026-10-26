package oathnet

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
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

func TestSavedEmailDestinationRequests(t *testing.T) {
	destination := `{"uid":"saved-email","name":"Security email","notification_type":"email","recipient_email":"security@example.com","target_hint":"s***@example.com","webhook_security_mode":null,"verified":true}`
	bodies := []map[string]interface{}{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte("[" + destination + "]"))
			return
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		bodies = append(bodies, body)
		if r.URL.Path == "/scanners/destinations" {
			_, _ = w.Write([]byte(destination))
		} else {
			_, _ = w.Write([]byte(`{"success":true}`))
		}
	}))
	defer server.Close()
	client, err := NewClient("test-key", WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	created, err := client.Scanners.CreateDestination(ScannerDestinationCreateRequest{
		Name: "Security email", NotificationType: "email", RecipientEmail: "security@example.com",
	})
	if err != nil || created.RecipientEmail != "security@example.com" || created.WebhookSecurityMode != "" {
		t.Fatalf("email create failed: %#v %v", created, err)
	}
	listed, err := client.Scanners.ListDestinations()
	if err != nil || len(listed) != 1 || listed[0].RecipientEmail != "security@example.com" {
		t.Fatalf("email list failed: %#v %v", listed, err)
	}
	if _, err := client.Scanners.Create(ScannerCreateRequest{Name: "Monitor", UseAccountEmail: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Scanners.Update("monitor", ScannerUpdateRequest{Name: "Renamed"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Scanners.Update("monitor", ScannerUpdateRequest{UseAccountEmail: true}); err != nil {
		t.Fatal(err)
	}
	query := ScannerQueryConfig{"q": "example.com"}
	for _, request := range []ScannerDraftTestRequest{
		{ScannerType: "breach", QueryConfig: query, DestinationUID: "saved-email"},
		{ScannerType: "breach", QueryConfig: query, UseAccountEmail: true},
	} {
		if _, err := client.Scanners.TestDraftDelivery(request); err != nil {
			t.Fatal(err)
		}
	}
	want := []map[string]interface{}{
		{"name": "Security email", "notification_type": "email", "recipient_email": "security@example.com"},
		{"name": "Monitor", "destination_uid": nil},
		{"name": "Renamed"},
		{"destination_uid": nil},
		{"scanner_type": "breach", "query_config": map[string]interface{}{"q": "example.com"}, "destination_uid": "saved-email"},
		{"scanner_type": "breach", "query_config": map[string]interface{}{"q": "example.com"}, "destination_uid": nil},
	}
	if !reflect.DeepEqual(bodies, want) {
		t.Fatalf("unexpected request bodies: got %#v, want %#v", bodies, want)
	}
}
