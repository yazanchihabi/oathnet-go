package oathnet

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPhonebookPageRequestAndValidation(t *testing.T) {
	for _, kind := range []string{"emails", "subdomains"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/service/v2/phonebook/"+kind || r.URL.Query().Get("cursor") != "opaque/+==" || r.URL.Query().Get("pwned_from") != "2025-01-01" || r.URL.Query().Get("indexed_to") != "2026-01-31" || r.URL.Query().Get("search_id") != "session" {
					t.Errorf("incorrect page request")
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"success":true,"data":{"domain":"example.com","kind":%q,"source":"all","returned_count":0,"page_size":50,"has_more":false,"visible_limit":-1,"limited":false}}`, kind)
			}))
			defer server.Close()
			client, err := NewClient("test-placeholder", WithBaseURL(server.URL))
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Stealer.PhonebookPage(kind, "example.com", &PhonebookPageOptions{Cursor: "opaque/+==", PwnedFrom: "2025-01-01", IndexedTo: "2026-01-31", SearchID: "session"})
			if err != nil || !response.Success || calls != 1 {
				t.Fatalf("response=%+v err=%v calls=%d", response, err, calls)
			}
		})
	}
	for _, page := range []*V2PhonebookPageData{nil, {Domain: "example.com", Kind: "emails", Source: "all", PageSize: 101}, {Domain: "example.com", Kind: "emails", Source: "all", PageSize: 50, ReturnedCount: 1}, {Domain: "example.com", Kind: "emails", Source: "all", PageSize: 50, HasMore: true}} {
		if validatePhonebookPage(page, "emails", "all") == nil {
			t.Fatal("accepted malformed page")
		}
	}
}

func TestPhonebookInitialPagesPreservesMetadataAndSources(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != phonebookV2Path || r.URL.Query().Get("paged") != "true" || r.URL.Query().Get("source") != "breach" {
			t.Errorf("incorrect initial page request")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"success":true,"_meta":{"search_id":"session-one"},"data":{"domain":"example.com","pages":{"emails":{"domain":"example.com","kind":"emails","source":"breach","returned_count":0,"page_size":50,"has_more":false,"visible_limit":-1,"limited":false},"subdomains":{"domain":"example.com","kind":"subdomains","source":"all","returned_count":0,"page_size":50,"has_more":false,"visible_limit":-1,"limited":false}}}}`)
	}))
	defer server.Close()
	client, err := NewClient("test-placeholder", WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Stealer.PhonebookInitialPages("example.com", &PhonebookPageOptions{Source: "breach"})
	if err != nil {
		t.Fatal(err)
	}
	if response.Meta["search_id"] != "session-one" {
		t.Fatalf("lost response metadata: %+v", response.Meta)
	}
}
