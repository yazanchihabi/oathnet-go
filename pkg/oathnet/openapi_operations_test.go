package oathnet

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// This table lists every public OpenAPI operation. Rich request and response
// assertions live in the service tests; this catches missing routes and methods.
func TestPublicOpenAPIOperations(t *testing.T) {
	cases := []struct {
		operationID string
		method      string
		path        string
		call        func(*Client) error
	}{
		{"initSearchSession", "POST", "/service/search/init", func(c *Client) error { _, err := c.Search.InitSession("user@example.com"); return err }},
		{"searchBreach", "GET", "/service/search-breach", func(c *Client) error { _, err := c.Search.Breach("user@example.com", nil); return err }},
		{"searchStealerOriginal", "GET", "/service/search-stealer", func(c *Client) error { _, err := c.Search.Stealer("user@example.com", nil); return err }},
		{"searchStealerV2", "GET", "/service/v2/stealer/search", func(c *Client) error { _, err := c.Stealer.Search("user@example.com", nil); return err }},
		{"searchStealerV2Post", "POST", "/service/v2/stealer/search", func(c *Client) error {
			_, err := c.Stealer.SearchPost(V2SearchPostBody{"q": "user@example.com"}, nil)
			return err
		}},
		{"extractSubdomainV2", "GET", "/service/v2/stealer/subdomain", func(c *Client) error { _, err := c.Stealer.ExtractSubdomainV2("example.com", nil); return err }},
		{"investigateStealerV2", "GET", "/service/v2/stealer/investigation/search", func(c *Client) error { _, err := c.Stealer.InvestigationSearch("user@example.com", nil); return err }},
		{"investigateStealerV2Post", "POST", "/service/v2/stealer/investigation/search", func(c *Client) error {
			_, err := c.Stealer.InvestigationSearchPost(&V2InvestigationSearchRequest{Q: "user@example.com"})
			return err
		}},
		{"getPhonebookV2", "GET", "/service/v2/phonebook", func(c *Client) error { _, err := c.Stealer.GetPhonebook("example.com", nil); return err }},
		{"searchBreachV2", "GET", "/service/v2/breach/search", func(c *Client) error { _, err := c.Breach.Search("user@example.com", nil); return err }},
		{"searchBreachV2Post", "POST", "/service/v2/breach/search", func(c *Client) error {
			_, err := c.Breach.SearchPost(V2SearchPostBody{"q": "user@example.com"}, nil)
			return err
		}},
		{"autocompleteBreachValuesV2", "GET", "/service/v2/breach/autocomplete", func(c *Client) error {
			_, err := c.Breach.Autocomplete(&BreachV2AutocompleteOptions{Field: "email", Query: "user@"})
			return err
		}},
		{"autocompleteBreachDBNamesV2", "GET", "/service/v2/breach/autocomplete/dbnames", func(c *Client) error { _, err := c.Breach.AutocompleteDBNames(nil); return err }},
		{"autocompleteBreachFieldsV2", "GET", "/service/v2/breach/autocomplete/fields", func(c *Client) error {
			_, err := c.Breach.AutocompleteFields(&BreachV2AutocompleteFieldsOptions{Field: "email"})
			return err
		}},
		{"createAIFilterV2", "POST", "/service/v2/ai/filter", func(c *Client) error {
			_, err := c.AI.Create(V2AIFilterRequest{Query: "Email is user@example.com", Index: AIFilterIndexBreach})
			return err
		}},
		{"getAIFilterContextV2", "GET", "/service/v2/ai/filter/fixture", func(c *Client) error { _, err := c.AI.GetContext("fixture"); return err }},
		{"searchVictimsV2", "GET", "/service/v2/victims/search", func(c *Client) error { _, err := c.Victims.Search("user@example.com", nil); return err }},
		{"searchVictimsV2Post", "POST", "/service/v2/victims/search", func(c *Client) error {
			_, err := c.Victims.SearchPost(V2SearchPostBody{"q": "user@example.com"}, nil)
			return err
		}},
		{"searchFilesMetadataV2", "GET", "/service/v2/files/search", func(c *Client) error { _, err := c.Victims.SearchFilesMetadata(nil); return err }},
		{"searchFilesMetadataV2Post", "POST", "/service/v2/files/search", func(c *Client) error {
			_, err := c.Victims.SearchFilesMetadataPost(&V2FileMetadataSearchRequest{Query: "example"})
			return err
		}},
		{"searchVictimPropertiesV2", "GET", "/service/v2/victims/properties/search", func(c *Client) error { _, err := c.Victims.SearchVictimProperties(nil); return err }},
		{"searchVictimPropertiesV2Post", "POST", "/service/v2/victims/properties/search", func(c *Client) error {
			_, err := c.Victims.SearchVictimPropertiesPost(&V2VictimPropertiesSearchRequest{Query: "example"})
			return err
		}},
		{"getVictimPropertiesV2", "GET", "/service/v2/victims/fixture/properties", func(c *Client) error { _, err := c.Victims.GetProperties("fixture", nil); return err }},
		{"getVictimSummaryV2", "GET", "/service/v2/victims/fixture/summary", func(c *Client) error { _, err := c.Victims.GetSummary("fixture", nil); return err }},
		{"getVictimCookiesV2", "GET", "/service/v2/victims/fixture/cookies", func(c *Client) error { _, err := c.Victims.GetCookies("fixture", nil); return err }},
		{"inspectVictimCookieDomainV2", "GET", "/service/v2/victims/fixture/cookies/domain", func(c *Client) error {
			_, err := c.Victims.InspectCookieDomain("fixture", &VictimCookieDomainOptions{Domain: "example.com"})
			return err
		}},
		{"getVictimManifestV2", "GET", "/service/v2/victims/fixture", func(c *Client) error { _, err := c.Victims.GetManifest("fixture"); return err }},
		{"getVictimFileV2", "GET", "/service/v2/victims/fixture/files/fixture", func(c *Client) error { _, err := c.Victims.GetFile("fixture", "fixture"); return err }},
		{"downloadVictimArchiveV2", "GET", "/service/v2/victims/fixture/archive", func(c *Client) error { _, err := c.Victims.DownloadArchiveBytes("fixture"); return err }},
		{"createFileSearchV2", "POST", "/service/v2/file-search", func(c *Client) error {
			_, err := c.FileSearch.Create("example", &FileSearchCreateOptions{LogIDs: []string{"fixture"}})
			return err
		}},
		{"getFileSearchV2", "GET", "/service/v2/file-search/fixture", func(c *Client) error { _, err := c.FileSearch.GetStatus("fixture"); return err }},
		{"createBulkSearchV2", "POST", "/service/v2/bulk-search", func(c *Client) error {
			_, err := c.Bulk.Create([]string{"user@example.com"}, "breach", nil)
			return err
		}},
		{"listBulkSearchV2", "GET", "/service/v2/bulk-search/list", func(c *Client) error { _, err := c.Bulk.List(1, 25); return err }},
		{"getBulkSearchV2", "GET", "/service/v2/bulk-search/fixture", func(c *Client) error { _, err := c.Bulk.GetStatus("fixture"); return err }},
		{"downloadBulkSearchV2", "GET", "/service/v2/bulk-search/fixture/download", func(c *Client) error { _, err := c.Bulk.DownloadBytes("fixture"); return err }},
		{"createExportV2", "POST", "/service/v2/exports", func(c *Client) error {
			_, err := c.Exports.Create("breach", &ExportCreateOptions{Search: map[string]interface{}{"q": "user@example.com"}})
			return err
		}},
		{"listExportsV2", "GET", "/service/v2/exports/list", func(c *Client) error { _, err := c.Exports.List(1, 25); return err }},
		{"getExportV2", "GET", "/service/v2/exports/fixture", func(c *Client) error { _, err := c.Exports.GetStatus("fixture"); return err }},
		{"downloadExportV2", "GET", "/service/v2/exports/fixture/download", func(c *Client) error { _, err := c.Exports.DownloadBytes("fixture"); return err }},
		{"getScannerQuota", "GET", "/scanners/quota", func(c *Client) error { _, err := c.Scanners.GetQuota(); return err }},
		{"listScanners", "GET", "/scanners", func(c *Client) error { _, err := c.Scanners.List(nil); return err }},
		{"createScanner", "POST", "/scanners/create", func(c *Client) error {
			_, err := c.Scanners.Create(ScannerCreateRequest{Name: "Example", QueryConfig: ScannerQueryConfig{"q": "user@example.com"}})
			return err
		}},
		{"getScanner", "GET", "/scanners/fixture", func(c *Client) error { _, err := c.Scanners.Get("fixture"); return err }},
		{"updateScanner", "PATCH", "/scanners/fixture/update", func(c *Client) error {
			_, err := c.Scanners.Update("fixture", ScannerUpdateRequest{Name: "Example"})
			return err
		}},
		{"deleteScanner", "DELETE", "/scanners/fixture/delete", func(c *Client) error { return c.Scanners.Delete("fixture") }},
		{"testDraftScannerDelivery", "POST", "/scanners/test-delivery", func(c *Client) error {
			_, err := c.Scanners.TestDraftDelivery(ScannerDraftTestRequest{Name: "Example"})
			return err
		}},
		{"testScannerNotification", "POST", "/scanners/fixture/test", func(c *Client) error { _, err := c.Scanners.TestNotification("fixture"); return err }},
		{"getScannerWebhookSecurity", "GET", "/scanners/fixture/webhook-security", func(c *Client) error { _, err := c.Scanners.GetWebhookSecurity("fixture"); return err }},
		{"rotateScannerWebhookSecret", "POST", "/scanners/fixture/webhook-security/rotate", func(c *Client) error { _, err := c.Scanners.RotateWebhookSecret("fixture"); return err }},
		{"pauseScanner", "POST", "/scanners/fixture/pause", func(c *Client) error { _, err := c.Scanners.Pause("fixture"); return err }},
		{"resumeScanner", "POST", "/scanners/fixture/resume", func(c *Client) error { _, err := c.Scanners.Resume("fixture"); return err }},
		{"triggerScanner", "POST", "/scanners/fixture/trigger", func(c *Client) error { _, err := c.Scanners.Trigger("fixture"); return err }},
		{"listScannerRuns", "GET", "/scanners/fixture/runs", func(c *Client) error { _, err := c.Scanners.ListRuns("fixture", nil); return err }},
		{"getScannerRun", "GET", "/scanners/fixture/runs/fixture", func(c *Client) error { _, err := c.Scanners.GetRun("fixture", "fixture"); return err }},
		{"ipInfo", "GET", "/service/ip-info", func(c *Client) error { _, err := c.OSINT.IPInfo("192.0.2.1"); return err }},
		{"steamLookup", "GET", "/service/steam", func(c *Client) error { _, err := c.OSINT.Steam("76561198000000000"); return err }},
		{"xboxLookup", "GET", "/service/xbox", func(c *Client) error { _, err := c.OSINT.Xbox("example_account"); return err }},
		{"discordUserinfo", "GET", "/service/discord-userinfo", func(c *Client) error { _, err := c.OSINT.DiscordUserinfo("100000000000000001"); return err }},
		{"discordUsernameHistory", "GET", "/service/discord-username-history", func(c *Client) error { _, err := c.OSINT.DiscordUsernameHistory("100000000000000001"); return err }},
		{"robloxUserinfo", "GET", "/service/roblox-userinfo", func(c *Client) error {
			_, err := c.OSINT.RobloxUserinfo(RobloxUserinfoOptions{Username: "example_account"})
			return err
		}},
		{"holehe", "GET", "/service/holehe", func(c *Client) error { _, err := c.OSINT.Holehe("user@example.com"); return err }},
		{"ghunt", "GET", "/service/ghunt", func(c *Client) error { _, err := c.OSINT.GHunt("user@example.com"); return err }},
		{"extractSubdomain", "GET", "/service/extract-subdomain", func(c *Client) error { _, err := c.OSINT.ExtractSubdomain("example.com", nil); return err }},
		{"dbnameAutocomplete", "GET", "/service/dbname-autocomplete", func(c *Client) error { _, err := c.Utility.DBNameAutocomplete("example"); return err }},
		{"minecraftHistory", "GET", "/service/mc-history", func(c *Client) error { _, err := c.OSINT.MinecraftHistory("example_account"); return err }},
		{"enrichIdentity", "GET", "/service/enrichment/", func(c *Client) error {
			_, err := c.OSINT.EnrichIdentity(EnrichmentRequest{Input: "example_account", Type: "username", Modules: []string{"instagram"}})
			return err
		}},
		{"enrichIdentityPost", "POST", "/service/enrichment/", func(c *Client) error {
			_, err := c.OSINT.EnrichIdentityPost(EnrichmentRequest{Input: "example_account", Type: "username", Modules: []string{"instagram"}})
			return err
		}},
		{"listScannerDestinations", "GET", "/scanners/destinations", func(c *Client) error { _, err := c.Scanners.ListDestinations(); return err }},
		{"createScannerDestination", "POST", "/scanners/destinations", func(c *Client) error {
			_, err := c.Scanners.CreateDestination(ScannerDestinationCreateRequest{Name: "Example", NotificationType: "webhook", WebhookURL: "https://alerts.example.com/events", WebhookSecret: "test-secret"})
			return err
		}},
		{"deleteScannerDestination", "DELETE", "/scanners/destinations/fixture", func(c *Client) error { return c.Scanners.DeleteDestination("fixture") }},
	}
	for _, tc := range cases {
		t.Run(tc.operationID, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != tc.method || r.URL.Path != tc.path {
					t.Errorf("route = %s %s, want %s %s", r.Method, r.URL.Path, tc.method, tc.path)
				}
				if r.Header.Get("x-api-key") != "test-key" {
					t.Error("missing API key header")
				}
				if r.Method == http.MethodDelete {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				switch tc.operationID {
				case "listScanners", "listScannerRuns", "listScannerDestinations", "dbnameAutocomplete":
					_, _ = w.Write([]byte(`[]`))
				default:
					_, _ = w.Write([]byte(`{"success":true,"data":{"job_id":"fixture","status":"queued","items":[]}}`))
				}
			}))
			defer server.Close()
			client, err := NewClient("test-key", WithBaseURL(server.URL))
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.call(client); err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatalf("expected one request, got %d", calls)
			}
		})
	}
}
