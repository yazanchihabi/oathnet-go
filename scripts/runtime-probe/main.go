// Run explicit SDK probes against the disposable local acceptance API.
// The context file is supplied by the development credential broker. It is
// read into memory; reports contain operation outcomes and response hashes only.
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/oathnet/oathnet-go/pkg/oathnet"
)

type fixtures struct {
	AutocompleteQuery  string                            `json:"autocomplete_query"`
	AutocompleteDBName string                            `json:"autocomplete_dbname"`
	APIKey             string                            `json:"api_key"`
	BaseURL            string                            `json:"base_url"`
	Query              string                            `json:"query"`
	Email              string                            `json:"email"`
	Domain             string                            `json:"domain"`
	LogID              string                            `json:"log_id"`
	FileID             string                            `json:"file_id"`
	CookieDomain       string                            `json:"cookie_domain"`
	FileExpression     string                            `json:"file_expression"`
	FileSHA256         string                            `json:"file_sha256"`
	ArchiveSHA256      string                            `json:"archive_sha256"`
	WebhookURL         string                            `json:"webhook_url"`
	WebhookSecret      string                            `json:"webhook_secret"`
	IP                 string                            `json:"ip"`
	SteamID            string                            `json:"steam_id"`
	XboxID             string                            `json:"xbl_id"`
	DiscordID          string                            `json:"discord_id"`
	RobloxUsername     string                            `json:"roblox_username"`
	RobloxUserID       string                            `json:"roblox_user_id"`
	DomainAlias        string                            `json:"domain_alias"`
	EnrichmentInput    string                            `json:"enrichment_input"`
	EnrichmentType     string                            `json:"enrichment_type"`
	EnrichmentModules  []string                          `json:"enrichment_modules"`
	ProviderEvidence   string                            `json:"provider_evidence"`
	ProviderExpected   map[string]map[string]interface{} `json:"-"`
}

type recorder struct {
	target      *url.URL
	transport   http.RoundTripper
	requests    int
	status      int
	body        []byte
	contentType string
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != r.target.Scheme || req.URL.Host != r.target.Host {
		return nil, errors.New("probe refused a different API origin")
	}
	r.requests++
	response, err := r.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 8*1024*1024+1))
	_ = response.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(body) > 8*1024*1024 {
		return nil, errors.New("probe response exceeded 8 MiB")
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	r.status = response.StatusCode
	r.body = body
	r.contentType = response.Header.Get("Content-Type")
	return response, nil
}

type row struct {
	Operation      string `json:"operation"`
	Scenario       string `json:"scenario"`
	Status         string `json:"status"`
	Proof          string `json:"proof"`
	HTTPStatus     int    `json:"http_status,omitempty"`
	Requests       int    `json:"requests"`
	ResponseBytes  int    `json:"response_bytes"`
	ResponseSHA256 string `json:"response_sha256,omitempty"`
	ContentType    string `json:"content_type,omitempty"`
	ErrorType      string `json:"error_type,omitempty"`
	Check          string `json:"check,omitempty"`
	ElapsedMS      int64  `json:"elapsed_ms"`
}

type probe struct {
	f              fixtures
	client         *oathnet.Client
	transport      *recorder
	rows           []row
	output         *json.Encoder
	sessionID      string
	filterID       string
	fileJob        string
	exportJob      string
	bulkJob        string
	scanner        string
	destination    string
	runID          string
	allowProviders bool
	allowMonitors  bool
	dbname         string
}

type checkError string

func (e checkError) Error() string { return string(e) }

type fixtureError string

func (e fixtureError) Error() string { return string(e) }
func need(ok bool, message string) error {
	if !ok {
		return checkError(message)
	}
	return nil
}
func present(value interface{}) bool {
	if value == nil {
		return false
	}
	v := reflect.ValueOf(value)
	return v.Kind() != reflect.Ptr || !v.IsNil()
}
func digest(value []byte) string                  { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }
func (p *probe) run(op string, call func() error) { p.runCase(op, "positive", call) }

func (p *probe) runCase(op, scenario string, call func() error) {
	started := time.Now()
	count := p.transport.requests
	p.transport.status = 0
	p.transport.body = nil
	p.transport.contentType = ""
	var err error
	if isMonitor(op) && !p.allowMonitors {
		err = fixtureError("monitor fixture execution is not enabled")
	} else if isProvider(op) && !p.allowProviders {
		err = fixtureError("provider fixture execution is not enabled")
	} else {
		err = call()
	}
	if err == nil && scenario == "positive" {
		err = p.checkProviderFields(op)
	}
	result := row{Operation: op, Scenario: scenario, Status: "passed", Proof: "real-dev-sdk", HTTPStatus: p.transport.status, Requests: p.transport.requests - count, ResponseBytes: len(p.transport.body), ContentType: p.transport.contentType, ElapsedMS: time.Since(started).Milliseconds()}
	if result.ResponseBytes > 0 {
		result.ResponseSHA256 = digest(p.transport.body)
	}
	if err != nil {
		result.Status = "failed"
		result.ErrorType = fmt.Sprintf("%T", err)
		switch value := err.(type) {
		case checkError:
			result.Check = string(value)
		case fixtureError:
			result.Status = "blocked-fixture"
			result.Check = string(value)
		}
	}
	if isProvider(op) {
		result.Proof = "real-dev-sdk-synthetic-provider-wire"
		if p.f.ProviderEvidence != "" {
			result.Proof = p.f.ProviderEvidence
		}
	}
	if op == "ghunt" || op == "holehe" {
		result.Proof = "real-dev-sdk-synthetic-provider-adapter"
	}
	if op == "minecraftHistory" {
		result.Proof = "real-dev-disabled-compatibility"
	}
	if isMonitor(op) {
		result.Proof = "real-dev-sdk-synthetic-notification-receiver"
	}
	p.rows = append(p.rows, result)
	if err := p.output.Encode(result); err != nil {
		panic(err)
	}
}
func isProvider(op string) bool {
	switch op {
	case "createAIFilterV2", "getAIFilterContextV2", "ipInfo", "steamLookup", "xboxLookup", "discordUserinfo", "robloxUserinfo", "holehe", "ghunt", "enrichIdentity", "enrichIdentityPost", "testDraftScannerDelivery", "testScannerNotification", "createScannerDestination":
		return true
	}
	return false
}
func isMonitor(op string) bool { return strings.Contains(op, "Scanner") }

func (p *probe) requireVictim() error {
	if p.f.LogID == "" {
		return fixtureError("missing selected victim fixture")
	}
	return nil
}
func (p *probe) requireScanner() error {
	if p.scanner == "" {
		return fixtureError("monitor creation did not provide an owned UID")
	}
	return nil
}
func (p *probe) requireJob(id string) error {
	if id == "" {
		return fixtureError("job creation did not provide an ID")
	}
	return nil
}
func (p *probe) searchOptions() *oathnet.BreachV2SearchOptions {
	return &oathnet.BreachV2SearchOptions{PageSize: 1, Fields: []string{"email", "dbname"}, SearchID: p.sessionID}
}

func (p *probe) searches() {
	p.run("initSearchSession", func() error {
		r, e := p.client.Search.InitSession(p.f.Query)
		if e != nil {
			return e
		}
		if !r.Success || r.Data == nil || r.Data.Session == nil {
			return checkError("missing session envelope")
		}
		p.sessionID = r.Data.Session.ID
		return need(p.sessionID != "", "missing session ID")
	})
	p.run("searchBreachV2", func() error {
		r, e := p.client.Breach.SearchGet(p.f.Email, p.searchOptions())
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && len(r.Data.Items) > 0, "known breach fixture not returned")
	})
	p.run("searchBreachV2Post", func() error {
		r, e := p.client.Breach.SearchPost(oathnet.V2SearchPostBody{"q": p.f.Email, "page_size": 1, "fields": []string{"email", "dbname"}, "search_id": p.sessionID}, nil)
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && len(r.Data.Items) > 0, "known breach POST fixture not returned")
	})
	p.run("searchBreach", func() error {
		r, e := p.client.Search.Breach(p.f.Email, &oathnet.SearchOptions{SearchID: p.sessionID})
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && len(r.Data.Results) > 0, "known legacy breach fixture not returned")
	})
	p.run("searchStealerV2", func() error {
		r, e := p.client.Stealer.SearchGet(p.f.Query, &oathnet.StealerSearchOptions{PageSize: 1, SearchID: p.sessionID})
		if e != nil {
			return e
		}
		if !r.Success || r.Data == nil || len(r.Data.Items) == 0 {
			return checkError("known credential fixture not returned")
		}
		if p.f.LogID == "" {
			p.f.LogID = r.Data.Items[0].LogID
		}
		return nil
	})
	p.run("searchStealerV2Post", func() error {
		r, e := p.client.Stealer.SearchPost(oathnet.V2SearchPostBody{"q": p.f.Query, "page_size": 1, "search_id": p.sessionID}, nil)
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && len(r.Data.Items) > 0, "known credential POST fixture not returned")
	})
	p.run("searchStealerOriginal", func() error {
		r, e := p.client.Search.Stealer(p.f.Query, &oathnet.SearchOptions{SearchID: p.sessionID})
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && len(r.Data.Results) > 0, "known legacy credential fixture not returned")
	})
	p.run("extractSubdomainV2", func() error {
		r, e := p.client.Stealer.Subdomain(p.domain(), "", &oathnet.SubdomainOptions{SearchID: p.sessionID})
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && len(r.Data.Subdomains) > 0, "known subdomain fixture not returned")
	})
	p.run("getPhonebookV2", func() error {
		r, e := p.client.Stealer.GetPhonebook(p.domain(), &oathnet.PhonebookOptions{SearchID: p.sessionID})
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && len(r.Data.Subdomains)+len(r.Data.Emails) > 0, "known phonebook fixture not returned")
	})
	p.run("investigateStealerV2", func() error {
		r, e := p.client.Stealer.InvestigationSearch(p.f.Query, &oathnet.InvestigationSearchOptions{Include: []string{"credentials", "victims", "evidence", "files"}, PageSize: 1, SearchID: p.sessionID})
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && (r.Data.Sections != nil || r.Data.Credentials != nil), "missing investigation sections")
	})
	p.run("investigateStealerV2Post", func() error {
		r, e := p.client.Stealer.InvestigationSearchPost(&oathnet.V2InvestigationSearchRequest{Q: p.f.Query, Include: []string{"credentials", "victims", "evidence", "files"}, PageSize: 1, SearchID: p.sessionID, Compact: true})
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && r.Data.Sections != nil, "missing compact investigation sections")
	})
	p.run("autocompleteBreachValuesV2", func() error {
		r, e := p.client.Breach.Autocomplete(&oathnet.BreachV2AutocompleteOptions{Field: "email_domain", Query: p.f.AutocompleteQuery, Limit: 5})
		if e != nil {
			return e
		}
		return need(len(r.Items) > 0, "known autocomplete value not returned")
	})
	p.run("autocompleteBreachDBNamesV2", func() error {
		r, e := p.client.Breach.AutocompleteDBNames(&oathnet.BreachV2AutocompleteDBNamesOptions{Query: p.f.AutocompleteDBName, Limit: 5})
		if e != nil {
			return e
		}
		if len(r.Items) > 0 {
			p.dbname = r.Items[0].Name
		}
		return need(len(r.Items) > 0, "source-name autocomplete empty")
	})
	p.run("autocompleteBreachFieldsV2", func() error {
		r, e := p.client.Breach.AutocompleteFields(&oathnet.BreachV2AutocompleteFieldsOptions{Field: "email", Limit: 5})
		if e != nil {
			return e
		}
		return need(len(r.Items) > 0, "field coverage autocomplete empty")
	})
	p.run("dbnameAutocomplete", func() error {
		r, e := p.client.Utility.DBNameAutocomplete(p.dbname)
		if e != nil {
			return e
		}
		return need(len(r) > 0, "legacy source-name autocomplete empty")
	})
	p.ai()
}

func (p *probe) ai() {
	p.run("createAIFilterV2", func() error {
		r, e := p.client.AI.Create(oathnet.V2AIFilterRequest{Query: "Find " + p.f.Email, Index: oathnet.AIFilterIndexBreach})
		if e != nil {
			return e
		}
		p.filterID = r.FilterID
		return need(p.filterID != "", "AI filter did not return a context ID")
	})
	p.run("getAIFilterContextV2", func() error {
		if p.filterID == "" {
			return fixtureError("AI creation did not provide a context ID")
		}
		r, e := p.client.AI.GetContext(p.filterID)
		if e != nil {
			return e
		}
		return need(r.ID == p.filterID, "AI context ID mismatch")
	})
}

func (p *probe) victims() {
	p.run("searchVictimsV2", func() error {
		r, e := p.client.Victims.SearchGet(p.f.Query, &oathnet.VictimsSearchOptions{PageSize: 1, SearchID: p.sessionID})
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && len(r.Data.Items) > 0, "known victim fixture not returned")
	})
	p.run("searchVictimsV2Post", func() error {
		r, e := p.client.Victims.SearchPost(oathnet.V2SearchPostBody{"q": p.f.Query, "page_size": 1, "search_id": p.sessionID}, nil)
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && len(r.Data.Items) > 0, "known victim POST fixture not returned")
	})
	p.run("searchFilesMetadataV2", func() error {
		if e := p.requireVictim(); e != nil {
			return e
		}
		r, e := p.client.Victims.SearchFilesMetadata(&oathnet.FileMetadataSearchOptions{LogID: p.f.LogID, PageSize: 5, SearchID: p.sessionID})
		if e != nil {
			return e
		}
		if !r.Success || r.Data == nil || len(r.Data.Items) == 0 {
			return checkError("known file metadata fixture not returned")
		}
		if p.f.FileID == "" {
			p.f.FileID = r.Data.Items[0].FileID
		}
		return nil
	})
	p.run("searchFilesMetadataV2Post", func() error {
		if e := p.requireVictim(); e != nil {
			return e
		}
		r, e := p.client.Victims.SearchFilesMetadataPost(&oathnet.V2FileMetadataSearchRequest{LogID: p.f.LogID, PageSize: 5, SearchID: p.sessionID})
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && len(r.Data.Items) > 0, "known file POST fixture not returned")
	})
	p.run("searchVictimPropertiesV2", func() error {
		if e := p.requireVictim(); e != nil {
			return e
		}
		r, e := p.client.Victims.SearchVictimProperties(&oathnet.VictimPropertiesSearchOptions{LogID: p.f.LogID, PageSize: 5, SearchID: p.sessionID})
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && len(r.Data.Items) > 0, "known property fixture not returned")
	})
	p.run("searchVictimPropertiesV2Post", func() error {
		if e := p.requireVictim(); e != nil {
			return e
		}
		r, e := p.client.Victims.SearchVictimPropertiesPost(&oathnet.V2VictimPropertiesSearchRequest{LogID: p.f.LogID, PageSize: 5, SearchID: p.sessionID})
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && len(r.Data.Items) > 0, "known property POST fixture not returned")
	})
	p.run("getVictimPropertiesV2", func() error {
		if e := p.requireVictim(); e != nil {
			return e
		}
		r, e := p.client.Victims.GetProperties(p.f.LogID, &oathnet.VictimPropertiesSearchOptions{PageSize: 5, SearchID: p.sessionID})
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && len(r.Data.Items) > 0, "known victim properties not returned")
	})
	p.run("getVictimSummaryV2", func() error {
		if e := p.requireVictim(); e != nil {
			return e
		}
		r, e := p.client.Victims.GetSummary(p.f.LogID, &oathnet.VictimSummaryOptions{SearchID: p.sessionID})
		if e != nil {
			return e
		}
		return need(r.LogID == p.f.LogID, "summary log ID mismatch")
	})
	p.run("getVictimCookiesV2", func() error {
		if e := p.requireVictim(); e != nil {
			return e
		}
		r, e := p.client.Victims.GetCookies(p.f.LogID, &oathnet.VictimCookieInventoryOptions{SearchID: p.sessionID})
		if e != nil {
			return e
		}
		return need(r.LogID == p.f.LogID && len(r.Domains)+len(r.Items) > 0, "known cookie inventory not returned")
	})
	p.run("inspectVictimCookieDomainV2", func() error {
		if e := p.requireVictim(); e != nil {
			return e
		}
		if p.f.CookieDomain == "" {
			return fixtureError("missing cookie-domain fixture")
		}
		r, e := p.client.Victims.InspectCookieDomain(p.f.LogID, &oathnet.VictimCookieDomainOptions{Domain: p.f.CookieDomain, SearchID: p.sessionID})
		if e != nil {
			return e
		}
		return need(strings.Contains(r, p.f.CookieDomain), "cookie-domain content did not include fixture domain")
	})
	p.run("getVictimManifestV2", func() error {
		if e := p.requireVictim(); e != nil {
			return e
		}
		r, e := p.client.Victims.GetManifest(p.f.LogID, &oathnet.VictimRawOptions{SearchID: p.sessionID})
		if e != nil {
			return e
		}
		return need(r.LogID == p.f.LogID && r.VictimTree != nil, "missing victim manifest tree")
	})
	p.run("getVictimFileV2", func() error {
		if e := p.requireVictim(); e != nil {
			return e
		}
		if p.f.FileID == "" {
			return fixtureError("missing file fixture")
		}
		r, e := p.client.Victims.GetFileResponse(p.f.LogID, p.f.FileID, &oathnet.VictimRawOptions{SearchID: p.sessionID})
		if e != nil {
			return e
		}
		if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
			return checkError("received file preview instead of original content")
		}
		if p.f.FileSHA256 != "" {
			return need(digest(r.Body) == p.f.FileSHA256, "file content hash mismatch")
		}
		return need(len(r.Body) > 0 && bytes.Contains(r.Body, []byte(p.f.FileExpression)), "file content did not include fixture expression")
	})
	p.run("downloadVictimArchiveV2", func() error {
		if e := p.requireVictim(); e != nil {
			return e
		}
		r, e := p.client.Victims.DownloadArchiveBytes(p.f.LogID, &oathnet.VictimRawOptions{SearchID: p.sessionID})
		if e != nil {
			return e
		}
		if p.f.ArchiveSHA256 != "" {
			return need(digest(r) == p.f.ArchiveSHA256, "archive content hash mismatch")
		}
		archive, e := zip.NewReader(bytes.NewReader(r), int64(len(r)))
		if e != nil {
			return checkError("archive was not valid ZIP content")
		}
		for _, entry := range archive.File {
			if entry.Name != "Reports/Notes.txt" {
				continue
			}
			file, e := entry.Open()
			if e != nil {
				return checkError("archive fixture entry could not be opened")
			}
			body, e := io.ReadAll(io.LimitReader(file, 4096))
			_ = file.Close()
			if e != nil {
				return checkError("archive fixture entry could not be read")
			}
			return need(bytes.Contains(body, []byte(p.f.FileExpression)), "archive entry content did not match fixture")
		}
		return checkError("archive is missing the selected fixture file")
	})
}

func (p *probe) jobs() {
	p.run("createFileSearchV2", func() error {
		if e := p.requireVictim(); e != nil {
			return e
		}
		r, e := p.client.FileSearch.Create(p.f.FileExpression, &oathnet.FileSearchCreateOptions{LogIDs: []string{p.f.LogID}, SearchMode: "literal", IncludeMatches: true, MaxMatches: 5})
		if e != nil {
			return e
		}
		if r.Data == nil {
			return checkError("missing file-search job")
		}
		p.fileJob = r.Data.JobID
		return need(r.Success && p.fileJob != "", "missing file-search job ID")
	})
	p.run("getFileSearchV2", func() error {
		if e := p.requireJob(p.fileJob); e != nil {
			return e
		}
		r, e := p.client.FileSearch.WaitForCompletion(p.fileJob, time.Second, time.Minute)
		if e != nil {
			return e
		}
		if r.Data == nil || r.Data.Status != "completed" {
			return checkError("file search did not complete")
		}
		for _, match := range r.Data.Matches {
			if match.LogID == p.f.LogID && match.FileID == p.f.FileID && strings.Contains(match.MatchText, p.f.FileExpression) {
				return nil
			}
		}
		return checkError("file search completed without the selected fixture match")
	})
	p.run("createBulkSearchV2", func() error {
		r, e := p.client.Bulk.Create([]string{p.f.Email}, "breach", &oathnet.BulkCreateOptions{Format: "jsonl", Limit: 5, Fields: []string{"email", "dbname"}})
		if e != nil {
			return e
		}
		if r.Data == nil {
			return checkError("missing bulk job")
		}
		p.bulkJob = r.Data.JobID
		return need(r.Success && p.bulkJob != "", "missing bulk job ID")
	})
	p.run("getBulkSearchV2", func() error {
		if e := p.requireJob(p.bulkJob); e != nil {
			return e
		}
		r, e := p.client.Bulk.WaitForCompletion(p.bulkJob, time.Second, time.Minute)
		if e != nil {
			return e
		}
		return need(r.Data != nil && r.Data.Status == "completed", "bulk job did not complete")
	})
	p.run("listBulkSearchV2", func() error {
		r, e := p.client.Bulk.List(1, 50)
		if e != nil {
			return e
		}
		for _, item := range r.Results {
			if item.JobID == p.bulkJob {
				return nil
			}
		}
		return checkError("created bulk job absent from list")
	})
	p.run("downloadBulkSearchV2", func() error {
		if e := p.requireJob(p.bulkJob); e != nil {
			return e
		}
		r, e := p.client.Bulk.DownloadBytes(p.bulkJob)
		if e != nil {
			return e
		}
		return p.checkExportRows(r)
	})
	p.run("createExportV2", func() error {
		r, e := p.client.Exports.Create("breach", &oathnet.ExportCreateOptions{Service: "breach", Format: "jsonl", Limit: 5, Fields: []string{"email", "dbname"}, Search: map[string]interface{}{"q": p.f.Email}})
		if e != nil {
			return e
		}
		if r.Data == nil {
			return checkError("missing export job")
		}
		p.exportJob = r.Data.JobID
		return need(r.Success && p.exportJob != "", "missing export job ID")
	})
	p.run("getExportV2", func() error {
		if e := p.requireJob(p.exportJob); e != nil {
			return e
		}
		r, e := p.client.Exports.WaitForCompletion(p.exportJob, time.Second, time.Minute)
		if e != nil {
			return e
		}
		return need(r.Data != nil && r.Data.Status == "completed", "export job did not complete")
	})
	p.run("listExportsV2", func() error {
		r, e := p.client.Exports.List(1, 50)
		if e != nil {
			return e
		}
		for _, item := range r.Results {
			if item.JobID == p.exportJob {
				return nil
			}
		}
		return checkError("created export job absent from list")
	})
	p.run("downloadExportV2", func() error {
		if e := p.requireJob(p.exportJob); e != nil {
			return e
		}
		r, e := p.client.Exports.DownloadBytes(p.exportJob)
		if e != nil {
			return e
		}
		return p.checkExportRows(r)
	})
}

func (p *probe) checkExportRows(raw []byte) error {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	count := 0
	for scanner.Scan() {
		var item map[string]json.RawMessage
		if json.Unmarshal(scanner.Bytes(), &item) != nil {
			return checkError("download contains a non-JSONL record")
		}
		var email []string
		if json.Unmarshal(item["email"], &email) != nil || len(email) == 0 || email[0] != p.f.Email {
			return checkError("download record has wrong fixture identity")
		}
		if _, ok := item["password"]; ok {
			return checkError("download includes an unselected password")
		}
		count++
	}
	if scanner.Err() != nil {
		return checkError("download record stream could not be read")
	}
	return need(count == 5, "download row count did not match the bounded fixture request")
}

func main() {
	contextPath := flag.String("context", "", "private broker context JSON")
	fixturePath := flag.String("fixtures", "", "synthetic dataset fixture JSON")
	outputPath := flag.String("output", "", "sanitized JSONL report")
	section := flag.String("section", "read", "read, jobs, providers, monitors, contracts, or all")
	execute := flag.Bool("execute", false, "execute against the explicitly approved local API")
	allowProviders := flag.Bool("allow-providers", false, "allow the task-owned provider and notification fixtures")
	allowMonitors := flag.Bool("allow-monitors", false, "allow run-owned monitors and approved notification fixture")
	providerPath := flag.String("provider-fixtures", "", "approved synthetic provider inputs and sink settings")
	flag.Parse()
	if !*execute || *contextPath == "" || *fixturePath == "" || *outputPath == "" {
		fmt.Fprintln(os.Stderr, "requires --execute, --context, --fixtures, and --output")
		os.Exit(2)
	}
	f, err := loadFixtures(*contextPath, *fixturePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *providerPath != "" {
		approvedKey, approvedBase := f.APIKey, f.BaseURL
		raw, e := os.ReadFile(*providerPath)
		if e != nil {
			panic("could not read provider fixtures")
		}
		if json.Unmarshal(raw, &f) != nil {
			panic("invalid provider fixtures")
		}
		var shared struct {
			Domain       string `json:"domain"`
			Notification struct {
				URL    string `json:"webhook_url"`
				Secret string `json:"webhook_secret"`
			} `json:"notification"`
			Providers struct {
				IP         string `json:"ip"`
				SteamID    string `json:"steam_id"`
				XboxID     string `json:"xbl_id"`
				DiscordID  string `json:"discord_id"`
				RobloxID   string `json:"roblox_id"`
				Enrichment struct {
					Input   string   `json:"input"`
					Type    string   `json:"type"`
					Modules []string `json:"modules"`
				} `json:"enrichment"`
				Expected map[string]map[string]interface{} `json:"expected"`
			} `json:"providers"`
		}
		if json.Unmarshal(raw, &shared) != nil {
			panic("invalid provider fixtures")
		}
		if shared.Domain != "" {
			f.DomainAlias = shared.Domain
		}
		if shared.Notification.URL != "" {
			f.WebhookURL = shared.Notification.URL
		}
		if shared.Notification.Secret != "" {
			f.WebhookSecret = shared.Notification.Secret
		}
		if shared.Providers.IP != "" {
			f.IP = shared.Providers.IP
		}
		if shared.Providers.SteamID != "" {
			f.SteamID = shared.Providers.SteamID
		}
		if shared.Providers.XboxID != "" {
			f.XboxID = shared.Providers.XboxID
		}
		if shared.Providers.DiscordID != "" {
			f.DiscordID = shared.Providers.DiscordID
		}
		if shared.Providers.RobloxID != "" {
			f.RobloxUserID = shared.Providers.RobloxID
		}
		if shared.Providers.Enrichment.Input != "" {
			f.EnrichmentInput = shared.Providers.Enrichment.Input
			f.EnrichmentType = shared.Providers.Enrichment.Type
			f.EnrichmentModules = shared.Providers.Enrichment.Modules
		}
		f.ProviderExpected = shared.Providers.Expected
		f.APIKey, f.BaseURL = approvedKey, approvedBase
	}
	target, err := url.Parse(f.BaseURL)
	if err != nil || target.String() != "http://127.0.0.1:19800/api" {
		fmt.Fprintln(os.Stderr, "probe target must be the approved disposable API at 127.0.0.1:19800")
		os.Exit(2)
	}
	transport := &recorder{target: target, transport: &http.Transport{Proxy: nil}}
	client, err := oathnet.NewClient(f.APIKey, oathnet.WithBaseURL(f.BaseURL), oathnet.WithHTTPClient(&http.Client{Transport: transport, Timeout: 30 * time.Second}))
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not initialize probe client")
		os.Exit(2)
	}
	output, err := os.OpenFile(*outputPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not open probe report")
		os.Exit(2)
	}
	p := &probe{f: f, client: client, transport: transport, output: json.NewEncoder(output), allowProviders: *allowProviders, allowMonitors: *allowMonitors}
	switch *section {
	case "read":
		p.searches()
		p.victims()
	case "jobs":
		p.jobs()
	case "providers":
		p.providers()
		p.ai()
	case "monitors":
		p.monitors()
	case "contracts":
		p.contracts()
	case "all":
		p.searches()
		p.victims()
		p.jobs()
		p.providers()
		p.monitors()
	default:
		fmt.Fprintln(os.Stderr, "requested probe section is not implemented yet")
		os.Exit(2)
	}
	_ = output.Close()
	counts := map[string]int{}
	for _, r := range p.rows {
		counts[r.Status]++
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"operations": len(p.rows), "counts": counts, "report": *outputPath}); err != nil {
		panic(err)
	}
	if counts["failed"] > 0 || counts["blocked-fixture"] > 0 {
		os.Exit(1)
	}
}

func loadFixtures(contextPath, fixturePath string) (fixtures, error) {
	var f fixtures
	raw, err := os.ReadFile(contextPath)
	if err != nil {
		return f, errors.New("could not read private broker context")
	}
	var broker struct {
		Auth struct {
			APIKey string `json:"api_key"`
		} `json:"auth"`
		BaseURLs struct {
			Django string `json:"django"`
		} `json:"base_urls"`
		Safety struct {
			IsProduction    bool `json:"is_production"`
			SafeDevDatabase bool `json:"safe_dev_database"`
		} `json:"safety"`
		Fixtures json.RawMessage `json:"fixtures"`
	}
	if json.Unmarshal(raw, &broker) != nil {
		return f, errors.New("invalid broker context")
	}
	if broker.Safety.IsProduction || !broker.Safety.SafeDevDatabase {
		return f, errors.New("broker context does not attest an isolated development database")
	}
	if json.Unmarshal(broker.Fixtures, &f) != nil {
		return f, errors.New("invalid broker fixture values")
	}
	f.APIKey = broker.Auth.APIKey
	f.BaseURL = strings.TrimRight(broker.BaseURLs.Django, "/")
	var shared struct {
		Supplemental struct {
			Query  string `json:"query"`
			Email  string `json:"email"`
			DBName string `json:"dbname"`
		} `json:"supplemental"`
		Query   string `json:"query"`
		Email   string `json:"email"`
		Victims []struct {
			LogID       string `json:"log_id"`
			FileID      string `json:"file_id"`
			NotesFileID string `json:"notes_file_id"`
		} `json:"victims"`
	}
	raw, err = os.ReadFile(fixturePath)
	if err != nil || json.Unmarshal(raw, &shared) != nil {
		return f, errors.New("could not read synthetic dataset fixtures")
	}
	f.AutocompleteQuery = shared.Supplemental.Query
	f.AutocompleteDBName = "readiness"
	if shared.Query != "" {
		f.Query = shared.Query
	}
	if strings.Contains(shared.Email, "@") {
		f.Email = shared.Email
		f.Domain = strings.SplitN(shared.Email, "@", 2)[1]
	}
	f.FileExpression = "needle"
	f.CookieDomain = f.Domain
	if len(shared.Victims) > 0 {
		f.LogID = shared.Victims[0].LogID
		f.FileID = shared.Victims[0].NotesFileID
		if f.FileID == "" {
			f.FileID = shared.Victims[0].FileID
		}
	}
	if f.AutocompleteQuery == "" {
		f.AutocompleteQuery = f.Email
	}
	if f.APIKey == "" || f.Query == "" || f.Domain == "" {
		return f, errors.New("broker or dataset fixtures are incomplete")
	}
	return f, nil
}
