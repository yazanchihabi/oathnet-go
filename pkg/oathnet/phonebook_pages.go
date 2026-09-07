package oathnet

import (
	"fmt"
	"net/url"
	"strconv"
)

// PhonebookPageOptions applies record source/date filters and bounded pagination.
// Keep filters and SearchID unchanged when following a Cursor.
type PhonebookPageOptions struct {
	Source      string
	PwnedFrom   string
	PwnedTo     string
	IndexedFrom string
	IndexedTo   string
	PageSize    int
	Cursor      string
	SearchID    string
}

type V2PhonebookPageData struct {
	Domain           string                        `json:"domain"`
	Kind             string                        `json:"kind"`
	Source           string                        `json:"source"`
	Emails           []V2PhonebookEmailInsight     `json:"emails,omitempty"`
	SubdomainResults []V2PhonebookSubdomainInsight `json:"subdomain_results,omitempty"`
	ReturnedCount    int                           `json:"returned_count"`
	PageSize         int                           `json:"page_size"`
	HasMore          bool                          `json:"has_more"`
	NextCursor       string                        `json:"next_cursor,omitempty"`
	VisibleLimit     int                           `json:"visible_limit"`
	Limited          bool                          `json:"limited"`
}

type V2PhonebookPageResponse struct {
	Success bool                   `json:"success"`
	Message string                 `json:"message,omitempty"`
	Data    *V2PhonebookPageData   `json:"data,omitempty"`
	Meta    map[string]interface{} `json:"_meta,omitempty"`
}

type V2PhonebookInitialPagesData struct {
	V2PhonebookData
	Pages map[string]V2PhonebookPageData `json:"pages"`
}

type V2PhonebookInitialPagesResponse struct {
	Meta    map[string]interface{}       `json:"_meta,omitempty"`
	Success bool                         `json:"success"`
	Message string                       `json:"message,omitempty"`
	Data    *V2PhonebookInitialPagesData `json:"data,omitempty"`
}

func phonebookPageParams(domain string, opts *PhonebookPageOptions) url.Values {
	p := url.Values{"domain": {domain}}
	if opts == nil {
		return p
	}
	for key, value := range map[string]string{"source": opts.Source, "pwned_from": opts.PwnedFrom, "pwned_to": opts.PwnedTo, "indexed_from": opts.IndexedFrom, "indexed_to": opts.IndexedTo, "cursor": opts.Cursor, "search_id": opts.SearchID} {
		if value != "" {
			p.Set(key, value)
		}
	}
	if opts.PageSize != 0 {
		p.Set("page_size", strconv.Itoa(opts.PageSize))
	}
	return p
}

func validatePhonebookPage(page *V2PhonebookPageData, kind, source string) error {
	if source == "" {
		source = "all"
	}
	if page == nil {
		return fmt.Errorf("missing Phonebook page")
	}
	count := len(page.Emails)
	if kind == "subdomains" {
		count = len(page.SubdomainResults)
	}
	if page.Domain == "" || page.Kind != kind || page.Source != source || page.ReturnedCount != count || page.PageSize < 1 || page.PageSize > 100 || count > page.PageSize || page.HasMore != (page.NextCursor != "") || page.VisibleLimit < -1 || page.Limited != (page.VisibleLimit >= 0) {
		return fmt.Errorf("inconsistent Phonebook page response")
	}
	return nil
}

func (s *StealerV2Service) PhonebookPage(kind, domain string, opts *PhonebookPageOptions) (*V2PhonebookPageResponse, error) {
	if kind != "emails" && kind != "subdomains" {
		return nil, fmt.Errorf("unknown Phonebook result type")
	}
	params := phonebookPageParams(domain, opts)
	var response V2PhonebookPageResponse
	err := s.client.get(phonebookV2Path+"/"+kind, params, &response)
	if err == nil && response.Success {
		err = validatePhonebookPage(response.Data, kind, params.Get("source"))
	}
	return &response, err
}

func (s *StealerV2Service) GetPhonebookEmailsV2(domain string, opts *PhonebookPageOptions) (*V2PhonebookPageResponse, error) {
	return s.PhonebookPage("emails", domain, opts)
}

func (s *StealerV2Service) GetPhonebookSubdomainsV2(domain string, opts *PhonebookPageOptions) (*V2PhonebookPageResponse, error) {
	return s.PhonebookPage("subdomains", domain, opts)
}

// PhonebookInitialPages retrieves both first pages for one lookup.
func (s *StealerV2Service) PhonebookInitialPages(domain string, opts *PhonebookPageOptions) (*V2PhonebookInitialPagesResponse, error) {
	params := phonebookPageParams(domain, opts)
	params.Set("paged", "true")
	var response V2PhonebookInitialPagesResponse
	err := s.client.get(phonebookV2Path, params, &response)
	if err != nil || !response.Success {
		return &response, err
	}
	if response.Data == nil {
		return nil, fmt.Errorf("missing Phonebook initial pages")
	}
	for _, kind := range []string{"emails", "subdomains"} {
		page := response.Data.Pages[kind]
		source := params.Get("source")
		if kind == "subdomains" {
			source = "all"
		}
		if err = validatePhonebookPage(&page, kind, source); err != nil {
			return nil, err
		}
	}
	return &response, nil
}
