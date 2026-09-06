package main

import (
	"encoding/json"
	"errors"
	"github.com/oathnet/oathnet-go/pkg/oathnet"
)

func expectValidation(err error) error {
	var validation *oathnet.ValidationError
	if !errors.As(err, &validation) || validation.StatusCode != 400 || validation.Message == "" || validation.Response == nil {
		return checkError("expected structured HTTP400 validation error")
	}
	return nil
}

func expectNotFound(err error) error {
	var missing *oathnet.NotFoundError
	if !errors.As(err, &missing) || missing.StatusCode != 404 || missing.Message == "" {
		return checkError("expected HTTP404 not-found error")
	}
	return nil
}

func (p *probe) contracts() {
	p.runCase("searchBreachV2", "projection-and-next-page", func() error {
		opts := &oathnet.BreachV2SearchOptions{PageSize: 1, Fields: []string{"email", "dbname"}}
		first, e := p.client.Breach.SearchGet(p.f.Email, opts)
		if e != nil {
			return e
		}
		if first.Data == nil || len(first.Data.Items) != 1 || first.Data.NextCursor == "" {
			return checkError("first projected breach page lacks an item and cursor")
		}
		item := first.Data.Items[0]
		var email []string
		if json.Unmarshal(item.Raw["email"], &email) != nil || len(email) == 0 || email[0] != p.f.Email {
			return checkError("array-valued breach identity was not preserved")
		}
		if _, ok := item.Raw["password"]; ok {
			return checkError("unselected password included in projection")
		}
		opts.Cursor = first.Data.NextCursor
		second, e := p.client.Breach.SearchGet(p.f.Email, opts)
		if e != nil {
			return e
		}
		return need(second.Success && second.Data != nil && len(second.Data.Items) == 1 && second.Data.Items[0].ID != "" && second.Data.Items[0].ID != item.ID, "next breach cursor did not advance")
	})
	p.runCase("searchStealerV2", "next-page", func() error {
		opts := &oathnet.StealerSearchOptions{PageSize: 1}
		first, e := p.client.Stealer.SearchGet(p.f.Query, opts)
		if e != nil {
			return e
		}
		if first.Data == nil || len(first.Data.Items) != 1 || first.Data.NextCursor == "" {
			return checkError("first credential page lacks an item and cursor")
		}
		opts.Cursor = first.Data.NextCursor
		second, e := p.client.Stealer.SearchGet(p.f.Query, opts)
		if e != nil {
			return e
		}
		return need(second.Success && second.Data != nil && len(second.Data.Items) == 1 && second.Data.Items[0].ID != "" && second.Data.Items[0].ID != first.Data.Items[0].ID, "next credential cursor did not advance")
	})
	p.runCase("searchBreachV2", "invalid-cursor-first-page-fallback", func() error {
		opts := &oathnet.BreachV2SearchOptions{PageSize: 1, Fields: []string{"email", "dbname"}}
		first, e := p.client.Breach.SearchGet(p.f.Email, opts)
		if e != nil {
			return e
		}
		opts.Cursor = "not-a-valid-cursor"
		repeated, e := p.client.Breach.SearchGet(p.f.Email, opts)
		if e != nil {
			return e
		}
		return need(first.Data != nil && repeated.Data != nil && len(first.Data.Items) == 1 && len(repeated.Data.Items) == 1 && first.Data.Items[0].ID == repeated.Data.Items[0].ID && repeated.Data.NextCursor != "" && repeated.Data.NextCursor != opts.Cursor, "malformed breach cursor did not match documented first-page fallback")
	})
	p.runCase("searchStealerV2", "invalid-cursor-first-page-fallback", func() error {
		opts := &oathnet.StealerSearchOptions{PageSize: 1}
		first, e := p.client.Stealer.SearchGet(p.f.Query, opts)
		if e != nil {
			return e
		}
		opts.Cursor = "not-a-valid-cursor"
		repeated, e := p.client.Stealer.SearchGet(p.f.Query, opts)
		if e != nil {
			return e
		}
		return need(first.Data != nil && repeated.Data != nil && len(first.Data.Items) == 1 && len(repeated.Data.Items) == 1 && first.Data.Items[0].ID == repeated.Data.Items[0].ID && repeated.Data.NextCursor != "" && repeated.Data.NextCursor != opts.Cursor, "malformed credential cursor did not match documented first-page fallback")
	})
	p.runCase("searchVictimsV2", "invalid-cursor-first-page-fallback", func() error {
		opts := &oathnet.VictimsSearchOptions{PageSize: 1}
		first, e := p.client.Victims.SearchGet(p.f.Query, opts)
		if e != nil {
			return e
		}
		opts.Cursor = "not-a-valid-cursor"
		repeated, e := p.client.Victims.SearchGet(p.f.Query, opts)
		if e != nil {
			return e
		}
		return need(first.Data != nil && repeated.Data != nil && len(first.Data.Items) == 1 && len(repeated.Data.Items) == 1 && first.Data.Items[0].LogID == repeated.Data.Items[0].LogID && repeated.Data.NextCursor != "" && repeated.Data.NextCursor != opts.Cursor, "malformed victim cursor did not match documented first-page fallback")
	})
	p.runCase("searchBreachV2Post", "invalid-filter", func() error {
		_, e := p.client.Breach.SearchPost(oathnet.V2SearchPostBody{"filter": map[string]interface{}{"field": "email", "operator": "not-an-operator", "value": "fixture"}}, nil)
		return expectValidation(e)
	})
	p.runCase("searchFilesMetadataV2", "explicit-zero-range", func() error {
		zero := 0
		r, e := p.client.Victims.SearchFilesMetadata(&oathnet.FileMetadataSearchOptions{LogID: p.f.LogID, SizeMaxValue: &zero})
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && len(r.Data.Items) == 0, "zero size limit returned a nonempty fixture file")
	})
	p.runCase("searchVictimPropertiesV2Post", "false-and-zero", func() error {
		inactive := false
		zero := float64(0)
		r, e := p.client.Victims.SearchVictimPropertiesPost(&oathnet.V2VictimPropertiesSearchRequest{LogID: p.f.LogID, Active: &inactive, ConfidenceMin: &zero})
		if e != nil {
			return e
		}
		if !r.Success || r.Data == nil || len(r.Data.Items) == 0 {
			return checkError("known inactive property fixture missing")
		}
		for _, item := range r.Data.Items {
			if item.ActiveValue == nil || *item.ActiveValue {
				return checkError("active property matched explicit false")
			}
		}
		return nil
	})
	p.runCase("getFileSearchV2", "unknown-job", func() error {
		_, e := p.client.FileSearch.GetStatus("00000000-0000-4000-8000-000000000000")
		return expectNotFound(e)
	})
	p.runCase("getExportV2", "unknown-job", func() error {
		_, e := p.client.Exports.GetStatus("00000000-0000-4000-8000-000000000000")
		return expectNotFound(e)
	})
	p.runCase("getBulkSearchV2", "unknown-job", func() error {
		_, e := p.client.Bulk.GetStatus("00000000-0000-4000-8000-000000000000")
		return expectNotFound(e)
	})
	p.runCase("createFileSearchV2", "missing-log-ids", func() error {
		_, e := p.client.FileSearch.Create("fixture", &oathnet.FileSearchCreateOptions{LogIDs: []string{}})
		return expectValidation(e)
	})
	p.runCase("createExportV2", "missing-service", func() error { _, e := p.client.Exports.Create("invalid", nil); return expectValidation(e) })
	p.runCase("createBulkSearchV2", "empty-terms", func() error { _, e := p.client.Bulk.Create([]string{}, "breach", nil); return expectValidation(e) })
	p.runCase("getVictimFileV2", "unknown-file", func() error {
		_, e := p.client.Victims.GetFileResponse(p.f.LogID, "000000000000000000000000")
		return expectNotFound(e)
	})
	p.runCase("enrichIdentity", "unknown-module", func() error {
		_, e := p.client.OSINT.EnrichIdentity(oathnet.EnrichmentRequest{Input: "ReadinessFixture", Type: "username", Modules: []string{"not-a-module"}})
		return expectValidation(e)
	})
	p.runCase("enrichIdentityPost", "invalid-type", func() error {
		_, e := p.client.OSINT.EnrichIdentityPost(oathnet.EnrichmentRequest{Input: "ReadinessFixture", Type: "invalid"})
		return expectValidation(e)
	})
}
