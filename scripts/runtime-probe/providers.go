package main

import (
	"encoding/json"
	"github.com/oathnet/oathnet-go/pkg/oathnet"
	"reflect"
	"strings"
)

func (p *probe) checkProviderFields(operation string) error {
	expected := p.f.ProviderExpected[operation]
	if len(expected) == 0 {
		return nil
	}
	var response map[string]interface{}
	if json.Unmarshal(p.transport.body, &response) != nil {
		return checkError("provider response is not a JSON object")
	}
	for path, want := range expected {
		value := response["data"]
		for _, part := range strings.Split(path, ".") {
			object, ok := value.(map[string]interface{})
			if !ok {
				return checkError("expected provider data structure missing")
			}
			value = object[part]
		}
		if !reflect.DeepEqual(value, want) {
			return checkError("provider data does not match synthetic expected identity")
		}
	}
	return nil
}

func (p *probe) domain() string {
	if p.f.DomainAlias != "" {
		return p.f.DomainAlias
	}
	return p.f.Domain
}

func (p *probe) providers() {
	opts := oathnet.OSINTOptions{SearchID: p.sessionID}
	p.run("ipInfo", func() error {
		r, e := p.client.OSINT.IPInfo(p.f.IP, opts)
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && r.Data.Query == p.f.IP && r.Data.Country != "" && r.Data.ProviderSummary != nil && r.Data.ProviderSummary.Completed > 0, "IP fixture identity or provider completion missing")
	})
	p.run("steamLookup", func() error {
		r, e := p.client.OSINT.Steam(p.f.SteamID, opts)
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && r.Data.ID == p.f.SteamID && r.Data.Username != "", "Steam fixture identity missing")
	})
	p.run("xboxLookup", func() error {
		r, e := p.client.OSINT.Xbox(p.f.XboxID, opts)
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && r.Data.ID == p.f.XboxID && r.Data.Username != "", "Xbox fixture identity missing")
	})
	p.run("discordUserinfo", func() error {
		r, e := p.client.OSINT.DiscordUserinfo(p.f.DiscordID, opts)
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && r.Data.ID == p.f.DiscordID && r.Data.Username != "", "Discord fixture identity missing")
	})
	p.run("discordUsernameHistory", func() error {
		r, e := p.client.OSINT.DiscordUsernameHistory(p.f.DiscordID, opts)
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && len(r.Data.History) > 0 && len(r.Data.History[0].Name) > 0, "Discord history fixture missing")
	})
	p.run("robloxUserinfo", func() error {
		r, e := p.client.OSINT.RobloxUserinfo(oathnet.RobloxUserinfoOptions{UserID: p.f.RobloxUserID, SearchID: p.sessionID})
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && (r.Data.UserID == p.f.RobloxUserID || r.Data.UserIDAlt == p.f.RobloxUserID) && (r.Data.Username != "" || r.Data.CurrentUsername != ""), "Roblox fixture identity missing")
	})
	p.run("holehe", func() error {
		r, e := p.client.OSINT.Holehe(p.f.Email, opts)
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && r.Data.Email == p.f.Email && len(r.Data.Domains) > 0 && r.Data.ProviderSummary != nil && r.Data.ProviderSummary.Completed > 0, "Holehe adapter fixture identity or completed checks missing")
	})
	p.run("ghunt", func() error {
		r, e := p.client.OSINT.GHunt(p.f.Email, opts)
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && r.Data.Data != nil && r.Data.Data.Profile != nil && r.Data.Data.Profile.GaiaID != "", "GHunt adapter fixture profile missing")
	})
	p.run("extractSubdomain", func() error {
		alive := false
		r, e := p.client.OSINT.ExtractSubdomain(p.domain(), &alive, opts)
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && len(r.Data.Subdomains) > 0, "legacy subdomain fixture missing")
	})
	p.run("minecraftHistory", func() error {
		r, e := p.client.OSINT.MinecraftHistory("ReadinessFixture", opts)
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && r.Data.Disabled && r.Data.Skipped && len(r.Data.History) == 0, "disabled Minecraft compatibility markers missing")
	})
	request := oathnet.EnrichmentRequest{Input: p.f.EnrichmentInput, Type: p.f.EnrichmentType, Modules: p.f.EnrichmentModules, SearchID: p.sessionID, Timeout: "10s"}
	validate := func(r *oathnet.EnrichmentResponse, e error) error {
		if e != nil {
			return e
		}
		if request.Input == "" || len(request.Modules) == 0 {
			return fixtureError("exact enrichment fixture input and modules required")
		}
		if r == nil || !r.Success || r.Data == nil || r.Data.Input != request.Input || r.Data.Found == 0 || len(r.Data.Results) != len(request.Modules) {
			return checkError("enrichment fixture identity or selected results missing")
		}
		for _, item := range r.Data.Results {
			if item.Status != "found" || item.Module == "" || len(item.Metadata) == 0 {
				return checkError("enrichment module did not produce a typed profile")
			}
		}
		return nil
	}
	p.run("enrichIdentity", func() error {
		if request.Input == "" || len(request.Modules) == 0 {
			return fixtureError("exact enrichment fixture input and modules required")
		}
		return validate(p.client.OSINT.EnrichIdentity(request))
	})
	p.run("enrichIdentityPost", func() error {
		if request.Input == "" || len(request.Modules) == 0 {
			return fixtureError("exact enrichment fixture input and modules required")
		}
		return validate(p.client.OSINT.EnrichIdentityPost(request))
	})
}
