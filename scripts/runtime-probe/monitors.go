package main

import (
	"github.com/oathnet/oathnet-go/pkg/oathnet"
	"time"
)

func (p *probe) monitors() {
	name := "go-readiness-" + time.Now().UTC().Format("20060102T150405.000000000")
	query := oathnet.ScannerQueryConfig{"q": p.f.Email}
	p.run("getScannerQuota", func() error {
		r, e := p.client.Scanners.GetQuota()
		if e != nil {
			return e
		}
		return need(r.MaxScanners > 0 && r.CanCreate && r.Remaining > 0, "monitor quota does not permit fixture")
	})
	p.run("listScannerDestinations", func() error {
		r, e := p.client.Scanners.ListDestinations()
		if e != nil {
			return e
		}
		return need(r != nil, "destination list decoded as null")
	})
	p.run("testDraftScannerDelivery", func() error {
		if p.f.WebhookURL == "" || p.f.WebhookSecret == "" {
			return fixtureError("approved notification fixture URL and secret required")
		}
		r, e := p.client.Scanners.TestDraftDelivery(oathnet.ScannerDraftTestRequest{Name: name, ScannerType: "breach", QueryConfig: query, NotificationType: "webhook", WebhookURL: p.f.WebhookURL, WebhookSecret: p.f.WebhookSecret, WebhookSecurityMode: "signed_json"})
		if e != nil {
			return e
		}
		return need(r.Success && r.StatusCode != nil && *r.StatusCode >= 200 && *r.StatusCode < 300 && r.Preview != nil && r.Preview.VerificationMethod != "", "draft notification did not confirm delivery and verification")
	})
	p.run("createScannerDestination", func() error {
		if p.f.WebhookURL == "" || p.f.WebhookSecret == "" {
			return fixtureError("approved notification fixture URL and secret required")
		}
		r, e := p.client.Scanners.CreateDestination(oathnet.ScannerDestinationCreateRequest{Name: name, NotificationType: "webhook", WebhookURL: p.f.WebhookURL, WebhookSecret: p.f.WebhookSecret, WebhookSecurityMode: "signed_json"})
		if e != nil {
			return e
		}
		p.destination = r.UID
		return need(p.destination != "" && r.Verified && r.TargetHint != "", "destination verification metadata missing")
	})
	p.run("createScanner", func() error {
		if p.destination == "" {
			return fixtureError("owned destination was not created")
		}
		r, e := p.client.Scanners.Create(oathnet.ScannerCreateRequest{Name: name, ScannerType: "breach", QueryConfig: query, DestinationUID: p.destination})
		if e != nil {
			return e
		}
		p.scanner = r.UID
		return need(p.scanner != "" && r.DestinationUID != nil && *r.DestinationUID == p.destination && r.Name == name, "created monitor did not retain destination or name")
	})
	p.run("listScanners", func() error {
		if e := p.requireScanner(); e != nil {
			return e
		}
		r, e := p.client.Scanners.List(&oathnet.ScannerListOptions{ScannerType: "breach"})
		if e != nil {
			return e
		}
		for _, s := range r {
			if s.UID == p.scanner {
				return nil
			}
		}
		return checkError("created monitor missing from list")
	})
	p.run("getScanner", func() error {
		if e := p.requireScanner(); e != nil {
			return e
		}
		r, e := p.client.Scanners.Get(p.scanner)
		if e != nil {
			return e
		}
		return need(r.UID == p.scanner && r.Name == name, "monitor detail identity mismatch")
	})
	p.run("updateScanner", func() error {
		if e := p.requireScanner(); e != nil {
			return e
		}
		zero := false
		r, e := p.client.Scanners.Update(p.scanner, oathnet.ScannerUpdateRequest{Name: name + "-updated", NotifyOnZeroResults: &zero})
		if e != nil {
			return e
		}
		return need(r.UID == p.scanner && r.Name == name+"-updated" && !r.NotifyOnZeroResults, "monitor update did not retain name or explicit false")
	})
	p.run("getScannerWebhookSecurity", func() error {
		if e := p.requireScanner(); e != nil {
			return e
		}
		r, e := p.client.Scanners.GetWebhookSecurity(p.scanner)
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && r.Data.ScannerUID == p.scanner && r.Data.SecretConfigured, "webhook verification metadata missing")
	})
	p.run("testScannerNotification", func() error {
		if e := p.requireScanner(); e != nil {
			return e
		}
		r, e := p.client.Scanners.TestNotification(p.scanner)
		if e != nil {
			return e
		}
		return need(r.Success && r.StatusCode != nil && *r.StatusCode >= 200 && *r.StatusCode < 300, "saved monitor delivery failed")
	})
	p.run("rotateScannerWebhookSecret", func() error {
		if e := p.requireScanner(); e != nil {
			return e
		}
		r, e := p.client.Scanners.RotateWebhookSecret(p.scanner)
		if e != nil {
			return e
		}
		return need(r.Success && r.Data != nil && r.Data.ScannerUID == p.scanner && r.Data.Secret != "" && r.Data.Secret != p.f.WebhookSecret, "rotation did not return a new task-owned secret")
	})
	p.run("pauseScanner", func() error {
		if e := p.requireScanner(); e != nil {
			return e
		}
		r, e := p.client.Scanners.Pause(p.scanner)
		if e != nil {
			return e
		}
		return need(r.UID == p.scanner && r.Status == "paused", "pause status mismatch")
	})
	p.run("resumeScanner", func() error {
		if e := p.requireScanner(); e != nil {
			return e
		}
		r, e := p.client.Scanners.Resume(p.scanner)
		if e != nil {
			return e
		}
		return need(r.UID == p.scanner && r.Status == "active", "resume status mismatch")
	})
	p.run("triggerScanner", func() error {
		if e := p.requireScanner(); e != nil {
			return e
		}
		r, e := p.client.Scanners.Trigger(p.scanner)
		if e != nil {
			return e
		}
		return need(r.ScannerUID == p.scanner, "trigger acknowledged a different monitor")
	})
	p.run("listScannerRuns", func() error {
		if e := p.requireScanner(); e != nil {
			return e
		}
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			r, e := p.client.Scanners.ListRuns(p.scanner, &oathnet.ScannerRunsOptions{Limit: 5})
			if e != nil {
				return e
			}
			for _, run := range r {
				if run.UID != "" {
					p.runID = run.UID
					return nil
				}
			}
			time.Sleep(time.Second)
		}
		return checkError("triggered monitor did not create a run before timeout")
	})
	p.run("getScannerRun", func() error {
		if e := p.requireScanner(); e != nil {
			return e
		}
		if p.runID == "" {
			return fixtureError("owned monitor run was not created")
		}
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			r, e := p.client.Scanners.GetRun(p.scanner, p.runID)
			if e != nil {
				return e
			}
			if r.UID != p.runID {
				return checkError("monitor run identity mismatch")
			}
			if r.Status == "completed" {
				return need(r.CompletedAt != nil && *r.CompletedAt != "" && (r.ErrorMessage == nil || *r.ErrorMessage == ""), "completed monitor run retained an error or lost completion time")
			}
			if r.Status == "failed" {
				return checkError("monitor run failed")
			}
			time.Sleep(time.Second)
		}
		return checkError("monitor run did not complete before timeout")
	})
	// Cleanup uses only UIDs returned by this invocation, even after a failed check.
	p.run("deleteScanner", func() error {
		if e := p.requireScanner(); e != nil {
			return e
		}
		e := p.client.Scanners.Delete(p.scanner)
		if e == nil {
			p.scanner = ""
		}
		return e
	})
	p.run("deleteScannerDestination", func() error {
		if p.destination == "" {
			return fixtureError("owned destination was not created")
		}
		e := p.client.Scanners.DeleteDestination(p.destination)
		if e == nil {
			p.destination = ""
		}
		return e
	})
}
