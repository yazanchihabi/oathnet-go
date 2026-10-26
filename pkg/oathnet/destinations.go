package oathnet

import "net/url"

// ListDestinations lists the account's verified alert destinations. Destination
// responses include saved email addresses but never complete webhook URLs or secrets.
func (s *ScannerService) ListDestinations() ([]ScannerDestination, error) {
	var resp []ScannerDestination
	err := s.client.get("/scanners/destinations", nil, &resp)
	return resp, err
}

// CreateDestination sends a real verification notification and saves a
// destination only if delivery succeeds. For generic webhooks, supply the
// signing secret already configured on the receiver.
// Email delivery acceptance does not prove mailbox ownership.
func (s *ScannerService) CreateDestination(req ScannerDestinationCreateRequest) (*ScannerDestination, error) {
	var resp ScannerDestination
	err := s.client.post("/scanners/destinations", req, &resp)
	return &resp, err
}

// DeleteDestination deletes an unused destination. A destination referenced by
// any monitor, including a paused monitor, returns HTTP 409.
func (s *ScannerService) DeleteDestination(destinationUID string) error {
	return s.client.delete("/scanners/destinations/"+url.PathEscape(destinationUID), nil)
}

type ScannerDestinationCreateRequest struct {
	Name                string `json:"name"`
	NotificationType    string `json:"notification_type"` // email, webhook, or discord
	RecipientEmail      string `json:"recipient_email,omitempty"`
	WebhookURL          string `json:"webhook_url,omitempty"`
	WebhookSecret       string `json:"webhook_secret,omitempty"`
	WebhookSecurityMode string `json:"webhook_security_mode,omitempty"` // signed_json or signed_encrypted
}

type ScannerDestination struct {
	UID              string `json:"uid"`
	Name             string `json:"name"`
	NotificationType string `json:"notification_type"`
	TargetHint       string `json:"target_hint"`
	RecipientEmail   string `json:"recipient_email,omitempty"`
	// WebhookSecurityMode is empty for email destinations, whose JSON mode is null.
	WebhookSecurityMode string `json:"webhook_security_mode"`
	Verified            bool   `json:"verified"`
	VerifiedAt          string `json:"verified_at"`
	CreatedAt           string `json:"created_at"`
	UpdatedAt           string `json:"updated_at"`
}
