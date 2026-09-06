package oathnet

import "net/url"

// ListDestinations lists the account's verified alert destinations. Destination
// responses expose a hostname hint, never the complete URL or signing secret.
func (s *ScannerService) ListDestinations() ([]ScannerDestination, error) {
	var resp []ScannerDestination
	err := s.client.get("/scanners/destinations", nil, &resp)
	return resp, err
}

// CreateDestination sends a real verification notification and saves a
// destination only if delivery succeeds. For generic webhooks, supply the
// signing secret already configured on the receiver.
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
	NotificationType    string `json:"notification_type"` // webhook or discord
	WebhookURL          string `json:"webhook_url"`
	WebhookSecret       string `json:"webhook_secret,omitempty"`
	WebhookSecurityMode string `json:"webhook_security_mode,omitempty"` // signed_json or signed_encrypted
}

type ScannerDestination struct {
	UID                 string `json:"uid"`
	Name                string `json:"name"`
	NotificationType    string `json:"notification_type"`
	TargetHint          string `json:"target_hint"`
	WebhookSecurityMode string `json:"webhook_security_mode"`
	Verified            bool   `json:"verified"`
	VerifiedAt          string `json:"verified_at"`
	CreatedAt           string `json:"created_at"`
	UpdatedAt           string `json:"updated_at"`
}
