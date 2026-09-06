package oathnet

import (
	"net"
	"net/url"
	"os"
	"testing"
)

// getAPIKey returns the API key from environment variable.
func getAPIKey(t *testing.T) string {
	t.Helper()
	if os.Getenv("OATHNET_LIVE_TESTS") != "1" {
		t.Skip("live tests require OATHNET_LIVE_TESTS=1 and an isolated local API")
	}
	apiKey := os.Getenv("OATHNET_API_KEY")
	if apiKey == "" {
		t.Skip("OATHNET_API_KEY environment variable required for integration tests")
	}
	return apiKey
}

// createTestClient creates a client for testing.
func createTestClient(t *testing.T) *Client {
	t.Helper()
	apiKey := getAPIKey(t)
	baseURL := os.Getenv("OATHNET_BASE_URL")
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed == nil || parsed.Scheme != "http" || parsed.Port() == "" || parsed.User != nil {
		t.Fatal("live tests require an explicit http://127.0.0.1:PORT/api isolated target")
	}
	ip := net.ParseIP(parsed.Hostname())
	if ip == nil || !ip.IsLoopback() {
		t.Fatal("live tests require a loopback API target")
	}
	client, err := NewClient(apiKey, WithBaseURL(baseURL))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	return client
}

// Test data constants
const (
	TestDiscordID            = "300760994454437890"
	TestDiscordIDWithHistory = "1375046349392974005"
	TestDiscordIDWithRoblox  = "1205957884584656927"
	TestSteamID              = "1100001586a2b38"
	TestXboxGamertag         = "ethan"
	TestRobloxUsername       = "chris"
	TestHoleheEmail          = "ethan_lewis_196@hotmail.co.uk"
	TestIP                   = "174.235.65.156"
	TestDomain               = "limabean.co.za"
	TestBreachQuery          = "winterfox"
	TestStealerQuery         = "gmail.com"
	TestVictimsQuery         = "gmail"
)
