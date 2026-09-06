// Package exampleclient shares configuration for the runnable SDK examples.
package exampleclient

import (
	"log"
	"os"
	"time"

	"github.com/oathnet/oathnet-go/pkg/oathnet"
)

// New reads the API key from the environment. OATHNET_BASE_URL is optional and
// lets the same example run against an explicitly configured development API.
func New() *oathnet.Client {
	options := []oathnet.ClientOption{oathnet.WithTimeout(30 * time.Second)}
	if baseURL := os.Getenv("OATHNET_BASE_URL"); baseURL != "" {
		options = append(options, oathnet.WithBaseURL(baseURL))
	}
	client, err := oathnet.NewClient(os.Getenv("OATHNET_API_KEY"), options...)
	if err != nil {
		log.Fatal(err)
	}
	return client
}

// Query returns the requested example input or a clearly synthetic default.
func Query() string {
	if query := os.Getenv("OATHNET_QUERY"); query != "" {
		return query
	}
	return "user@example.com"
}

// Required reads an input that must come from an earlier API response.
func Required(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("set %s to a value returned by the API", name)
	}
	return value
}
