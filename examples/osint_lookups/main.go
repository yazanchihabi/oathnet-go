// Run one enrichment module. Set OATHNET_USERNAME to the public username.
package main

import (
	"fmt"
	"github.com/oathnet/oathnet-go/examples/internal/exampleclient"
	"github.com/oathnet/oathnet-go/pkg/oathnet"
	"log"
)

func main() {
	client := exampleclient.New()
	response, err := client.OSINT.EnrichIdentityPost(oathnet.EnrichmentRequest{
		Input:   exampleclient.Required("OATHNET_USERNAME"),
		Type:    "username",
		Modules: []string{"instagram"},
		Timeout: "15s",
	})
	if err != nil {
		log.Fatal(err)
	}
	if response.Data == nil {
		log.Fatal("enrichment returned no outcome data")
	}
	// HTTP 200 may contain no found profiles or an unavailable provider.
	fmt.Printf("Found %d of %d module outcomes\n", response.Data.Found, response.Data.Total)
	for _, result := range response.Data.Results {
		fmt.Printf("%s: %s\n", result.Module, result.Status)
	}
}
