// Run one V2 breach search. No search session is needed for a single lookup.
package main

import (
	"fmt"
	"github.com/oathnet/oathnet-go/examples/internal/exampleclient"
	"github.com/oathnet/oathnet-go/pkg/oathnet"
	"log"
)

func main() {
	client := exampleclient.New()
	response, err := client.Breach.Search(exampleclient.Query(), &oathnet.BreachV2SearchOptions{
		PageSize: 25,
		Fields:   []string{"email", "dbname"},
	})
	if err != nil {
		log.Fatal(err)
	}
	if !response.Success || response.Data == nil {
		log.Fatal("search returned no successful data")
	}
	fmt.Printf("Received %d records on this page\n", len(response.Data.Items))
	for _, item := range response.Data.Items {
		// Raw preserves arrays and other original source value shapes.
		fmt.Printf("email=%s source=%s\n", item.Raw["email"], item.Raw["dbname"])
	}
}
