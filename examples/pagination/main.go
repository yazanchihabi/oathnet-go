// Read at most three pages while preserving the original search settings.
package main

import (
	"context"
	"fmt"
	"github.com/oathnet/oathnet-go/examples/internal/exampleclient"
	"github.com/oathnet/oathnet-go/pkg/oathnet"
	"log"
	"time"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	client := exampleclient.New().WithContext(ctx)
	options := &oathnet.BreachV2SearchOptions{PageSize: 25, Fields: []string{"email", "dbname"}}
	query := exampleclient.Query()
	for page := 1; page <= 3; page++ {
		options.Page = page
		response, err := client.Breach.Search(query, options)
		if err != nil {
			log.Fatal(err)
		}
		if !response.Success || response.Data == nil {
			log.Fatal("search returned no successful data")
		}
		fmt.Printf("Page %d: %d records\n", page, len(response.Data.Items))
		if response.Data.Meta == nil {
			break
		}
		fmt.Printf("Accessible pages: %d; results: %d\n", response.Data.Meta.TotalPages, response.Data.Meta.TotalResults)
		if !response.Data.Meta.HasMore {
			break
		}
	}
}
