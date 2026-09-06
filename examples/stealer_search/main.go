// Find credential records that can lead to a captured-device record in Victims.
package main

import (
	"fmt"
	"github.com/oathnet/oathnet-go/examples/internal/exampleclient"
	"github.com/oathnet/oathnet-go/pkg/oathnet"
	"log"
)

func main() {
	client := exampleclient.New()
	response, err := client.Stealer.Search(exampleclient.Query(), &oathnet.StealerSearchOptions{HasLogID: true, PageSize: 5})
	if err != nil {
		log.Fatal(err)
	}
	if !response.Success || response.Data == nil {
		log.Fatal("search returned no successful data")
	}
	fmt.Printf("Received %d credential records\n", len(response.Data.Items))
	for _, record := range response.Data.Items {
		if record.LogID != "" {
			fmt.Printf("Linked victim log_id: %s\n", record.LogID)
		}
	}
}
