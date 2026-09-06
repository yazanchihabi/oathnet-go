// Use a structured filter without changing the server's search semantics.
package main

import (
	"fmt"
	"github.com/oathnet/oathnet-go/examples/internal/exampleclient"
	"github.com/oathnet/oathnet-go/pkg/oathnet"
	"log"
)

func main() {
	client := exampleclient.New()
	response, err := client.Breach.Search("", &oathnet.BreachV2SearchOptions{
		Filter:   oathnet.StructuredFilter{"field": "email", "operator": "eq", "value": exampleclient.Query()},
		PageSize: 25,
		Fields:   []string{"email", "dbname"},
	})
	if err != nil {
		log.Fatal(err)
	}
	if !response.Success || response.Data == nil {
		log.Fatal("search returned no successful data")
	}
	fmt.Printf("Received %d matching records\n", len(response.Data.Items))
	if response.Data.Meta != nil {
		fmt.Printf("Total: %d, relation: %s\n", response.Data.Meta.Total, response.Data.Meta.TotalRelation)
	}
}
