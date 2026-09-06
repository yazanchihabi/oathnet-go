// Inspect a failed call without automatically retrying quota-spending work.
package main

import (
	"fmt"
	"github.com/oathnet/oathnet-go/examples/internal/exampleclient"
	"github.com/oathnet/oathnet-go/pkg/oathnet"
	"log"
)

func main() {
	response, err := exampleclient.New().Breach.Search(exampleclient.Query(), nil)
	if err != nil {
		switch apiError := err.(type) {
		case *oathnet.RateLimitError:
			log.Printf("Rate limited. Retry-After: %s", apiError.RetryAfter)
		case *oathnet.AuthenticationError:
			log.Print("Check the configured API key")
		case *oathnet.ValidationError:
			log.Printf("Request rejected with HTTP %d: %s", apiError.StatusCode, apiError.Message)
		default:
			log.Print(err)
		}
		return
	}
	if !response.Success || response.Data == nil {
		log.Fatal("search returned no successful data")
	}
	fmt.Printf("Received %d records\n", len(response.Data.Items))
}
