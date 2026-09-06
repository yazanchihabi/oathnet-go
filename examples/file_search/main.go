// Scan one selected victim's files. Set OATHNET_LOG_ID before running.
package main

import (
	"fmt"
	"github.com/oathnet/oathnet-go/examples/internal/exampleclient"
	"github.com/oathnet/oathnet-go/pkg/oathnet"
	"log"
	"time"
)

func main() {
	client := exampleclient.New()
	job, err := client.FileSearch.Create(exampleclient.Query(), &oathnet.FileSearchCreateOptions{
		LogIDs:         []string{exampleclient.Required("OATHNET_LOG_ID")},
		SearchMode:     "literal",
		IncludeMatches: true,
		MaxMatches:     25,
	})
	if err != nil {
		log.Fatal(err)
	}
	if !job.Success || job.Data == nil || job.Data.JobID == "" {
		log.Fatal("file search did not return a job ID")
	}
	result, err := client.FileSearch.WaitForCompletion(job.Data.JobID, time.Second, time.Minute)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Completed with %d returned matches\n", len(result.Data.Matches))
}
