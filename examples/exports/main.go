// Create one breach export and download it only after it completes.
package main

import (
	"fmt"
	"github.com/oathnet/oathnet-go/examples/internal/exampleclient"
	"github.com/oathnet/oathnet-go/pkg/oathnet"
	"log"
	"os"
	"time"
)

func main() {
	client := exampleclient.New()
	job, err := client.Exports.Create("breach", &oathnet.ExportCreateOptions{
		Service: "breach", Format: "jsonl", Limit: 100,
		Fields: []string{"email", "dbname"},
		Search: map[string]interface{}{"q": exampleclient.Query()},
	})
	if err != nil {
		log.Fatal(err)
	}
	if !job.Success || job.Data == nil || job.Data.JobID == "" {
		log.Fatal("export did not return a job ID")
	}
	if _, err := client.Exports.WaitForCompletion(job.Data.JobID, time.Second, 2*time.Minute); err != nil {
		log.Fatal(err)
	}
	data, err := client.Exports.DownloadBytes(job.Data.JobID)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("export.jsonl", data, 0600); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Saved %d bytes to export.jsonl\n", len(data))
}
