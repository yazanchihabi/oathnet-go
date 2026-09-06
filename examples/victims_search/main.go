// Inspect a selected victim. Set OATHNET_LOG_ID from a preceding search.
package main

import (
	"fmt"
	"github.com/oathnet/oathnet-go/examples/internal/exampleclient"
	"log"
)

func main() {
	client := exampleclient.New()
	logID := exampleclient.Required("OATHNET_LOG_ID")
	summary, err := client.Victims.GetSummary(logID, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Summary for %s; limited preview: %t\n", summary.LogID, summary.PolicyRedacted)
	manifest, err := client.Victims.GetManifest(logID)
	if err != nil {
		log.Fatal(err)
	}
	if manifest.VictimTree == nil {
		log.Fatal("manifest did not contain a file tree")
	}
	fmt.Printf("File tree: %s, %d top-level entries\n", manifest.VictimTree.Name, len(manifest.VictimTree.Children))
}
