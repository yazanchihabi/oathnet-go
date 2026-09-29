# OathNet Go SDK

Use the Go client for OathNet searches, investigations, public-account enrichment, exports, bulk jobs, and monitors. Go 1.21 or later is required. The repository also contains a smaller command-line client.

## Install

```bash
go get github.com/oathnet/oathnet-go
export OATHNET_API_KEY="YOUR_API_KEY"
```

Keep your key in the environment or a secret manager. See [authentication](https://docs.oathnet.org/introduction/authentication) for creating a key.

## Make a search

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "time"

    "github.com/oathnet/oathnet-go/pkg/oathnet"
)

func main() {
    client, err := oathnet.NewClient(os.Getenv("OATHNET_API_KEY"))
    if err != nil { log.Fatal(err) }

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    response, err := client.WithContext(ctx).Breach.Search("user@example.com", &oathnet.BreachV2SearchOptions{
        Page: 4,
        PageSize: 25,
        Fields: []string{"email", "dbname"},
    })
    if err != nil { log.Fatal(err) }
    if !response.Success || response.Data == nil { log.Fatal("search returned no successful data") }

    fmt.Printf("Received %d records\n", len(response.Data.Items))
    for _, item := range response.Data.Items {
        fmt.Printf("email=%s source=%s\n", item.Raw["email"], item.Raw["dbname"])
    }
}
```

`Raw` preserves the source document's JSON values, including arrays, objects, nulls, numbers, and custom fields. Existing scalar convenience fields such as `Email` are populated when that source value is a string. Use `Raw` for integrations that need every source shape.

Set `Page` and `PageSize` on breach, stealer, victim, or investigation search options. Read `response.Data.Meta.Page`, `TotalPages`, `TotalResults`, and `ResultLimit`. Legacy response data exposes the page metadata as `Pagination`, preserving its existing account `Meta` field.

Pages start at 1. The default page size is 25; the backend caps it at 500. Your plan limits the total accessible results, with no separate plan page-count or page-size limit. `total_pages` describes that accessible window; it is 0 for an empty or incomplete response. Interactive search has a technical window of at most 10,000 results.

Existing cursor calls remain supported. Send the returned cursor unchanged with the original search options, and omit `page`. Do not combine a page number with a cursor. Keep the query and sort stable; the index can change between requests. A total with `Meta.TotalRelation == "gte"` is a lower bound. See [pagination](https://docs.oathnet.org/guides/pagination).

## Select a workflow

The SDK has methods for every operation in the public OpenAPI document. Aliases ending in `V2` call the same operation as their shorter method names.

| Workflow | Methods | Guide |
| --- | --- | --- |
| Search session | `Search.InitSession` | [Sessions](https://docs.oathnet.org/guides/search-sessions) |
| Data Breaches | `Breach.Search`, `SearchPost`, `Autocomplete`, `AutocompleteDBNames`, `AutocompleteFields` | [Breach search](https://docs.oathnet.org/guides/breach-search) |
| Stealer | `Stealer.Search`, `SearchPost`, `Subdomain`, `GetPhonebook` | [Stealer](https://docs.oathnet.org/guides/stealer-search) |
| Connected records | `Stealer.InvestigationSearch`, `InvestigationSearchPost` | [Investigations](https://docs.oathnet.org/guides/investigations) |
| Victims | `Victims.Search`, `SearchPost`, `GetSummary`, `SearchVictimProperties`, `SearchVictimPropertiesPost`, `GetProperties` | [Victims](https://docs.oathnet.org/guides/victims) |
| Cookies | `Victims.GetCookies`, `InspectCookieDomain` | [Victim reference](https://docs.oathnet.org/api-reference/getVictimCookiesV2) |
| Files and archives | `Victims.SearchFilesMetadata`, `SearchFilesMetadataPost`, `GetManifest`, `GetFile`, `GetFileResponse`, `DownloadArchiveBytes` | [Files](https://docs.oathnet.org/guides/file-search) |
| Search file content | `FileSearch.Create`, `GetStatus`, `WaitForCompletion` | [File search](https://docs.oathnet.org/guides/file-search) |
| Export one search | `Exports.Create`, `List`, `GetStatus`, `DownloadBytes`, `WaitForCompletion` | [Exports](https://docs.oathnet.org/guides/exports) |
| Search several terms | `Bulk.Create`, `List`, `GetStatus`, `DownloadBytes`, `WaitForCompletion` | [Bulk search](https://docs.oathnet.org/guides/bulk-search) |
| Monitor management | `Scanners.GetQuota`, `List`, `Create`, `Get`, `Update`, `Delete`, `Pause`, `Resume`, `Trigger`, `ListRuns`, `GetRun` | [Monitors](https://docs.oathnet.org/guides/scanners) |
| Monitor delivery | `Scanners.TestDraftDelivery`, `TestNotification`, `GetWebhookSecurity`, `RotateWebhookSecret`, `ListDestinations`, `CreateDestination`, `DeleteDestination` | [Webhooks](https://docs.oathnet.org/guides/webhooks) |
| Public-account modules | `OSINT.EnrichIdentity`, `EnrichIdentityPost` | [Enrichment](https://docs.oathnet.org/api-reference/enrichIdentity) |
| Individual lookups | `OSINT.IPInfo`, `Steam`, `Xbox`, `DiscordUserinfo`, `DiscordUsernameHistory`, `RobloxUserinfo`, `Holehe`, `GHunt`, `ExtractSubdomain` | [Account lookups](https://docs.oathnet.org/guides/osint-lookups) |
| Compatibility | `Search.Breach`, `Search.Stealer`, `Utility.DBNameAutocomplete`, `OSINT.MinecraftHistory` | [Legacy routes](https://docs.oathnet.org/guides/legacy) |

`MinecraftHistory` is a disabled compatibility route and returns an empty history. `DiscordToRoblox` remains in the SDK for older callers but is not a supported lookup for new integrations.

## Filters and sessions

`Breach.Search`, `Stealer.Search`, and `Victims.Search` switch to POST when the options include `Filter` or `FilterID`. Their `SearchGet` methods explicitly use GET, including structured filters. Use `SearchPost` with a `V2SearchPostBody` to send an explicit JSON body. Array query parameters use repeated plain names, such as `fields=email&fields=dbname`.

`AI.Create` turns a natural-language request into a structured filter; `AI.GetContext` retrieves its temporary context. Build and preserve reusable filters using the [structured filter guide](https://docs.oathnet.org/guides/structured-filters).

`Search.InitSession` returns `Data.Session.ID`. Set `SearchID` on related searches to use that session. Sessions expire and have service allowances; they do not make every operation free or schedule repeated searches.


## Jobs and downloads

Check the creation response and save `Data.JobID`. `WaitForCompletion(jobID, pollInterval, timeout)` honors the server's suggested polling delay and applies the timeout to the complete wait, including HTTP requests. It returns a `JobError` for failed, canceled, or expired jobs. Only a completed job is ready to download.

`Exports.DownloadBytes` and `Bulk.DownloadBytes` return bytes. `Download` writes a file. `DownloadResponse` retains response headers. For victim files, use `Victims.GetFileResponse` and check `Header.Get("Content-Type")`: account-limited access can return a JSON preview with HTTP 200. Do not save a preview as an original file. See [jobs](https://docs.oathnet.org/guides/jobs) for expiry and job-specific access rules.

## Errors and cancellation

Check both the returned error and the endpoint's result fields. HTTP 200 may contain partial lookup outcomes, a failed notification test, or redacted results.

HTTP errors use `AuthenticationError`, `ValidationError`, `NotFoundError`, `RateLimitError`, or `OathNetError`. These retain `StatusCode`, `Code`, `Details`, `Response`, and `RetryAfter` when supplied by the server. Error classification does not replace checking the server's policy or quota message. The SDK does not automatically retry requests.

`WithTimeout` sets a timeout for each HTTP request. `client.WithContext(ctx)` binds a separate client to a caller's cancellation or deadline. `WithHTTPClient` accepts a custom transport. Cross-origin redirects do not receive the API key.

## Runnable examples

Clone the repository, set `OATHNET_API_KEY`, and run an example from its root:

```bash
go run ./examples/basic_usage
```

`OATHNET_QUERY` overrides the synthetic `user@example.com` query. `OATHNET_BASE_URL` optionally selects a development API, including its `/api` prefix. The default origin is `https://oathnet.org/api`.

| Example | What it demonstrates |
| --- | --- |
| `basic_usage` | One V2 search and lossless source values |
| `breach_search` | A structured email filter |
| `pagination` | At most three pages with a workflow deadline |
| `stealer_search` | Credentials connected to Victims |
| `victims_search` | Summary and file manifest; requires `OATHNET_LOG_ID` |
| `file_search` | A content-search job; requires `OATHNET_LOG_ID` |
| `exports` | A bounded export saved to `export.jsonl` |
| `osint_lookups` | One enrichment module; requires `OATHNET_USERNAME` |
| `error_handling` | Status and retry metadata without automatic retries |

## Go command-line client

```bash
go build -o oathnet ./cmd/oathnet
./oathnet --help
./oathnet stealer search --help
```

The Go CLI supports a subset of SDK methods. Use its command help for current flags; use the SDK for investigations, monitor destinations, enrichment modules, and other operations absent from the CLI. The [main CLI documentation](https://docs.oathnet.org/sdks/cli) describes the separately maintained Python CLI.

## Development and tests

```bash
go test ./...
go test -race ./pkg/oathnet
go vet ./...
go build ./...
python3 scripts/check_openapi_parity.py --openapi ../../docs-site/openapi.yaml
```

The parity script requires PyYAML and a local copy of the public OpenAPI document. The shown path is for the monorepo; use `--openapi` to select another copy. It captures actual SDK requests without opening a socket and checks every OpenAPI operation and option. It proves serialization; the separate `scripts/runtime-probe` program verifies responses against an explicitly approved disposable API.

Normal tests use local HTTP fixtures and require no API key. The existing integration tests run only with `OATHNET_LIVE_TESTS=1`, `OATHNET_API_KEY`, and an explicit loopback `OATHNET_BASE_URL` that includes a port. Before opting in, prove that the API's database, caches, and downstream services are disposable. Those tests create jobs and consume development quota; a loopback URL alone does not prove isolation.

See [documentation](https://docs.oathnet.org), [SDK source](https://github.com/oathnet/oathnet-go), and [support](https://docs.oathnet.org/resources/support).
