# Local API acceptance probe

This maintenance tool exercises all 70 public operations through the actual Go
SDK. It is separate from `go test`: requests reach a running Django API and its
disposable Search, storage, queue, and provider fixtures.

The target is fixed to `http://127.0.0.1:19800/api`. An operator must establish
that its database and downstream services are isolated before running it. The
tool also checks the development credential broker's safety assertions and
refuses a different HTTP origin. It never reads a key from command-line flags.

```bash
go run ./scripts/runtime-probe \
  --execute \
  --context /path/to/private-broker-context.json \
  --fixtures /path/to/synthetic-fixtures.json \
  --provider-fixtures /path/to/private-provider-fixtures.json \
  --allow-providers --allow-monitors \
  --section all \
  --output /path/to/go-operations.jsonl
```

The broker context supplies `auth.api_key`, `base_urls.django`, development
safety flags, and basic synthetic selectors. The dataset fixture identifies
the selected victim/files, primary email, supplemental autocomplete query, and
source names. The provider fixture supplies approved synthetic identifiers,
expected public response fields, and the task receiver's URL and signing
secret. Keep both context files private. The API key remains in memory.

`--section` accepts `read`, `jobs`, `providers`, `monitors`, `contracts`, or
`all`. The `all` section covers each OpenAPI operation once. Run `contracts`
separately for projection, pagination, false/zero filters, invalid inputs, and
unknown resources. Provider and monitor work requires its corresponding flag.

Assertions inspect decoded SDK results, exact fixture identities, completed
jobs, file matches, parsed ZIP entries, and bounded JSONL downloads. Monitors
and destinations are deleted using only UIDs created by that invocation.
Completed jobs expire through the development API's normal job lifecycle.

Reports contain operation/scenario names, status, response size/hash, HTTP
status, and fixed assertion labels. They contain no keys, secrets, response
bodies, or customer records. Provider wire fixtures prove parsing and API
integration; they do not prove availability of external provider accounts.
GHunt and Holehe availability failures remain failed positive rows when their
provider dependencies are unavailable. Minecraft's disabled compatibility
response has a separate proof label.

Malformed primary-search cursors currently restart the first page. The
`contracts` section checks this documented behavior by comparing record IDs
and returned cursors; it does not misreport that fallback as input rejection.

For request construction without a running API, use
`python3 scripts/check_openapi_parity.py --openapi /path/to/openapi.yaml`.
That check proves exact methods, paths, and parameter forwarding before a
socket is opened. It does not prove server acceptance or response semantics.
