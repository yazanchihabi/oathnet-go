# Unreleased

This candidate is awaiting a published Go module revision. The public module
still resolves to the earlier SDK until that revision is published.

- Added identity enrichment, reusable monitor destinations, explicit GET search
  methods, context cancellation, and download responses with content headers.
- Query arrays now use repeated plain keys, such as `fields=email&fields=dbname`.
- Breach records preserve every source JSON value in `V2BreachResult.Raw`.
  Existing scalar fields remain available when the source contains a matching
  scalar value.
- Job helpers reject malformed responses, stop on failed or canceled jobs, and
  apply polling deadlines to HTTP requests as well as waits. HTTP errors retain
  status, code, details, and retry headers. Downloads reject API error envelopes
  returned as JSON without an attachment header.
- File metadata selectors support multiple names, folders, kinds, and extensions.
  Optional numeric overrides preserve explicit zero values in requests.
- Victim property results retain optional active/confidence values, so callers
  can distinguish an unreported value from false or zero.

`FileSearchProgress.Percent` changed from `int` to `float64` because the API can
return fractional progress, such as `12.5`. Code that assigns this field to an
integer variable must now convert it explicitly with `int(progress.Percent)` or
use a `float64` variable. The conversion truncates the fractional part.

Search convenience methods retain their automatic POST behavior for structured
filters. Use `SearchGet` when you require the explicit GET operation. Existing
method names and scalar option fields remain available; new pointer overrides
take precedence when set.
