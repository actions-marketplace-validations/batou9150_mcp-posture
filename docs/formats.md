# Report formats

| Format | Flag | Use |
|---|---|---|
| table | `-f table` (default) | terminal |
| JSON | `-f json` or `--json PATH` | automation; schema below |
| SARIF 2.1.0 | `-f sarif` or `--sarif PATH` | GitHub code scanning and other SARIF consumers |
| Markdown | `-f markdown` or `--markdown PATH` | PR comments, job summaries |

Output is deterministic: findings are sorted by target, severity, check ID and fingerprint;
`--no-timestamp` drops the only time-dependent field.

## JSON

The report is versioned (`schema_version: "1.0"`); the JSON Schema is published at
[`schema/report-v1.json`](schema/report-v1.json) and tested against the code. Every finding
carries a `fingerprint` (stable across runs for the same check, target and location) for
deduplication.

## SARIF

- One rule per catalogue entry, with `security-severity` for GitHub's severity mapping and a
  `helpUri` to this site.
- Code scanning only displays results attached to a file in the repository, so each result is
  anchored to the file and line that declares the target (targets file, `mcp-posture.toml`,
  `.mcp.json`), or to `--sarif-anchor`.
- `partialFingerprints` carry the finding fingerprint, so alerts are tracked across runs.
- Suppressed findings are emitted with SARIF `suppressions` and their justification.

## Neutralized text

Tool names, descriptions and error bodies come from the scanned server. Reports never contain
raw control, bidi or invisible characters: JSON and SARIF escape them (`\u202e`), table and
Markdown show `<U+202E>`.
