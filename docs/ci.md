# CI integration

## GitHub Action

```yaml
name: MCP posture
on:
  schedule: [{cron: "0 6 * * 1"}]
  pull_request:
    paths: ["mcp-servers.txt", "mcp-posture.toml", ".mcp-posture-ignore", "mcp-posture.lock.json"]

permissions:
  contents: read
  security-events: write   # SARIF upload to code scanning

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: batou9150/mcp-posture@main   # pin to a release tag or commit SHA
        with:
          targets-file: mcp-servers.txt
          fail-on: high
          baseline: mcp-posture.lock.json
          token: ${{ secrets.MCP_SCAN_TOKEN }}   # optional, to list tools behind auth
```

| Input | Default | |
|---|---|---|
| `targets` | | URLs, one per line (`#` comments allowed) |
| `config` | `./mcp-posture.toml` | config file |
| `targets-file` | | file with one URL per line; SARIF results point to its lines |
| `fail-on` | `high` | minimum severity that fails the step |
| `baseline` | | lock file from `mcp-posture pin` |
| `token` | | bearer token, passed to the scanner through the environment, never logged |
| `args` | | extra `mcp-posture scan` arguments |
| `upload-sarif` | `true` | upload to code scanning |
| `sarif-category` | `mcp-posture` | code scanning category |
| `job-summary` | `true` | append the Markdown report to the job summary |
| `fail` | `true` | fail the step on blocking findings |

Outputs: `exit-code`, `sarif-file`, `json-file`. The SARIF upload and the job summary run even
when findings fail the step.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | no unsuppressed finding at or above `--fail-on`, every target reachable |
| `1` | at least one unsuppressed finding at or above `--fail-on` |
| `2` | usage or configuration error |
| `3` | a target was unreachable (and no blocking finding) |

## Other CI systems

```bash
uvx --from git+https://github.com/batou9150/mcp-posture mcp-posture scan \
  --targets-file mcp-servers.txt --sarif mcp-posture.sarif --markdown mcp-posture.md
```

GitLab, Azure DevOps and others ingest the SARIF file directly; the Markdown file is ready to post
as a merge-request comment.
