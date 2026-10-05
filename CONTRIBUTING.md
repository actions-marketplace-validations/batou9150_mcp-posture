# Contributing

Thanks for helping. Bug reports, false positives and new checks are all welcome.

## Ground rules

- Only test against servers you own. Tests run against in-process fixtures
  (`tests/fixtures/servers.py`) or `scripts/demo_servers.py` on localhost; never add a test,
  fixture or example that contacts a third-party server.
- No real hostnames, tokens, tool definitions or reports from production systems in issues,
  fixtures or docs. Use `example.com` / `*.test` names and synthetic data.
- The scanner is passive: metadata `GET`s, the MCP handshake and list calls. Changes that make
  it call tools or send state-changing requests need a design discussion first.

## Development

```bash
uv sync
uv run ruff check && uv run ruff format --check && uv run mypy && uv run pytest
```

`pytest` enforces 90% coverage. `pre-commit install` runs the same checks on commit.
`uv run python scripts/demo_servers.py` starts local fixture servers (secure on :8401,
misconfigured on :8402, poisoned on :8403) to scan with `--allow-private`.

## Adding a check

1. **Find the requirement.** Every check maps to a normative statement (MCP spec revision, RFC,
   IETF draft or security best practice). Add or update its row in `docs/spec-notes.md`.
2. **Pick an ID.** `MCPP-<FAMILY><NN>`, the next free number in the family. IDs are stable:
   never renumber or reuse one; a removed check goes into `RETIRED_IDS` in `registry.py`.
3. **Write the check** in `src/mcp_posture/checks/<family>.py`:

   ```python
   @check(
       id="MCPP-ASM14",
       title="Short, specific title",
       severity=Severity.MEDIUM,
       confidence=Confidence.HIGH,
       revisions=revisions_from(SpecRevision.R2025_11_25),
       references=[R.MCP_AUTH_2025_11],
       rationale="""Why it matters, for someone who has not read the spec.""",
       remediation="""What to change, concretely.""",
   )
   def asm14(ctx: ScanContext) -> Iterator[Finding]:
       ...
       yield ctx.finding("MCPP-ASM14", "What was observed.", location=..., evidence=[...])
   ```

   Checks are pure functions of the frozen `ScanContext`: no network I/O inside a check. If you
   need more data, collect it in `engine.collect` / `discovery.py` / `client.py` through the
   `Fetcher` (which enforces the SSRF guard, size caps and redirect policy).
   Give findings a `location` and, when one check can fire several times on the same location,
   a distinct `key`, so fingerprints stay unique and stable across runs.
4. **Test both ways.** Add a positive and a negative test marked
   `@pytest.mark.check("positive", "MCPP-ASM14")` and `@pytest.mark.check("negative", ...)`.
   `tests/test_catalogue.py` fails if either is missing. Prefer a fixture profile knob
   (`McpProfile` / `AsProfile`) over a hand-built context when the check reads HTTP data.
5. **Docs** are generated from the registry (`docs/gen_checks.py`); the README family table is
   checked by `tests/test_docs.py`.

Regenerate golden reports when output changes on purpose:
`UPDATE_GOLDEN=1 uv run pytest tests/test_report.py`, then review the diff.

## Commits and pull requests

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
(`feat:`, `fix:`, `docs:`, `ci:`, `deps:`...). release-please derives versions and the changelog
from them, so a user-visible change needs `feat:` or `fix:`. A new check is a `feat:`; a
change of a check's default severity is a `feat:` with a note in the body.

Keep pull requests focused, with tests, and green CI.
