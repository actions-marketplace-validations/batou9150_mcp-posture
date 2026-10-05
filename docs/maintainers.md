# Maintainer guide

## Releasing

Releases are automated by [release-please](https://github.com/googleapis/release-please)
(`.github/workflows/release.yml`):

1. Every push to `main` updates a release PR with the next version (from Conventional Commit
   types) and the `CHANGELOG.md` entry. Version strings live in `pyproject.toml`,
   `src/mcp_posture/__init__.py`, `.claude-plugin/plugin.json`, `uv.lock` and
   `.release-please-manifest.json`; `scripts/check_version.py` fails the build if they disagree.
2. Merging the release PR tags `vX.Y.Z` and creates the GitHub release. The workflow then:
    - builds the sdist and wheel, attests their build provenance and a CycloneDX SBOM;
    - publishes to PyPI with Trusted Publishing (environment `pypi`, PEP 740 attestations);
    - attaches the distributions and the SBOM to the GitHub release;
    - builds the multi-arch image, pushes it to `ghcr.io/batou9150/mcp-posture`, signs it with
      cosign (keyless) and attaches provenance and SBOM attestations.

**Release candidates** are tagged by hand on a commit whose version strings already say
`X.Y.Z-rcN`: push the tag first (`git push origin vX.Y.Z-rcN`), which runs the same jobs and
creates a pre-release, then push `main`. To leave the RC line, add a `Release-As: X.Y.Z` footer
to a commit on `main`.

Pre-releases do not move the `latest` or `X.Y` image tags.

## One-time repository setup

- **PyPI**: a (pending) trusted publisher for owner `batou9150`, repository `mcp-posture`,
  workflow `release.yml`, environment `pypi`.
- **Environment `pypi`**: Settings > Environments. Add yourself as required reviewer so every
  upload waits for a manual approval, and restrict deployment to tags `v*`.
- **Actions**: Settings > Actions > General > Workflow permissions: read-only default, and allow
  GitHub Actions to create pull requests (release-please needs it).
- **Pages**: source *GitHub Actions*; repository variable `DEPLOY_DOCS=true`.
- **Security**: enable private vulnerability reporting, Dependabot alerts and security updates,
  secret scanning with push protection, code scanning (CodeQL workflow).

## Branch protection

Recommended ruleset for `main` (Settings > Rules > Rulesets):

- Require a pull request before merging (0 approvals is fine for a solo maintainer; it keeps
  release-please and Dependabot changes reviewable).
- Require status checks: `check (3.12)`, `check (3.13)`, `audit`, `package`, `selftest`,
  `build` (Docker), `analyze (python)`, `analyze (actions)`.
- Require linear history; block force pushes and deletions.
- Tag ruleset for `v*`: restrict creation to maintainers, block deletion and updates.

## Dependencies

Dependabot opens weekly grouped PRs for GitHub Actions (pinned by commit SHA), uv
dependencies and the Docker base images (pinned by digest). `tests/test_action.py` fails if an
action or base image loses its pin.
