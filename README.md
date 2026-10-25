# RoninOS Review Action

Runs the deterministic aperture on a pull request and publishes:

- one idempotent `RoninOS` check run,
- one marker-tagged summary comment,
- line-anchored review comments for modeled findings.

It runs in the caller's GitHub runner. No RoninOS server receives the caller's source
code on this path.

## Requirements

- `actions/checkout` with `fetch-depth: 0` before this action.
- `contents: read`, `pull-requests: write`, and `checks: write`.
- A published `roninos` package version. The action pins the version explicitly.

## Local use in this repository

```yaml
permissions:
  contents: read
  pull-requests: write
  checks: write

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: ./actions/roninos-review
        with:
          github-token: ${{ github.token }}
          roninos-version: '3.0.0'
          head-sha: ${{ github.event.pull_request.head.sha || github.sha }}
```

The repo workflow `.github/workflows/roninos-review.yml` uses this shape and is
`workflow_call`-ready.

## External use

The public action is published at `freewho99/roninos-review-action`. Pin the
reviewed release tag rather than a floating branch:

```yaml
permissions:
  contents: read
  pull-requests: write
  checks: write

jobs:
  roninos:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: freewho99/roninos-review-action@v1.0.7
        with:
          github-token: ${{ github.token }}
          roninos-version: '3.0.0'
          head-sha: ${{ github.event.pull_request.head.sha || github.sha }}
```

One workflow is the whole install. No RoninOS-hosted runner is required; the
action executes in the caller's runner.

## Current scope

This Action delivers the deterministic review surface, a hidden receipt for PR
chat, Tree-sitter-verified single-hunk suggestion blocks, and thread resolution
only on a clean re-audit. A clean PR posts one successful check run and no PR
comment. Finding comments carry the receipt's Ed25519 attestation; the hidden
receipt marker also carries the public key used by the runner.

Verify a receipt offline:

```bash
node scripts/verify-roninos-receipt-v0.mjs roninos-receipt.json public-key.pem
```

External Marketplace publication and the external-repository acceptance run are
the remaining delivery step.

## Idempotency

The summary comment and check run carry stable markers and are updated on rerun.
An existing review containing the same marker is not posted twice.
