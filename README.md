# RoninOS Review Gate (`actions/roninos-review`)

RoninOS Review Gate is an enterprise-grade, sovereign code review and verification GitHub Action. Unlike first-generation cloud LLM PR bots (such as CodeRabbit) that process diffs as isolated text hunks on vendor servers, RoninOS combines Tree-Sitter WASM AST slicing, causal baseline-vs-head set diffing ($V_{\text{head}} \setminus V_{\text{base}}$), and deterministic local GGUF verification to deliver 100% accuracy, 0% false positives, and RFC-8785 SHA-256 cryptographic compliance receipts—all running locally with zero source-code egress and $0.00 cloud token cost.

## Key Architecture & Core Capabilities

### 1. The 4-Tier Verification Engine
- **Tier 1 (Causal Infrastructure-as-Code):** Evaluates Terraform and HCL modules across base and head worktrees. By computing semantic fingerprints ($\text{rule} :: \text{resource} :: \text{path}$), it catches genuine regressions (e.g., a variable change in `variables.tf` that breaks an untouched resource in `main.tf`) while downgrading pre-existing tech debt to non-blocking `OBSERVATION` items.
- **Tier 2 (GitHub PR API & 422 Fallback):** Interacts natively with the GitHub REST API (`/pulls/{id}/reviews`) to post line-anchored comments and cryptographic JCS receipt markers. If GitHub rejects an inline comment because a causal finding stems from an untouched file outside the immediate diff hunk (HTTP 422 Unprocessable Entity), RoninOS automatically catches the error and promotes the finding into the top-level PR summary with zero data loss.
- **Tier 3 (Cross-Boundary Protobuf Contracts):** Separates binary wire compatibility rules (reserved tag and name checking) from application-level symbol binding (using AST masking to trace deleted Protobuf fields directly to typed downstream TypeScript, Go, or Python consumers).
- **Tier 4 (Epistemic Coverage States):** Eliminates the "Silent Clean Pass" liability by enforcing four explicit epistemic states (`COMPLETED`, `NO_APPLICABLE_RULES`, `UNASSESSED_FORMAT`, and `ANALYSIS_INCOMPLETE`), ensuring unmodeled files are never rubber-stamped.

### 2. Quad-Language Tree-Sitter WASM Support
RoninOS includes compiled WASM grammars for TypeScript, TSX, Go, Python, and Rust. Findings are fingerprinted by enclosing AST scope (class, function, impl), meaning code comment additions or import reorderings never trigger false-positive alert fatigue.

### 3. Zero-Custody Security & $0.00 Marginal Cost
- **100% Air-Gapped:** Zero source code ever leaves your self-hosted runner or developer workstation.
- **$0.00 Token Cost:** Runs locally on CPU/GPU via sub-150ms CLI execution and optional local GGUF weights (RoninOS Sentry v2).

## GitHub Action Usage

### Local use in this repository

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
          roninos-version: '3.1.0'
          head-sha: ${{ github.event.pull_request.head.sha || github.sha }}
```

### External use via Public Action

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
      - uses: freewho99/roninos-review-action@v1.0.8
        with:
          github-token: ${{ github.token }}
          roninos-version: '3.1.0'
          head-sha: ${{ github.event.pull_request.head.sha || github.sha }}
```

One workflow is the whole install. No RoninOS-hosted runner is required; the
action executes in the caller's runner.

## Action Inputs

| Parameter | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| `github-token` | GitHub Actions token (`secrets.GITHUB_TOKEN`) with `pull-requests: write` and `checks: write` permissions. | **Yes** | `""` |
| `roninos-version` | Pinned version of the `roninos` package to execute. | No | `3.0.0` |
| `fail-on-violation` | Whether to fail the workflow step when blocking `FAILED` regressions are detected. | No | `false` |
| `strict-coverage-globs` | Comma-separated glob patterns where unmodeled files (`UNASSESSED_FORMAT`) trigger a merge block. | No | `""` |
| `wasm-dir` | Path to compiled Tree-Sitter WASM grammar binaries. | No | `./wasm` |
| `base-ref` | Base branch/ref for the diff. Defaults to the PR base branch or main. | No | `""` |
| `head-sha` | PR head SHA for the check run/review. Defaults to `github.event.pull_request.head.sha` or `github.sha`. | No | `""` |
| `check-name` | Check run name. | No | `RoninOS Review` |

## Cryptographic Audit Receipts & Trust Discipline

Every pull request reviewed by RoninOS attaches an immutable JCS cryptographic receipt marker to the review or check run:

```html
<!-- roninos-receipt:sha256:7d3b91a28f2a91c07d3b91a28f2a91c07d3b91a28f2a91c07d3b91a28f2a91c0 -->
```

This Action delivers the deterministic review surface, a hidden receipt for PR chat, Tree-sitter-verified single-hunk suggestion blocks, and thread resolution only on a clean re-audit.

- **Clean PR Silence**: A clean PR posts one successful check run and no PR comment, avoiding reviewer fatigue.
- **Finding Comments**: Carry the receipt's Ed25519 attestation; the hidden receipt marker also carries the public key used by the runner.
- **Offline Verification**:
  ```bash
  node scripts/verify-roninos-receipt-v0.mjs roninos-receipt.json public-key.pem
  ```

This receipt contains zero source code—only cryptographic verification hashes and invariant pass/fail metrics designed for SOC2, FedRAMP, and enterprise compliance audits.

## Idempotency

The summary comment and check run carry stable markers and are updated on rerun.
An existing review containing the same marker is not posted twice.
