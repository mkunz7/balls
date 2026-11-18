# BALLS Security Scanner Plugin

Workspace-scoped Antigravity plugin for **BALLS (Better Agentic Large Language Scanner)**.

## Bundled Subagents

- `balls-reviewer` (invoked with `Model: "flash"`): Read-only component security reviewer using CodeGraph and source inspection.
- `balls-hunter` (invoked with `Model: "flash"`): Read-only category vulnerability hunter scoped to one component and 1–2 related categories.
- `balls-coverage-critic` (invoked with `Model: "flash"`): Read-only auditor verifying coverage completeness and candidate ledger integrity.
- `balls-verifier` (invoked with `Model: "pro"`): Skeptical independent verifier for routine vulnerability candidates.
- `balls-verifier-deep` (invoked with `Model: "pro"`): Deep high-reasoning verifier for Critical/High findings, exploit-chain pivots, and contested claims.
