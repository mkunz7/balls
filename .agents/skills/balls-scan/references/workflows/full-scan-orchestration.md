# Full scan orchestration

Use this checklist with the `balls-scan` skill. It adapts the multi-stage audit workflow to Antigravity native subagents (`invoke_subagent` / `run_workflow`) and the BALLS scripts.

1. Resolve `BALLS_ROOT` and `TARGET`, and establish a unique scan directory under `<target>/.balls/scans/<id>/`.
2. Set `CODEGRAPH` to the absolute path of `$BALLS_ROOT/scripts/codegraph-agent.sh`. Check/build the CodeGraph index through this wrapper. Include `BALLS_ROOT` and `CODEGRAPH` absolute paths in subagent prompts; do not assume subagents inherit the coordinator's `PATH`. Use `cd "$TARGET" && "$CODEGRAPH" explore` for symbol and source-to-sink questions; inspect the returned source at decisive locations with `read_file`.
3. Map components, entry points, data stores, trust boundaries, and security controls. Record the map in `architecture.json` and create explicit work units in `coverage.json` for each applicable component × category pair. Do not use one row per category for the whole repository.
3a. For web applications, inventory each route and method, then map relevant route-level checks (authentication abuse, CSRF, output encoding, and error handling) to explicit units or record why they do not apply. Inventory every outbound HTTP client call separately from inbound route handling.
3b. For authorization and business-logic units, map principal/resource access and workflow states/invariants. For supply-chain units, inventory manifests and lockfiles and separate repository-resolved versions from any unobserved installed environment.
4. Prepare the complete independent assignment queue after the initial architecture map. Launch `balls-reviewer` (`Model: "flash"`) and `balls-hunter` (`Model: "flash"`) subagents together in parallel; do not make hunters wait for all reviewers to finish. Keep up to 10–12 active subagents (excluding the coordinator) and refill each free slot reactively as Antigravity wakes the coordinator upon subagent completion (never poll in a loop). Each hunter task covers one component and no more than two related categories; never merge unrelated components into broad labels such as "web", "identity", or "residual". Use one or two relevant guide sections rather than loading a long guide in full. If the repo has fewer independent assignments, launch all of them.
5. Record every hypothesis with `scripts/balls-candidates.py add` before verification. Once the initial candidate ledger is complete, start candidate verification and a separate `balls-coverage-critic` (`Model: "flash"`) in parallel. Launch focused follow-up `balls-hunter` subagents for gaps as slots free; verify those new candidates as soon as they return.
6. Deduplicate candidates, then launch fresh verifier subagents concurrently, up to 11 while reserving one of the 12 slots for `balls-coverage-critic`; refill reactively as each finishes. Use `balls-verifier` (`Model: "pro"`) for routine verification; use `balls-verifier-deep` (`Model: "pro"`) for Critical/High findings, chain pivots, and materially contested cases. Preserve confirmed, likely, possible, rejected, merged, and unresolved cases with rationale and cross-links.
7. The coordinator writes verifier-approved evidence to SQLite. This keeps write ownership clear while hunters and verifiers remain read-only.
8. Run cross-component chain analysis, render the report with the DB CLI, then check report paths and source excerpts.

Initialize state with:

```bash
mkdir -p "$SCAN_DIR"
python3 "$BALLS_ROOT/scripts/balls-db.py" --db "$DB" init \
  --scan "$SCAN" --slug "$SLUG" --remote "$REMOTE" --target "$TARGET"
```

The database is per scan, uses SQLite WAL plus a busy timeout, and makes report generation reproducible. Save progress to files before context compaction or ending the session.

## Coverage unit format

Use one stable row for every applicable component/category pair; mark non-applicable pairs with a short reason rather than silently omitting them. For example:

```json
{
  "unit_id": "pictures::ssrf",
  "component": "pictures",
  "category": "ssrf",
  "assigned_agent": "balls-hunter-pictures-ssrf",
  "status": "assigned",
  "evidence": [],
  "note": null
}
```

Each reviewer or hunter must report its `unit_id`s, sources inspected, CodeGraph flows (or explain why CodeGraph was unavailable), candidates, and explicit no-finding conclusions. A fresh coverage critic compares completed unit IDs against the plan while initial verification proceeds, then opens focused follow-ups for gaps. The final coverage record must distinguish `confirmed`, `needs-validation`, `rejected`, `reviewed-no-finding`, `not-applicable`, `degraded`, and `not-reviewed`; do not mark a category complete merely because another category in the same component was inspected.

## Scheduling rules

- Do not run reviewer, hunter, and verifier phases as serial groups when their inputs are ready. Reviewers and hunters start together after the architecture/coverage plan; verification starts after candidate deduplication while the separate coverage critic checks for gaps.
- Treat assignments as a work queue. Launch up to 12 independent subagents in the initial fan-out, then dispatch the next assignment immediately when a slot frees. Never wait for every agent in a batch if completed agents can be replaced.
- Keep work independent: one hunter owns its result, while only the coordinator writes shared scan artifacts and SQLite. Grouping reduces duplicate repository exploration without combining unrelated risk classes.
- Keep prompts lean: pass concise architecture notes, exact unit IDs, relevant graph paths, and only matching category-guide sections. Ask for the required evidence schema and a short no-finding record, not a narrative essay.
- Record planned task count, peak active subagents, and elapsed seconds for reconnaissance, hunting, verification, and reporting under `coverage.json` → `execution`. Update `maxObservedConcurrentSubagents` from actual observations; do not claim the configured cap was reached unless observed. If peak activity is much lower than the available independent work, explain why rather than silently serializing.
