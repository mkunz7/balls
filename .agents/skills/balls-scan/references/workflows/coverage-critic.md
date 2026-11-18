# Coverage critic

Start this pass once the initial component reviews and category hunters finish, using a fresh `balls-coverage-critic` subagent (`Model: "flash"`) that did not author the primary coverage map or hunting assignments. To reduce idle time, verification of already collected candidates may run concurrently. Finish the critic before closing the scan; launch its follow-up hunters in free slots and verify their returned candidates afterward.

## Inputs

- `architecture.json`
- `coverage.json` including stable component/category `unit_id`s and completed assignments
- `candidates.json`
- current source inventory and CodeGraph status
- per-agent results and category guides used

## Audit steps

1. Confirm every meaningful component from the architecture map has one component reviewer and every applicable component/category pair has a coverage unit.
2. Compare unit IDs with assignments. Flag missing, duplicated, cross-component, too-broad, or uncompleted work. A category marked complete needs its own evidence or explicit no-finding result.
3. Compare the source inventory and CodeGraph routes/call edges with reviewed files. Look for reachable inputs to filesystem, HTTP clients, templates, parsers, SQL, subprocesses, authentication, authorization, and expensive operations that have no corresponding unit or candidate.
3a. For each web route, check that route-specific error rendering, authentication-abuse controls, CSRF/state-change behavior, and exceptional input paths were considered independently where applicable. A category-wide pass does not establish that every endpoint or failure branch was reviewed.
4. Check that every hunter-reported hypothesis appears in the candidate ledger as `PENDING` before verification. Flag leads that disappeared, were merged without a target record, or were promoted without a source path.
5. Identify high-risk units with only one narrow pattern pass. Request independent second hunters for authentication/session, authorization/IDOR, injection, XSS, SSRF, path traversal/file access, deserialization, secrets, and resource exhaustion where applicable.
6. Re-open each relevant guide for uncovered or weakly reviewed units. Do not ask one agent to review unrelated components to fill several gaps at once.
6a. For authentication surfaces, compare distinct failure branches and repository-defined throttling controls. For outbound HTTP calls, check URL construction, transport security, redirect/timeout/size policy, and whether response data influences authorization. For input-handling paths, trace exception behavior and partially persisted state.
6b. For authorization, require a route × method × principal/resource matrix or a concrete reason it is inapplicable. For business workflows, require state/invariant and failure-order traces. For file access, distinguish a local artifact from an artifact reachable through application/server configuration. For dependency claims, require manifest plus lock/resolution and advisory-range evidence, or retain the lead as needs-validation.
7. Emit a short critic result with: unit ID, defect, risk, exact missing evidence, requested follow-up assignment, and completion decision. The coordinator updates `coverage.json` and repeats the critic only for failed units.

## Exit condition

Exit only when each applicable unit has a reviewer/hunter assignment, a disposition, and evidence or a reason it could not be assessed. Mark genuinely irrelevant units `not-applicable` with a concrete reason. If CodeGraph or source is unavailable, mark the affected units `degraded` and state the fallback used; never mark them fully reviewed by implication.
