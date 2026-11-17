# Independent finding verification

Give one unique candidate to a fresh verifier. The verifier should inspect the target source and relevant CodeGraph paths independently, then try to disprove the claim.

Check attacker reachability, input control, exact source-to-sink behavior, framework defaults, sanitizer context, authorization, repository-defined configuration, and realistic impact. Search the repository for the strongest counterexample or mitigating control and re-check every cited line. Treat the application as supplied: do not invent a secure environment override, proxy control, or hosting setting. A hypothetical external mitigation is unknown context, not evidence that disproves a source-defined weakness. Bound the claim to what the code establishes; do not assert a production deployment without repository evidence.

Return one verdict:

- `CONFIRMED`: evidence establishes the security weakness and impact.
- `LIKELY`: most of the path is supported, with a specific unresolved assumption.
- `POSSIBLE`: plausible but missing material evidence; keep out of confirmed totals.
- `FALSE_POSITIVE`: a specific control or incorrect premise disproves the candidate.

For each surviving candidate, also provide a source-supported reproduction plan when practical. Never execute the target, payloads, or reproduction commands. Prefer commands that target a disposable local instance, use test-only values, and make one bounded request. Do not include destructive actions, loops that exhaust resources, real credentials, secret values, or commands aimed at third-party systems. If a command is not safe or the required environment is unknown, give manual steps and explain the limitation instead of inventing a runnable exploit.

Include attacker, defender, and auditor reasoning. The coordinator uses these notes to populate the finding record, so make them specific to the code and any plausible counterargument.

## Finding write-up fields

Return enough detail for a reviewer to understand the issue without reconstructing it from the raw source:

- **Summary / description:** 2–4 sentences naming the root cause, affected operation, violated security property, and why the existing code permits it.
- **Evidence / data flow:** exact source and sink, relevant transformations, validation or authorization behavior, and line references. Include the shortest decisive source excerpt.
- **Attack scenario:** state the attacker's starting access, the input or action they control, the required steps or victim action, and the observable success condition. Do not provide speculative steps.
- **Impact:** state confidentiality, integrity, and/or availability effects as applicable; identify affected data or users and bound claims by process permissions, network reachability, repository-defined controls, or other concrete evidence. Do not reduce impact based on hypothetical deployment controls.
- **Defenses and counterarguments:** explain the strongest defense or limiting condition and why it does or does not prevent the path.
- **Remediation:** lead with the code-level fix; add validation, safe failure behavior, least privilege, or defense-in-depth controls only when they address this path.
- **Reproduction plan:** provide `preconditions`, ordered `steps` (each with an action, optional command, and expected result), and `limitations`. Use placeholders for target addresses and credentials. If source evidence is sufficient but no safe command can establish the behavior, say so explicitly.
- **Fixed-code example:** provide a minimal, language-appropriate `fix_example` with `language`, `code`, and optional `notes`. Keep it scoped to the actual vulnerable path; identify dependencies or assumptions and do not present pseudocode as drop-in code.

Return both objects with the candidate record. The coordinator stores them in `candidates.json` using `--reproduction-json` and `--fix-example-json`, then carries verified versions into `report-narrative.json`.

Do not copy OWASP/CWE mappings into prose. The report renderer adds its curated CWE and OWASP references from the verified finding's CWE and issue type.

The scanner renders the vulnerable source excerpt as **Before** and the `fix_example` as **Example Fixed Code**. Reproduction commands are report-only guidance; never run them as part of the scan.
