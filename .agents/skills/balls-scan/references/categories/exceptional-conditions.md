# Exceptional input and error handling

Use this guide for attacker-controlled input that can trigger unexpected types, missing values, parse failures, failed network calls, database errors, or partial state changes. Review it with `config.md`, `business-logic.md`, and `resource-exhaustion.md` as relevant.

## Static review method

1. Start from reachable routes and trace absent, malformed, wrong-type, boundary, and unexpected values into conversions, parsers, file/network operations, and database writes.
2. Identify which exceptions each operation may raise and inspect the exact handler scope. Check whether a broad or mismatched exception handler misses the failure, returns sensitive details, continues with an unsafe default, or leaves state partially committed.
3. Trace the order of validation, persistence, authorization decisions, side effects, and session assignment. Look for records created before required checks, nullable authorization flags, and updates skipped when a later operation fails.
4. Trace error responses and templates. Determine whether source-defined debug/error settings expose tracebacks, paths, SQL details, secrets, or user input. Assess configured source behavior; do not assume runtime deployment disables it.
5. Check cleanup and rollback behavior after failures: database transactions, temporary files, locks, external resources, and session state.

## Evidence and impact gates

- A 500 response or caught exception alone is not a security finding. Establish an information disclosure, fail-open authorization decision, integrity/state inconsistency, persistent resource leak, or meaningful availability effect.
- A debug setting is evidence of configured behavior, but remote code execution requires a separate reachable exploit path. Do not infer it from the setting alone.
- For partial-state flaws, name the exact pre-failure state, failing operation, skipped invariant, and later reachable operation that consumes the inconsistent state.
- For unhandled errors, identify what sensitive detail reaches an attacker-controlled response; a server-side log-only stack trace is a different exposure.
- Do not execute the target. Use source and framework behavior to form a reproduction plan and mark any runtime-only result as unverified.

## Common sinks

- `int()`, enum conversion, JSON/XML parsing, path construction, request field access, and deserialization
- Outbound HTTP and file reads that can fail after a database commit
- Broad `except`, `except Exception`, success-shaped fallback values, and error templates
- Flows that persist an account or session before all authorization-related state is initialized
