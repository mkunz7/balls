# Component review

The reviewer establishes facts for hunters; it does not assert vulnerabilities or severity.

For the assigned component, use CodeGraph and targeted source reads to map:

- Public entry points, route handlers, event handlers, CLI commands, and background jobs.
- Inputs and their validation, parsing, normalization, and transformations.
- Sensitive sinks: database queries, file access, templates, process execution, outbound network requests, cryptography, and privilege changes.
- Authentication and authorization checks, trust boundaries, shared middleware, and configuration.
- Calls across component boundaries and any dynamic dispatch or callback paths.
- Tests or fixtures that establish expected behavior; do not execute target code.

Return a compact intelligence report with exact relative paths and line ranges, confirmed defenses, unresolved reachability questions, and high-value hunting areas. Use `codegraph explore "<source to sink or feature flow>"` first for graph structure; follow with direct reads where a finding depends on exact logic.
