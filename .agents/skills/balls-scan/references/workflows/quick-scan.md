# Quick scan

Use a bounded pass when the user explicitly asks for a rapid assessment. State that it is less complete than the full scan and preserve the same evidence standards.

1. Identify languages, frameworks, entry points, and major trust boundaries.
2. Initialize a BALLS scan directory and CodeGraph index when available.
3. Prioritize authentication/authorization, injection, XSS, SSRF, file access, secrets/configuration, and unsafe deserialization.
4. Launch all independent `balls-hunter` (`Model: "flash"`) assignments together (up to the 12-agent cap), then verify distinct high-impact candidates in parallel with `balls-verifier` / `balls-verifier-deep` (`Model: "pro"`) and refill free slots reactively.
5. Record what was reviewed and skipped; do not imply comprehensive category coverage.
6. Write the report narrative from verified evidence using `report-writing.md`, render it from SQLite with `--narrative`, and include the coverage limitations.

Do not run the target or its dependencies. Use `../categories/` guides for each assigned weakness class.
