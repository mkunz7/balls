# Scan resumption

All durable work belongs in `<target>/.balls/scans/<id>/` and the scan database. After a new session or context compaction, resume from artifacts rather than relying on chat history.

1. Read `coverage.json`, `architecture.json`, and `candidates.json` if present.
2. Query `balls-db.py stats --scan "$SCAN"` and list components, candidates, and verified findings from the database.
3. Compare completed assignments with the coverage ledger; launch only missing or explicitly reopened units.
4. Preserve the same scan ID and database path. Do not reset the ledger or duplicate existing findings.
5. Before finishing, write the current stage, open questions, and next actions into `progress.md`.

If the DB is unavailable, report the problem and recover from the JSON artifacts only after checking their scan ID and target path.
