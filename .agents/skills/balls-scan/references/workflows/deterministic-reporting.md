# Deterministic reporting

Finding records, IDs, counts, indexes, coverage tables, and source excerpts are assembled deterministically from verified SQLite rows and scan artifacts. The coordinator may add a Codex-authored `report-narrative.json` for section summaries; it must be grounded in the same final artifacts and is included in the report JSON so the prose can be reviewed and reproduced. The renderer does not call a model or API. Obvious credential assignments are redacted from source excerpts.

Use the scan database CLI:

```bash
python3 "$BALLS_ROOT/scripts/balls-db.py" --db "$DB" stats --scan "$SCAN"
python3 "$BALLS_ROOT/scripts/balls-db.py" --db "$DB" report \
  --scan "$SCAN" --source-root "$TARGET" \
  --architecture "$SCAN_DIR/architecture.json" \
  --coverage "$SCAN_DIR/coverage.json" \
  --candidates "$SCAN_DIR/candidates.json" \
  --narrative "$SCAN_DIR/report-narrative.json" \
  --comparison "$SCAN_DIR/reference-claim-matrix.json" \
  --out "$SCAN_DIR/BALLS-REPORT.md"
```

Pass `--comparison` when a reference claim matrix exists. Pass `--narrative` when the coordinator has written evidence-led section summaries. The Markdown and JSON include scope, component architecture, category coverage, candidate dispositions, exploit chains, remediation priorities, and optional claim-by-claim comparison. Review both outputs for accurate paths, current line ranges, redacted secrets, and consistent totals. Unresolved candidates remain outside verified finding counts and the overall risk rating.
