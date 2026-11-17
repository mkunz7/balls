#!/usr/bin/env python3
"""balls-db — the BALLS SQLite CLI.

Agents and their fan-out children write pipeline rows DIRECTLY through this CLI, so there
is no "return results up the chain" plumbing and concurrent writers are serialized safely
by SQLite (WAL + busy_timeout). Report generation is a query, not an LLM task.

Invoke via the plugin-root env var so it resolves from any cwd:
  python "scripts/balls-db.py" <command> --db <path> ...

Commands:
  init            create the schema + scan row
  add-component   register a component (returns its id)
  set-component   update a component's status
  add-aoi         add a reviewer area-of-interest (investigator children)
  add-raw-finding record a hunter finding (category-hunter children) -> id + fingerprint
  add-council     record a council verdict for a raw finding (perspectives required)
  add-chain       create an exploit chain (returns its id)
  add-chain-member add a finding (by fingerprint) to a chain
  promote         deterministic dedup/suppress/number -> findings table
  report          promote, then render BALLS-REPORT.md + .json
  stats           print current counts
  list-aoi        list a component's areas of interest
  list-raw        list a component's raw findings (+ council status)
  list-findings   list promoted survivors across ALL components (for the exploit-chain pass)
"""

import argparse
import json
import os
import sqlite3
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "lib"))
import ballsdblib as db  # noqa: E402
import ballslib as rl  # noqa: E402


def _component_id(conn, scan, name):
    row = conn.execute("SELECT id FROM components WHERE scan_id=? AND name=?", (scan, name)).fetchone()
    if not row:
        sys.exit("ERROR: no component '%s' in scan '%s' (add-component first)" % (name, scan))
    return row["id"]


def cmd_init(a):
    db.init_db(a.db, a.scan, a.slug, a.remote, a.target)
    print("initialized %s (scan %s)" % (a.db, a.scan))


def cmd_add_component(a):
    conn = db.connect(a.db)
    cur = conn.execute(
        "INSERT OR IGNORE INTO components (scan_id, name, language, framework, type, risk_level, "
        " description, paths, status, created_at) VALUES (?,?,?,?,?,?,?,?, 'pending', ?)",
        (a.scan, a.name, a.language, a.framework, a.type, a.risk, a.description, a.paths, db.now()))
    conn.commit()
    cid = _component_id(conn, a.scan, a.name)
    print(cid)


def cmd_set_component(a):
    conn = db.connect(a.db)
    conn.execute("UPDATE components SET status=? WHERE scan_id=? AND name=?", (a.status, a.scan, a.name))
    conn.commit()
    print("component %s -> %s" % (a.name, a.status))


def cmd_add_aoi(a):
    conn = db.connect(a.db)
    cid = _component_id(conn, a.scan, a.component)
    cur = conn.execute(
        "INSERT INTO areas_of_interest (scan_id, component_id, note, file, line, question, created_by, created_at) "
        "VALUES (?,?,?,?,?,?,?,?)", (a.scan, cid, a.note, a.file, a.line, a.question, a.by, db.now()))
    conn.commit()
    print(cur.lastrowid)


def cmd_add_raw_finding(a):
    # A data flow is only meaningful when proven: if a source or sink is given, proof is required.
    if (a.df_source or a.df_sink) and not (a.df_proof and a.df_proof.strip()):
        sys.exit("ERROR: --df-proof is required when --df-source/--df-sink is given "
                 "(an unproven data flow is not a finding — prove it or omit the flow)")
    conn = db.connect(a.db)
    cid = _component_id(conn, a.scan, a.component)
    fp = db.fingerprint_row(a.component, a.cwe_id, a.file, a.line_start, a.type)
    cur = conn.execute(
        "INSERT INTO raw_findings (scan_id, component_id, fingerprint, type, severity, confidence, "
        " attack_vector, cwe_id, cwe_name, file, line_start, line_end, code_snippet, description, "
        " df_source, df_sink, df_sanitization, df_proof, hunter, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (a.scan, cid, fp, a.type, a.severity, a.confidence, a.attack_vector, a.cwe_id, a.cwe_name,
         a.file, a.line_start, a.line_end, a.code, a.description, a.df_source, a.df_sink,
         a.df_sanitization, a.df_proof, a.hunter, db.now()))
    conn.commit()
    print("%d\t%s" % (cur.lastrowid, fp))


def cmd_add_council(a):
    conn = db.connect(a.db)
    row = conn.execute("SELECT component_id FROM raw_findings WHERE id=? AND scan_id=?",
                       (a.raw_finding, a.scan)).fetchone()
    if not row:
        sys.exit("ERROR: no raw finding id=%s in scan '%s'" % (a.raw_finding, a.scan))
    try:
        cur = conn.execute(
            "INSERT INTO council (scan_id, component_id, raw_finding_id, council_vote, severity, "
            " attacker, defender, auditor, proven_primitive, attack_scenario, impact, remediation, "
            " rationale, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (a.scan, row["component_id"], a.raw_finding, a.vote, a.severity, a.attacker, a.defender,
             a.auditor, 1 if a.proven_primitive else 0, a.attack_scenario, a.impact, a.remediation,
             a.rationale, db.now()))
        conn.commit()
    except sqlite3.IntegrityError as exc:
        msg = str(exc)
        if "CHECK" in msg or "attacker" in msg:
            sys.exit("ERROR: council perspectives must all be non-empty "
                     "(--attacker/--defender/--auditor); the DB rejected the row: %s" % msg)
        if "UNIQUE" in msg:
            sys.exit("ERROR: raw finding %s already has a council verdict" % a.raw_finding)
        raise
    print(cur.lastrowid)


def cmd_add_chain(a):
    conn = db.connect(a.db)
    cur = conn.execute(
        "INSERT INTO chains (scan_id, title, combined_severity, rationale, created_at) VALUES (?,?,?,?,?)",
        (a.scan, a.title, a.severity, a.rationale, db.now()))
    conn.commit()
    print(cur.lastrowid)


def cmd_add_chain_member(a):
    conn = db.connect(a.db)
    conn.execute("INSERT INTO chain_members (chain_id, fingerprint, step_order, gains) VALUES (?,?,?,?)",
                 (a.chain, a.fingerprint, a.order, a.gains))
    conn.commit()
    print("ok")


def cmd_promote(a):
    conn = db.connect(a.db)
    s = db.promote(conn, a.scan)
    print("promoted: %d findings, %d dismissed, %d suppressed, %d dangling chains, risk=%s" % (
        s["findings"], s["dismissed"], s["suppressed"], s["dangling_chains"], s["risk_rating"]))


def cmd_report(a):
    conn = db.connect(a.db)
    db.promote(conn, a.scan)  # always render from a fresh promotion
    md, data = db.build_report(conn, a.scan, a.source_root,
                               a.architecture, a.coverage, a.candidates, a.comparison,
                               a.narrative)
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write(md)
    json_path = a.json or (os.path.splitext(a.out)[0] + ".json")
    rl.dump_json(json_path, data)
    print("report -> %s (%d findings) ; json -> %s" % (a.out, data["stats"]["total"], json_path))


def cmd_stats(a):
    conn = db.connect(a.db)
    for tbl in ("components", "areas_of_interest", "raw_findings", "council", "findings",
                "suppressions", "chains"):
        n = conn.execute("SELECT COUNT(*) n FROM %s WHERE scan_id=?" % tbl
                         if tbl != "chain_members" else "SELECT 0 n", (a.scan,)).fetchone()["n"]
        print("%-18s %d" % (tbl, n))


def cmd_list_aoi(a):
    conn = db.connect(a.db)
    cid = _component_id(conn, a.scan, a.component)
    rows = conn.execute(
        "SELECT id, note, file, line, question, created_by FROM areas_of_interest "
        "WHERE scan_id=? AND component_id=? ORDER BY id", (a.scan, cid)).fetchall()
    if a.json:
        print(json.dumps([dict(r) for r in rows], indent=2))
        return
    for r in rows:
        loc = (" (%s:%s)" % (r["file"], r["line"])) if r["file"] else ""
        q = ("  Q: %s" % r["question"]) if r["question"] else ""
        print("[%d] %s%s%s" % (r["id"], r["note"], loc, q))


def cmd_list_raw(a):
    conn = db.connect(a.db)
    cid = _component_id(conn, a.scan, a.component)
    rows = conn.execute(
        "SELECT r.id, r.fingerprint, r.type, r.severity, r.confidence, r.attack_vector, r.cwe_id, "
        " r.cwe_name, r.file, r.line_start, r.line_end, r.df_source, r.df_sink, r.df_sanitization, "
        " r.df_proof, r.description, r.hunter, "
        " (SELECT COUNT(*) FROM council c WHERE c.raw_finding_id=r.id) AS reviewed "
        "FROM raw_findings r WHERE r.scan_id=? AND r.component_id=? ORDER BY r.id", (a.scan, cid)).fetchall()
    if a.json:
        print(json.dumps([dict(r) for r in rows], indent=2))
        return
    for r in rows:
        mark = "" if r["reviewed"] else "  [NEEDS COUNCIL]"
        print("[%d] %s %s %s %s:%s-%s (%s)%s" % (
            r["id"], r["severity"], r["type"], r["cwe_id"] or "", r["file"], r["line_start"],
            r["line_end"], r["hunter"] or "", mark))


def cmd_list_findings(a):
    """List promoted survivors across ALL components — the input to the global exploit-chain
    pass. Run `promote` first (the findings table is empty until then). Each row carries the
    fingerprint needed by `add-chain-member`."""
    conn = db.connect(a.db)
    if not conn.execute("SELECT 1 FROM findings WHERE scan_id=? LIMIT 1", (a.scan,)).fetchone():
        msg = "no promoted findings yet — run `balls-db.py promote --scan %s` first" % a.scan
        print(json.dumps({"error": msg}) if a.json else "(%s)" % msg)
        return
    rows = conn.execute(
        "SELECT report_id, fingerprint, component, type, severity, confidence, attack_vector, "
        " cwe_id, cwe_name, file, line_start, line_end, df_source, df_sink, impact, description "
        "FROM findings WHERE scan_id=? ORDER BY report_id", (a.scan,)).fetchall()
    if a.json:
        print(json.dumps([dict(r) for r in rows], indent=2))
        return
    for r in rows:
        print("%s [%s/%s] %s %s @%s %s:%s-%s fp=%s" % (
            r["report_id"], r["severity"], r["attack_vector"] or "?", r["type"], r["cwe_id"] or "",
            r["component"] or "?", r["file"], r["line_start"], r["line_end"], r["fingerprint"]))
        detail = "    src=%s sink=%s impact=%s" % (
            r["df_source"] or "?", r["df_sink"] or "?", r["impact"] or "?")
        print(detail)


def build_parser():
    p = argparse.ArgumentParser(prog="balls-db")
    p.add_argument("--db", required=True, help="path to balls.db")
    sub = p.add_subparsers(dest="cmd", required=True)

    q = sub.add_parser("init"); q.set_defaults(fn=cmd_init)
    q.add_argument("--scan", required=True); q.add_argument("--slug"); q.add_argument("--remote"); q.add_argument("--target")

    q = sub.add_parser("add-component"); q.set_defaults(fn=cmd_add_component)
    q.add_argument("--scan", required=True); q.add_argument("--name", required=True)
    q.add_argument("--language"); q.add_argument("--framework"); q.add_argument("--type")
    q.add_argument("--risk"); q.add_argument("--description"); q.add_argument("--paths")

    q = sub.add_parser("set-component"); q.set_defaults(fn=cmd_set_component)
    q.add_argument("--scan", required=True); q.add_argument("--name", required=True); q.add_argument("--status", required=True)

    q = sub.add_parser("add-aoi"); q.set_defaults(fn=cmd_add_aoi)
    q.add_argument("--scan", required=True); q.add_argument("--component", required=True)
    q.add_argument("--note", required=True); q.add_argument("--file"); q.add_argument("--line", type=int)
    q.add_argument("--question"); q.add_argument("--by")

    q = sub.add_parser("add-raw-finding"); q.set_defaults(fn=cmd_add_raw_finding)
    q.add_argument("--scan", required=True); q.add_argument("--component", required=True)
    q.add_argument("--type", required=True); q.add_argument("--severity", required=True)
    q.add_argument("--confidence"); q.add_argument("--attack-vector", dest="attack_vector")
    q.add_argument("--cwe-id", dest="cwe_id"); q.add_argument("--cwe-name", dest="cwe_name")
    q.add_argument("--file", required=True); q.add_argument("--line-start", dest="line_start", type=int,
                   help="1-based start line; the report extracts the real code from file:line_start-line_end")
    q.add_argument("--line-end", dest="line_end", type=int); q.add_argument("--code",
                   help="OPTIONAL fallback snippet; normally omit it — the report reads the real source from file+lines")
    q.add_argument("--description"); q.add_argument("--df-source", dest="df_source")
    q.add_argument("--df-sink", dest="df_sink"); q.add_argument("--df-sanitization", dest="df_sanitization")
    q.add_argument("--df-proof", dest="df_proof"); q.add_argument("--hunter")

    q = sub.add_parser("add-council"); q.set_defaults(fn=cmd_add_council)
    q.add_argument("--scan", required=True); q.add_argument("--raw-finding", dest="raw_finding", type=int, required=True)
    q.add_argument("--vote", required=True); q.add_argument("--severity", required=True)
    q.add_argument("--attacker", required=True); q.add_argument("--defender", required=True); q.add_argument("--auditor", required=True)
    q.add_argument("--proven-primitive", dest="proven_primitive", action="store_true")
    q.add_argument("--attack-scenario", dest="attack_scenario"); q.add_argument("--impact")
    q.add_argument("--remediation"); q.add_argument("--rationale")

    q = sub.add_parser("add-chain"); q.set_defaults(fn=cmd_add_chain)
    q.add_argument("--scan", required=True); q.add_argument("--title", required=True)
    q.add_argument("--severity"); q.add_argument("--rationale")

    q = sub.add_parser("add-chain-member"); q.set_defaults(fn=cmd_add_chain_member)
    q.add_argument("--chain", type=int, required=True); q.add_argument("--fingerprint", required=True)
    q.add_argument("--order", type=int); q.add_argument("--gains")

    q = sub.add_parser("promote"); q.set_defaults(fn=cmd_promote); q.add_argument("--scan", required=True)

    q = sub.add_parser("report"); q.set_defaults(fn=cmd_report)
    q.add_argument("--scan", required=True); q.add_argument("--out", required=True); q.add_argument("--json")
    q.add_argument("--source-root", dest="source_root",
                   help="root the finding file paths are relative to (defaults to the scan target_path); "
                        "the Vulnerable code block is extracted verbatim from here")
    q.add_argument("--architecture", help="architecture.json to include in the report")
    q.add_argument("--coverage", help="coverage.json to include in the report")
    q.add_argument("--candidates", help="candidates.json to include as unresolved leads")
    q.add_argument("--comparison", help="optional reference-claim-matrix.json to include in the appendix")
    q.add_argument("--narrative", help="optional report-narrative.json authored from verified scan artifacts")

    q = sub.add_parser("stats"); q.set_defaults(fn=cmd_stats); q.add_argument("--scan", required=True)

    q = sub.add_parser("list-aoi"); q.set_defaults(fn=cmd_list_aoi)
    q.add_argument("--scan", required=True); q.add_argument("--component", required=True); q.add_argument("--json", action="store_true")

    q = sub.add_parser("list-raw"); q.set_defaults(fn=cmd_list_raw)
    q.add_argument("--scan", required=True); q.add_argument("--component", required=True); q.add_argument("--json", action="store_true")

    q = sub.add_parser("list-findings"); q.set_defaults(fn=cmd_list_findings)
    q.add_argument("--scan", required=True); q.add_argument("--json", action="store_true")
    return p


def main():
    args = build_parser().parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
