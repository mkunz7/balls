#!/usr/bin/env python3
"""BALLS SQLite store helper (stdlib only).

Owns the connection policy (WAL + busy_timeout so parallel subagent writers are safe),
schema init, the deterministic `promote` step (dedup -> suppress -> assign BALLS-NNN),
and report rendering from the DB. The balls-db CLI is a thin wrapper over these.
"""

import datetime
import json
import os
import sqlite3
import re

_HERE = os.path.dirname(os.path.abspath(__file__))
import sys
sys.path.insert(0, os.path.join(_HERE, "lib"))
import ballslib as rl  # noqa: E402

SCHEMA_PATH = os.path.normpath(os.path.join(_HERE, "..", "balls-schema.sql"))

# Memory-corruption CWEs — suppressed from the report unless proven_primitive is set.
MEMORY_SAFETY_CWES = {
    "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-134", "CWE-190",
    "CWE-191", "CWE-401", "CWE-415", "CWE-416", "CWE-476", "CWE-787", "CWE-824",
    "CWE-843", "CWE-908",
}
SEV_TAG = {"Critical": "[CRIT]", "High": "[HIGH]", "Medium": "[MED]", "Low": "[LOW]", "Info": "[INFO]"}

OWASP_REFERENCES = {
    "CWE-22": [
        ("OWASP Top 10:2025 A01 — Broken Access Control", "https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/"),
        ("OWASP WSTG-ATHZ-01 — Directory Traversal / File Include", "https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include/"),
        ("OWASP Path Traversal Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Prevention_Cheat_Sheet.html"),
    ],
    "CWE-321": [
        ("OWASP Top 10:2025 A04 — Cryptographic Failures", "https://top10.owasp.org/2025/A04_2025-Cryptographic_Failures/"),
        ("OWASP Secrets Management Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"),
        ("OWASP Session Management Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"),
    ],
    "CWE-352": [
        ("OWASP Top 10:2025 A01 — Broken Access Control (includes CSRF)", "https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/"),
        ("OWASP Cross-Site Request Forgery Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"),
    ],
    "CWE-532": [
        ("OWASP Top 10:2025 A09 — Security Logging and Alerting Failures", "https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/"),
        ("OWASP Logging Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"),
    ],
    "CWE-636": [
        ("OWASP Top 10:2025 A10 — Mishandling of Exceptional Conditions", "https://top10.owasp.org/2025/A10_2025-Mishandling_of_Exceptional_Conditions/"),
        ("OWASP Error Handling Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"),
    ],
    "CWE-918": [
        ("OWASP Top 10:2025 A01 — Broken Access Control (includes SSRF)", "https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/"),
        ("OWASP SSRF Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"),
    ],
    "CWE-79": [
        ("OWASP Top 10:2025 A05 — Injection", "https://top10.owasp.org/2025/A05_2025-Injection/"),
        ("OWASP Cross Site Scripting Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
    ],
    "CWE-204": [
        ("OWASP Top 10:2025 A07 — Authentication Failures", "https://top10.owasp.org/2025/A07_2025-Authentication_Failures/"),
        ("OWASP Authentication Cheat Sheet — generic authentication responses", "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"),
    ],
    "CWE-284": [
        ("OWASP Top 10:2025 A01 — Broken Access Control", "https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/"),
        ("OWASP Authorization Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"),
    ],
    "CWE-400": [
        ("OWASP Top 10:2025 X01 — Lack of Application Resilience (additional risk)", "https://top10.owasp.org/2025/X01_2025-Next_Steps/"),
        ("OWASP Denial of Service Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html"),
    ],
    "CWE-760": [
        ("OWASP Top 10:2025 A04 — Cryptographic Failures", "https://top10.owasp.org/2025/A04_2025-Cryptographic_Failures/"),
        ("OWASP Password Storage Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"),
    ],
}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# --- connection ---

def connect(db_path):
    """Open the DB with the concurrency-safe pragmas. WAL lets many readers run while a
    single writer commits; busy_timeout makes concurrent writers wait-and-retry instead
    of failing, so parallel hunter/investigator inserts never lose rows."""
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path, scan_id, slug=None, remote=None, target_path=None):
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = connect(db_path)
    with open(SCHEMA_PATH, "r", encoding="utf-8") as fh:
        conn.executescript(fh.read())
    conn.execute(
        "INSERT OR IGNORE INTO scans (id, slug, remote, target_path, state, created_at, updated_at) "
        "VALUES (?,?,?,?, 'initializing', ?, ?)",
        (scan_id, slug, remote, target_path, now(), now()),
    )
    conn.commit()
    return conn


def fingerprint_row(component, cwe_id, file, line_start, ftype):
    return rl.fingerprint({
        "component": component, "cwe": {"id": cwe_id}, "file": file,
        "line": {"start": line_start}, "type": ftype,
    })


def _is_memory_safety(cwe_id):
    return str(cwe_id or "").upper().strip() in MEMORY_SAFETY_CWES


# --- promote: council -> findings (deterministic) ---

def promote(conn, scan_id):
    """Rebuild the findings/suppressions/chain-numbering for a scan from council rows.

    Idempotent: safe to re-run. Drops FALSE_POSITIVE (dismissed), suppresses memory-safety
    without a proven primitive, dedups by fingerprint (keeping the most severe), orders,
    and assigns BALLS-NNN. Chains that reference a non-surviving finding are dropped.
    """
    conn.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
    conn.execute("DELETE FROM suppressions WHERE scan_id=?", (scan_id,))

    rows = conn.execute(
        "SELECT c.*, r.fingerprint AS fp, r.component_id AS comp_id, r.type AS r_type, "
        "       r.confidence AS r_conf, r.attack_vector AS r_av, r.cwe_id AS r_cwe_id, "
        "       r.cwe_name AS r_cwe_name, r.file AS r_file, r.line_start AS r_ls, "
        "       r.line_end AS r_le, r.code_snippet AS r_code, r.description AS r_desc, "
        "       r.df_source AS r_src, r.df_sink AS r_sink, r.df_sanitization AS r_san, "
        "       r.df_proof AS r_proof, comp.name AS comp_name "
        "FROM council c "
        "JOIN raw_findings r ON r.id = c.raw_finding_id "
        "JOIN components comp ON comp.id = r.component_id "
        "WHERE c.scan_id=?",
        (scan_id,),
    ).fetchall()

    dismissed = 0
    suppressed = []
    best = {}  # fingerprint -> chosen row dict
    for r in rows:
        if r["council_vote"] == "FALSE_POSITIVE":
            dismissed += 1
            continue
        if _is_memory_safety(r["r_cwe_id"]) and not r["proven_primitive"]:
            suppressed.append((r["fp"], r["comp_name"], r["r_type"], r["r_cwe_id"], r["severity"],
                               "memory-safety finding without a proven exploit primitive"))
            continue
        fp = r["fp"]
        prev = best.get(fp)
        if prev is None or _sev_key(r["severity"], r["r_conf"]) < _sev_key(prev["severity"], prev["r_conf"]):
            best[fp] = r

    survivors = sorted(best.values(), key=lambda r: (
        rl.SEVERITY_ORDER.get(r["severity"], 99),
        rl.CONFIDENCE_ORDER.get(r["r_conf"], 99),
        rl.VOTE_ORDER.get(r["council_vote"], 99),
        rl.VECTOR_ORDER.get(r["r_av"], 99),
        str(r["r_file"] or "").lower(),
        r["r_ls"] or 0,
    ))
    width = max(3, len(str(len(survivors))))
    for i, r in enumerate(survivors, 1):
        conn.execute(
            "INSERT INTO findings (scan_id, component_id, raw_finding_id, council_id, fingerprint, "
            " report_id, component, type, severity, confidence, council_vote, attack_vector, cwe_id, "
            " cwe_name, file, line_start, line_end, code_snippet, description, df_source, df_sink, "
            " df_sanitization, df_proof, attack_scenario, impact, remediation, attacker, defender, "
            " auditor, proven_primitive) "
            "VALUES (?,?,?,?,?, ?,?,?,?,?,?,?,?, ?,?,?,?,?,?,?,?, ?,?,?,?,?,?,?, ?,?)",
            (scan_id, r["comp_id"], r["raw_finding_id"], r["id"], r["fp"],
             "BALLS-" + str(i).zfill(width), r["comp_name"], r["r_type"], r["severity"], r["r_conf"],
             r["council_vote"], r["r_av"], r["r_cwe_id"], r["r_cwe_name"], r["r_file"], r["r_ls"],
             r["r_le"], r["r_code"], r["r_desc"], r["r_src"], r["r_sink"], r["r_san"], r["r_proof"],
             r["attack_scenario"], r["impact"], r["remediation"], r["attacker"], r["defender"],
             r["auditor"], r["proven_primitive"]),
        )
    for s in suppressed:
        conn.execute(
            "INSERT INTO suppressions (scan_id, fingerprint, component, type, cwe_id, severity, reason, created_at) "
            "VALUES (?,?,?,?,?,?,?,?)", (scan_id,) + s + (now(),))

    valid_fps = set(best.keys())
    dangling = _number_chains(conn, scan_id, valid_fps)

    risk = _risk_rating(survivors)
    conn.execute("UPDATE scans SET risk_rating=?, state='reported', updated_at=? WHERE id=?",
                 (risk, now(), scan_id))
    conn.commit()
    return {"findings": len(survivors), "dismissed": dismissed, "suppressed": len(suppressed),
            "dangling_chains": dangling, "risk_rating": risk}


def _sev_key(severity, confidence):
    return (rl.SEVERITY_ORDER.get(severity, 99), rl.CONFIDENCE_ORDER.get(confidence, 99))


def _risk_rating(survivors):
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        if any(r["severity"] == sev and r["council_vote"] in ("CONFIRMED", "LIKELY") for r in survivors):
            return "Informational" if sev == "Info" else sev
    return "None"


def _number_chains(conn, scan_id, valid_fps):
    conn.execute("UPDATE chains SET report_id=NULL WHERE scan_id=?", (scan_id,))
    chains = conn.execute("SELECT * FROM chains WHERE scan_id=? ORDER BY id", (scan_id,)).fetchall()
    keep = []
    dangling = 0
    for ch in chains:
        members = conn.execute("SELECT fingerprint FROM chain_members WHERE chain_id=?", (ch["id"],)).fetchall()
        fps = [m["fingerprint"] for m in members]
        if fps and all(fp in valid_fps for fp in fps):
            keep.append(ch)
        else:
            dangling += 1
    keep.sort(key=lambda c: rl.SEVERITY_ORDER.get(c["combined_severity"], 99))
    cwidth = max(2, len(str(len(keep))))
    for i, ch in enumerate(keep, 1):
        conn.execute("UPDATE chains SET report_id=? WHERE id=?", ("CHAIN-" + str(i).zfill(cwidth), ch["id"]))
    return dangling


# --- report rendering (from DB) ---

def _block_scalar(header, val):
    return "**%s**\n\n%s\n\n" % (header, val) if val else ""


def extract_source(source_root, file, line_start, line_end):
    """Read the exact vulnerable lines from the real file on disk — so the report's code
    block is verbatim source, never LLM-typed text (no code hallucination). Returns a
    line-numbered snippet, or None if the file/lines can't be resolved (caller falls back
    to any stored snippet)."""
    if not file or not line_start:
        return None
    f = str(file).replace("\\", "/")
    candidates = []
    if os.path.isabs(f):
        candidates.append(f)
    if source_root:
        candidates.append(os.path.join(source_root, f))
    candidates.append(f)  # relative to cwd, last resort
    path = next((p for p in candidates if p and os.path.isfile(p)), None)
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return None
    s = max(1, int(line_start))
    e = int(line_end) if line_end else s
    e = max(s, min(e, len(lines)))
    if s > len(lines):
        return None
    width = len(str(e))
    return "\n".join("%*d  %s" % (width, s + i, text) for i, text in enumerate(lines[s - 1:e]))


def _block_code(row, source_root):
    # Prefer the real file contents; the stored snippet is only a fallback when the file
    # can't be read (wrong path / not cloned locally).
    src = extract_source(source_root, row["file"], row["line_start"], row["line_end"])
    if src is None:
        src = row["code_snippet"]
    if src:
        src = _redact_sensitive_literals(src)
    return "**Vulnerable code (before)**\n\n```\n%s\n```\n\n" % src if src else ""


def _redact_sensitive_literals(source):
    """Redact obvious hard-coded credential assignments from report excerpts."""
    pattern = re.compile(
        r'''(?i)^(\s*[^#\n]*?(?:secret|password|token|api[_-]?key|private[_-]?key|credential)[A-Z0-9_]*\s*=\s*)([rubfRUBF]*)(["'])(.*?)(\3)'''
    )
    return "\n".join(
        pattern.sub(lambda m: m.group(1) + m.group(2) + m.group(3) + "[REDACTED]" + m.group(5), line)
        for line in source.splitlines()
    )


def _block_data_flow(row):
    rows = [("Source", row["df_source"]), ("Sink", row["df_sink"]),
            ("Sanitization", row["df_sanitization"]), ("Proof", row["df_proof"])]
    lines = ["- %s: %s" % (label, val) for label, val in rows if val]
    return "**Data flow**\n\n" + "\n".join(lines) + "\n\n" if lines else ""


def _block_perspectives(row):
    rows = [("Attacker", row["attacker"]), ("Defender", row["defender"]), ("Auditor", row["auditor"])]
    lines = ["- %s: %s" % (label, val) for label, val in rows if val]
    return "**Council perspectives**\n\n" + "\n".join(lines) + "\n\n" if lines else ""


def _block_reproduction(details):
    """Render safe, source-supported reproduction steps authored in the narrative."""
    reproduction = details.get("reproduction") if isinstance(details, dict) else None
    if not isinstance(reproduction, dict):
        return "_No safe reproduction steps were established from the available source evidence._"

    lines = []
    preconditions = reproduction.get("preconditions")
    if isinstance(preconditions, str) and preconditions.strip():
        lines.extend(["**Preconditions**", "", preconditions.strip(), ""])

    steps = reproduction.get("steps")
    if isinstance(steps, list):
        for index, step in enumerate(steps, 1):
            if not isinstance(step, dict):
                continue
            action = step.get("action")
            if not isinstance(action, str) or not action.strip():
                continue
            lines.extend(["%d. %s" % (index, action.strip())])
            command = step.get("command")
            if isinstance(command, list):
                command = "\n".join(str(part) for part in command)
            if isinstance(command, str) and command.strip():
                fence = "```"
                while fence in command:
                    fence += "`"
                lines.extend(["", fence + "sh", command.strip(), fence])
            expected = step.get("expected_result")
            if isinstance(expected, str) and expected.strip():
                lines.extend(["", "**Expected result:** %s" % expected.strip()])
            lines.append("")

    limitations = reproduction.get("limitations")
    if isinstance(limitations, str) and limitations.strip():
        lines.extend(["**Limitations:** %s" % limitations.strip(), ""])

    if not lines:
        return "_No safe reproduction steps were established from the available source evidence._"
    lines.extend(["_Run reproduction steps only against an authorized test instance._", ""])
    return "\n".join(lines)


def _block_fixed_code(details):
    """Render an illustrative remediation snippet supplied by the report writer."""
    example = details.get("fix_example") if isinstance(details, dict) else None
    if not isinstance(example, dict):
        return "_No standalone fixed-code example was established; use the remediation steps below._"
    code = example.get("code")
    if not isinstance(code, str) or not code.strip():
        return "_No standalone fixed-code example was established; use the remediation steps below._"
    language = example.get("language")
    if not isinstance(language, str) or not re.fullmatch(r"[A-Za-z0-9_+#.-]{1,20}", language):
        language = ""
    fence = "```"
    while fence in code:
        fence += "`"
    lines = ["```" + language, code.strip(), fence]
    notes = example.get("notes")
    if isinstance(notes, str) and notes.strip():
        lines.extend(["", "**Notes:** %s" % notes.strip()])
    return "\n".join(lines)


def _finding_references(row):
    cwe_id = (row["cwe_id"] or "").upper()
    references = []
    match = re.search(r"(\d+)", cwe_id)
    if match:
        references.append({
            "type": "CWE",
            "label": "%s — %s" % (cwe_id, row["cwe_name"] or "Weakness entry"),
            "url": "https://cwe.mitre.org/data/definitions/%s.html" % match.group(1),
        })
    for label, url in OWASP_REFERENCES.get(cwe_id, []):
        references.append({"type": "OWASP", "label": label, "url": url})
    if cwe_id == "CWE-284" and any(word in (row["type"] or "").lower()
                                     for word in ("signup", "partial", "failure")):
        references.append({
            "type": "OWASP",
            "label": "OWASP Top 10:2025 A10 — Mishandling of Exceptional Conditions",
            "url": "https://top10.owasp.org/2025/A10_2025-Mishandling_of_Exceptional_Conditions/",
        })
    if cwe_id == "CWE-79":
        finding_type = (row["type"] or "").lower()
        if "reflected" in finding_type:
            references.append({
                "type": "OWASP WSTG",
                "label": "WSTG-INPV-01 — Reflected Cross-Site Scripting",
                "url": "https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting/",
            })
        elif "stored" in finding_type:
            references.append({
                "type": "OWASP WSTG",
                "label": "WSTG-INPV-02 — Stored Cross-Site Scripting",
                "url": "https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting/",
            })
    items = ["- **%s:** [%s](%s)" % (ref["type"], ref["label"], ref["url"])
             for ref in references]
    return references, "\n".join(items) if items else "_No mapped standards references were supplied._"


def _lines(row):
    s, e = row["line_start"], row["line_end"]
    if e is None or e == s:
        return str(s)
    return "%s-%s" % (s, e)


def _finding_ctx(row, source_root, narrative=None):
    references, references_block = _finding_references(row)
    cwe_match = re.search(r"(\d+)", row["cwe_id"] or "")
    details = (narrative or {}).get("finding_details", {})
    details = details.get(row["report_id"], {}) if isinstance(details, dict) else {}
    if not isinstance(details, dict):
        details = {}
    remediation_steps = details.get("remediation_steps")
    if isinstance(remediation_steps, list) and remediation_steps:
        remediation_block = "**Remediation steps**\n\n" + "\n".join(
            "%d. %s" % (i, item) for i, item in enumerate(remediation_steps, 1)
            if isinstance(item, str) and item.strip()) + "\n\n"
    else:
        remediation_block = _block_scalar("Remediation", row["remediation"])
    return {
        "id": row["report_id"] or "", "type": row["type"] or "",
        "severity": row["severity"] or "", "sevTag": SEV_TAG.get(row["severity"], ""),
        "confidence": row["confidence"] or "", "vote": row["council_vote"] or "",
        "attack_vector": row["attack_vector"] or "", "component": row["component"] or "",
        "cweId": row["cwe_id"] or "", "cweName": row["cwe_name"] or "",
        "cweUrl": ("https://cwe.mitre.org/data/definitions/%s.html" % cwe_match.group(1)
                   if cwe_match else ""),
        "references": references, "references_block": references_block,
        "file": row["file"] or "", "lines": _lines(row),
        "description": details.get("summary") or row["description"] or "",
        "code_block": _block_code(row, source_root),
        "data_flow_block": _block_data_flow(row),
        "_df_source": row["df_source"], "_df_sink": row["df_sink"],
        "_df_sanitization": row["df_sanitization"], "_df_proof": row["df_proof"],
        "attack_scenario_block": _block_scalar(
            "Attack scenario", details.get("attack_path_and_preconditions") or row["attack_scenario"]),
        "reproduction_block": _block_reproduction(details),
        "fixed_code_block": _block_fixed_code(details),
        "impact_block": _block_scalar(
            "Impact", details.get("impact_and_limits") or row["impact"]),
        "perspectives_block": _block_perspectives(row),
        "remediation_block": remediation_block,
    }


def _artifact(path):
    if not path:
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _mdcell(value):
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")


def _architecture_sections(architecture):
    if not architecture:
        return "_Architecture metadata was not supplied._", "_No component map was supplied._"
    stack = architecture.get("stack") or []
    components = architecture.get("components") or []
    rows = []
    for comp in components:
        rows.append("| %s | %s | %s | %s |" % (
            _mdcell(comp.get("name")), _mdcell(comp.get("type", "")),
            _mdcell(", ".join(comp.get("paths", []))),
            _mdcell(comp.get("description", ""))))
    comp_table = ("| Component | Type | Paths | Description |\n|---|---|---|---|\n" + "\n".join(rows)) \
        if rows else "_No components were recorded._"
    blocks = []
    for comp in components:
        lines = ["### %s" % (comp.get("name") or "Component")]
        for label, key in (("Entry points", "entry_points"), ("Data stores", "data_stores"),
                           ("External services", "external_services"),
                           ("Trust boundaries", "trust_boundaries"),
                           ("Security controls reviewed", "security_controls_to_review")):
            values = comp.get(key) or []
            if values:
                lines.append("\n**%s**\n%s" % (label, "\n".join("- %s" % x for x in values)))
        blocks.append("\n".join(lines))
    extra = []
    if stack:
        extra.append("**Observed stack:** " + ", ".join(str(x) for x in stack))
    cg = architecture.get("codegraph")
    if cg:
        extra.append("**CodeGraph:** %s; %s files, %s nodes, %s edges; state: %s." % (
            cg.get("version", "unknown"), cg.get("files", "?"), cg.get("nodes", "?"),
            cg.get("edges", "?"), cg.get("state", "unknown")))
    return "\n\n".join(extra + [comp_table]), "\n\n".join(blocks) or "_No detailed component notes were supplied._"


def _coverage_sections(coverage):
    if not coverage:
        return "_Coverage metadata was not supplied._", ""
    units = coverage.get("units") or coverage.get("coverage") or []
    rows = []
    counts = {}
    for unit in units:
        status = unit.get("status", "unknown")
        counts[status] = counts.get(status, 0) + 1
        rows.append("| %s | %s | %s | %s | %s | %s |" % (
            _mdcell(unit.get("unit_id", "")), _mdcell(unit.get("component", unit.get("agent_group", ""))),
            _mdcell(unit.get("category")), _mdcell(status), _mdcell(unit.get("assigned_agent", "")),
            _mdcell(unit.get("note", unit.get("guide", "")))))
    table = ("| Unit | Component | Category | Status | Review assignment | Evidence note |\n|---|---|---|---|---|---|\n" + "\n".join(rows)) \
        if rows else "_No coverage units were recorded._"
    assignments = coverage.get("assignments") or []
    assignment_rows = []
    for assignment in assignments:
        assignment_rows.append("| %s | %s | %s | %s | %s |" % (
            _mdcell(assignment.get("assignment_id")), _mdcell(assignment.get("component")),
            _mdcell(assignment.get("role")), _mdcell(assignment.get("status")),
            _mdcell(", ".join(assignment.get("unit_ids", [])))))
    assignment_table = ("**Assignments**\n\n| Assignment | Component | Role | Status | Unit IDs |\n|---|---|---|---|---|\n" +
                       "\n".join(assignment_rows)) if assignment_rows else ""
    counts_text = ", ".join("%s: %d" % (k, counts[k]) for k in sorted(counts))
    execution = coverage.get("execution") or {}
    if not execution and coverage.get("constraints"):
        execution = {"constraints": coverage["constraints"]}
    details = []
    if counts_text:
        details.append("**Coverage status counts:** " + counts_text)
    if execution:
        details.append("**Execution and limits:** " + "; ".join(
            "%s=%s" % (k, v) for k, v in execution.items()))
    return "\n\n".join(details + [table, assignment_table]), ""


def _candidate_sections(candidates):
    if not candidates:
        return "_No unresolved candidates were supplied._", [], "_No candidate dispositions were supplied._"
    items = candidates.get("candidates", []) if isinstance(candidates, dict) else candidates
    open_statuses = {"PENDING", "POSSIBLE", "NEEDS_VALIDATION"}
    unresolved = [item for item in items if str(item.get("status", "NEEDS_VALIDATION")).upper() in open_statuses]
    blocks = []
    for item in unresolved:
        title = item.get("title", "Unresolved candidate")
        if item.get("id"):
            title = "%s — %s" % (item["id"], title)
        loc = item.get("file", "")
        if item.get("line_start"):
            loc += ":%s" % item["line_start"]
            if item.get("line_end") and item["line_end"] != item["line_start"]:
                loc += "-%s" % item["line_end"]
        lines = ["### %s" % title,
                 "- **Status:** %s" % item.get("status", "NEEDS_VALIDATION"),
                 "- **Location:** `%s`" % loc]
        if item.get("component") or item.get("category"):
            lines.append("- **Component / category:** %s / %s" % (
                item.get("component", ""), item.get("category", "")))
        if item.get("source_agent"):
            lines.append("- **Source assignment:** %s" % item["source_agent"])
        for key, label in (("source", "Observed evidence"), ("reason", "Why unresolved"),
                           ("rationale", "Disposition rationale"), ("advisory", "Advisory")):
            if item.get(key):
                lines.append("- **%s:** %s" % (label, item[key]))
        blocks.append("\n".join(lines))
    counts = {}
    for item in items:
        status = str(item.get("status", "PENDING")).upper()
        counts[status] = counts.get(status, 0) + 1
    summary = ["| Disposition | Count |", "|---|---:|"]
    summary.extend("| %s | %d |" % (status, counts[status]) for status in sorted(counts))
    return "\n\n".join(blocks) or "_No unresolved candidates were supplied._", items, "\n".join(summary)


def _remediation_priorities(findings):
    order = ["Critical", "High", "Medium", "Low", "Info"]
    names = {"Critical": "Immediate", "High": "Next", "Medium": "Planned", "Low": "Hardening"}
    blocks = []
    for severity in order:
        subset = [f for f in findings if f["severity"] == severity]
        if not subset:
            continue
        lines = ["### %s priority — %s" % (names.get(severity, severity), severity)]
        for finding in subset:
            lines.append("- **%s — %s** (`%s:%s`): %s" % (
                finding["report_id"], finding["type"], finding["file"], _lines(finding),
                finding["remediation"] or "Remediation guidance not recorded."))
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks) or "_No verified findings to prioritize._"


def _render_data_flows(ctxs):
    blocks = []
    for ctx in ctxs:
        src = ctx.get("_df_source")
        sink = ctx.get("_df_sink")
        if not src or not sink:
            continue
        def label(value):
            value = re.sub(r"[\[\]{}\"`]", "", str(value))
            value = re.sub(r"\s+", " ", value).replace("|", "/")
            return value[:180]
        block = ["### %s — %s" % (ctx["id"], ctx["type"]), "",
                 "```mermaid", "flowchart LR",
                 '  src["Source: %s"] --> sink["Sink: %s"]' % (label(src), label(sink))]
        if ctx.get("_df_sanitization"):
            block.append('  defense["Existing defense: %s"]' % label(ctx["_df_sanitization"]))
        block.append("```")
        if ctx.get("_df_proof"):
            block.extend(["", "**Evidence:** %s" % ctx["_df_proof"]])
        blocks.append("\n".join(block))
    return "\n\n".join(blocks) or "_No verified source-to-sink flows were recorded._"


def _severity_breakdown(findings):
    rows = ["| Severity | Confirmed | Likely | Possible | Total |", "|---|---:|---:|---:|---:|"]
    for severity in ["Critical", "High", "Medium", "Low", "Info"]:
        subset = [f for f in findings if f["severity"] == severity]
        if not subset:
            continue
        counts = {v: sum(1 for f in subset if f["council_vote"] == v)
                  for v in ["CONFIRMED", "LIKELY", "POSSIBLE"]}
        rows.append("| %s | %d | %d | %d | **%d** |" % (
            severity, counts["CONFIRMED"], counts["LIKELY"], counts["POSSIBLE"], len(subset)))
    counts = tuple(sum(1 for f in findings if f["council_vote"] == v)
                   for v in ["CONFIRMED", "LIKELY", "POSSIBLE"])
    rows.append("| **Total** | %d | %d | %d | **%d** |" % (counts + (len(findings),)))
    return "\n".join(rows)


def _group_table(findings, key_fn, title):
    groups = {}
    for f in findings:
        key = key_fn(f) or "Not recorded"
        groups.setdefault(key, []).append(f)
    if not groups:
        return "_No verified findings._"
    rows = ["| %s | Findings | IDs |" % title, "|---|---:|---|"]
    for key in sorted(groups, key=lambda k: (-len(groups[k]), str(k).lower())):
        rows.append("| %s | %d | %s |" % (
            _mdcell(key), len(groups[key]), ", ".join(f["report_id"] for f in groups[key])))
    return "\n".join(rows)


def _finding_index(ctxs):
    rows = []
    for c in ctxs:
        rows.append("| [%s](#%s) | %s | %s | %s | %s | `%s` | %s | %s |" % (
            c["id"], c["id"].lower(), c["severity"], c["attack_vector"], c["type"],
            c["component"], c["file"], c["lines"], c["confidence"]))
    return "\n".join(rows) or "| _none_ | | | | | | | | |"


def _group_detailed_findings(findings, root, narrative=None):
    blocks = []
    for severity in ["Critical", "High", "Medium", "Low", "Info"]:
        subset = [f for f in findings if f["severity"] == severity]
        if not subset:
            continue
        blocks.append("### %s Findings\n\n%s" % (
            severity, "\n\n".join(re.sub(r"\n{3,}", "\n\n", rl.render_template(
                rl.load_template("finding.md.tmpl"), _finding_ctx(f, root, narrative))).rstrip() for f in subset)))
    return "\n\n".join(blocks) or "_No findings._"


def _top_findings(findings):
    top = [f for f in findings if f["severity"] in ("Critical", "High")][:5]
    if not top:
        return "_No Critical or High verified findings._"
    return "\n".join("- **%s — %s** (`%s:%s`): %s" % (
        f["report_id"], f["type"], f["file"], _lines(f), f["impact"] or f["description"])
        for f in top)


def _component_table(architecture, findings):
    components = architecture.get("components", []) if architecture else []
    if not components:
        return "_No component map was supplied._"
    rows = ["| Component | Type | Files / paths | Verified findings | Highest severity |", "|---|---|---|---:|---|"]
    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    for comp in components:
        name = comp.get("name", "")
        related = [f for f in findings if f["component"] == name]
        high = next((s for s in severity_order if any(f["severity"] == s for f in related)), "None")
        rows.append("| %s | %s | %s | %d | %s |" % (
            _mdcell(name), _mdcell(comp.get("type", "")),
            _mdcell(", ".join(comp.get("paths", []))), len(related), high))
    return "\n".join(rows)


def _category_summary(coverage):
    units = (coverage or {}).get("units", [])
    grouped = {}
    for u in units:
        grouped.setdefault(u.get("category", "unknown"), []).append(u)
    rows = ["| Category | Components reviewed | Unit status |", "|---|---:|---|"]
    for category in sorted(grouped):
        comp_names = sorted({u.get("component", "") for u in grouped[category]})
        statuses = sorted({u.get("status", "unknown") for u in grouped[category]})
        rows.append("| %s | %d | %s |" % (_mdcell(category), len(comp_names), _mdcell(", ".join(statuses))))
    return "\n".join(rows) if grouped else "_No category coverage was supplied._"


def _methodology(coverage, architecture):
    execution = (coverage or {}).get("execution", {})
    assignments = (coverage or {}).get("assignments", [])
    graph = (architecture or {}).get("codegraph", {})
    reviewers = sum(1 for a in assignments if a.get("role") == "component-reviewer")
    hunters = sum(1 for a in assignments if a.get("role") == "category-hunter")
    verifier_count = execution.get("independentVerifierAgents", "not recorded")
    initial_groups = execution.get("initialGroupedHunterAssignments", 0)
    category_work = (
        "The initial broad passes were followed by component-scoped category passes."
        if initial_groups else
        "Focused component-scoped category passes were run."
    )
    verification_work = (
        "Independent verifiers checked reachability, defenses, and impact."
        if verifier_count not in (0, "0", None) else
        "No separate fresh verifier agents ran; the coordinator rechecked source evidence."
    )
    component_work = (
        "Focused reviewers traced one component at a time."
        if reviewers else
        "The coordinator and category hunters reviewed the selected components."
    )
    stages = [
        "| Stage | Work performed | Recorded coverage |",
        "|---|---|---|",
        "| Reconnaissance | Repository structure, stack, and local code graph recorded. | %s files; %s graph nodes; graph status %s. |" % (
            graph.get("files", "not recorded"), graph.get("nodes", "not recorded"), graph.get("state", "not recorded")),
        "| Component review | %s | %s component reviewers; %s registered components. |" % (
            component_work,
            reviewers or execution.get("focusedComponentReviewers", "not recorded"),
            len((coverage or {}).get("assignments", [])) and len({u.get("component") for u in (coverage or {}).get("units", [])}) or "not recorded"),
        "| Category hunting | %s | %s initial broad groups; %s component-scoped hunter assignments; %s total units. |" % (
            category_work, initial_groups,
            hunters or execution.get("categoryHunterAssignments", "not recorded"), len((coverage or {}).get("units", []))),
        "| Independent verification | %s | %s verifier assignments. |" % (verification_work, verifier_count),
        "| Model execution | Codex-native reviewers and hunters used the signed-in session. | Direct model API calls: %s; observed concurrency: %s of configured %s. |" % (
            execution.get("directModelApiCalls", "not recorded"), execution.get("maxObservedConcurrentSubagents", "not recorded"),
            execution.get("configuredMaxConcurrentSubagents", "not recorded")),
        "| Report generation | Findings, IDs, counts, source excerpts, indexes, diagrams, and appendices were assembled from scan artifacts. | Deterministic SQLite-backed renderer. |",
    ]
    if graph.get("followupNote"):
        stages.append("\n" + graph["followupNote"])
    return "\n".join(stages)


def _technology_stack(architecture):
    stack = (architecture or {}).get("stack", [])
    return "\n".join("- %s" % item for item in stack) if stack else "_No stack inventory was supplied._"


def _interaction_map(architecture):
    if not architecture:
        return "_No architecture map was supplied._"
    edges = architecture.get("interactions", [])
    if not edges:
        return "_No explicit component interaction edges were recorded._"
    lines = ["```mermaid", "flowchart LR"]
    for node in architecture.get("interaction_nodes", []):
        node_id = re.sub(r"[^A-Za-z0-9_]", "_", node.get("id", "node"))
        label = re.sub(r'[\[\]{}\"]', "", node.get("label", node_id)).replace("|", "/")
        lines.append('  %s["%s"]' % (node_id, label))
    for edge in edges:
        source = re.sub(r"[^A-Za-z0-9_]", "_", edge.get("from", "node"))
        target = re.sub(r"[^A-Za-z0-9_]", "_", edge.get("to", "node"))
        label = re.sub(r'[\[\]{}\"]', "", edge.get("label", "")).replace("|", "/")
        lines.append("  %s -->|%s| %s" % (source, label, target))
    lines.append("```")
    return "\n".join(lines)


def _out_of_scope(architecture):
    values = (architecture or {}).get("out_of_scope", [])
    if not values:
        values = ["External service implementation and runtime configuration not present in the repository.",
                  "Dynamic testing, penetration testing, and dependency installation.",
                  "Infrastructure controls such as proxy, firewall, TLS termination, and WAF settings."]
    return "\n".join("- %s" % x for x in values)


def _cwe_reference(findings):
    unique = {}
    for f in findings:
        if f["cwe_id"]:
            unique[f["cwe_id"]] = f["cwe_name"] or ""
    if not unique:
        return "_No CWE identifiers were recorded._"
    rows = ["| CWE | Name | Reference |", "|---|---|---|"]
    for cwe in sorted(unique):
        number = re.search(r"(\d+)", cwe)
        link = "https://cwe.mitre.org/data/definitions/%s.html" % number.group(1) if number else ""
        rows.append("| %s | %s | [MITRE](%s) |" % (_mdcell(cwe), _mdcell(unique[cwe]), link))
    return "\n".join(rows)


def _glossary():
    return "\n".join([
        "- **Confirmed:** source evidence and attack conditions were independently verified.",
        "- **Likely / Possible:** evidence supports the issue, but one or more material conditions remain uncertain.",
        "- **Needs validation:** a plausible lead remains outside verified totals pending deployment, service, or runtime facts.",
        "- **Attack vector:** where the attacker begins (for example, Internet, authenticated, internal network, or local access).",
        "- **Exploit chain:** a reviewed sequence of findings where one step materially enables the next.",
        "- **CWE:** Common Weakness Enumeration identifier for the underlying weakness.",
    ])


def _comparison_section(comparison):
    if not comparison:
        return "_No reference-claim comparison was supplied._"
    rows = ["| Ref | Claim | Disposition | BALLS finding / candidate | Rationale |",
            "|---|---|---|---|---|"]
    for item in comparison.get("claims", []):
        link = item.get("balls_finding_id") or item.get("candidate_id") or item.get("merged_into") or "—"
        rows.append("| %s | %s | %s | %s | %s |" % (
            _mdcell(item.get("reference_id")), _mdcell(item.get("title")),
            _mdcell(item.get("status")), _mdcell(link), _mdcell(item.get("rationale"))))
    summary = comparison.get("status_counts", {})
    note = "**Claim dispositions:** " + ", ".join("%s: %s" % (k, summary[k]) for k in sorted(summary))
    return note + "\n\n" + "\n".join(rows)


def _narrative_block(narrative, key, fallback):
    """Read a string or paragraph array from an optional Codex-authored narrative."""
    value = (narrative or {}).get(key)
    if isinstance(value, list):
        value = "\n\n".join(part.strip() for part in value if isinstance(part, str) and part.strip())
    if isinstance(value, str) and value.strip():
        return value.strip()
    return fallback


def _executive_summary(scan, architecture, coverage, findings, chains, open_count):
    components = architecture.get("components", []) if architecture else []
    component_names = [c.get("name", "component") for c in components]
    stack = architecture.get("stack", []) if architecture else []
    stack_text = ", ".join(str(x) for x in stack[:4]) or "the recorded application stack"
    bysev = {severity: sum(1 for f in findings if f["severity"] == severity)
             for severity in rl.SEVERITY_ORDER}
    verdicts = {status: sum(1 for f in findings if f["council_vote"] == status)
                for status in ("CONFIRMED", "LIKELY", "POSSIBLE")}
    risk = scan["risk_rating"] or "None"
    components_text = ", ".join(component_names) if component_names else "the recorded application components"
    units = len((coverage or {}).get("units", []))
    paragraph1 = (
        "A static source security assessment was conducted against **%s**, covering %s. "
        "The review mapped %d components (%s) and assessed %d component-by-category work units. "
        "The overall risk rating is **%s**, based on the verified findings and recorded attack paths."
    ) % (scan["slug"] or scan["id"], stack_text, len(component_names), components_text, units, risk)

    ranked = sorted(findings, key=lambda f: (rl.SEVERITY_ORDER.get(f["severity"], 9),
                                              rl.VOTE_ORDER.get(f["council_vote"], 9), f["report_id"]))
    risk_items = []
    for finding in ranked[:4]:
        impact = finding["impact"] or finding["description"] or "Impact requires additional context."
        risk_items.append("**%s — %s**: %s" % (finding["report_id"], finding["type"], impact))
    risk_text = "; ".join(risk_items) if risk_items else "No findings were promoted from the reviewed source."
    chain_text = (" The review also documented %d exploit chain%s: %s." % (
        len(chains), "s" if len(chains) != 1 else "",
        "; ".join(c["title"] for c in chains[:3]))) if chains else " No multi-finding exploit chain was validated."
    paragraph2 = (
        "The report contains **%d findings**: %d Critical, %d High, %d Medium, %d Low, and %d Info; "
        "%d are Confirmed and %d are Likely. The most significant source-backed risks include %s.%s"
    ) % (len(findings), bysev.get("Critical", 0), bysev.get("High", 0), bysev.get("Medium", 0),
         bysev.get("Low", 0), bysev.get("Info", 0), verdicts["CONFIRMED"], verdicts["LIKELY"],
         risk_text, chain_text)

    high_findings = [f for f in ranked if f["severity"] in ("Critical", "High")]
    actions = []
    for finding in high_findings[:4]:
        if finding["remediation"]:
            actions.append("**%s:** %s" % (finding["report_id"], finding["remediation"]))
    action_text = " ".join(actions) if actions else "Prioritize the highest-severity findings listed below."
    paragraph3 = (
        "Immediate work should address the highest-severity findings: %s "
        "There are **%d unresolved candidates** outside the verified totals; their deployment, service, or runtime assumptions are listed separately. "
        "This assessment is static: the target and dependencies were not executed or installed, so behavior that depends on external services or production controls remains unverified."
    ) % (action_text, open_count)
    return "\n\n".join((paragraph1, paragraph2, paragraph3))


def _component_overviews(narrative, architecture, findings):
    components = architecture.get("components", []) if architecture else []
    summaries = (narrative or {}).get("component_summaries", {})
    if not isinstance(summaries, dict):
        summaries = {}
    rows = ["| Component | Assessment summary |", "|---|---|"]
    for component in components:
        name = component.get("name", "")
        related = [f for f in findings if f["component"] == name]
        summary = summaries.get(name)
        if not isinstance(summary, str) or not summary.strip():
            if related:
                ids = ", ".join(f["report_id"] for f in related)
                high = sum(1 for f in related if f["severity"] in ("Critical", "High"))
                summary = "%d reported finding(s): %s; %d Critical/High." % (len(related), ids, high)
            else:
                summary = "No finding was promoted for this component; see unresolved candidates and coverage notes for remaining uncertainty."
        rows.append("| %s | %s |" % (_mdcell(name), _mdcell(summary)))
    return "\n".join(rows) if components else "_No component summaries were supplied._"


def build_report(conn, scan_id, source_root=None, architecture_path=None,
                 coverage_path=None, candidates_path=None, comparison_path=None,
                 narrative_path=None):
    """Return (markdown, data_dict) rendered deterministically from the DB. The
    "Vulnerable code" block is extracted from real source under source_root (defaults to
    the scan's target_path)."""
    scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    root = source_root or (scan["target_path"] if scan else None)
    findings = conn.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY report_id", (scan_id,)).fetchall()
    suppressed = conn.execute("SELECT * FROM suppressions WHERE scan_id=?", (scan_id,)).fetchall()
    dismissed = conn.execute(
        "SELECT COUNT(*) n FROM council WHERE scan_id=? AND council_vote='FALSE_POSITIVE'", (scan_id,)
    ).fetchone()["n"]
    raw_count = conn.execute("SELECT COUNT(*) n FROM raw_findings WHERE scan_id=?", (scan_id,)).fetchone()["n"]
    chains = conn.execute(
        "SELECT * FROM chains WHERE scan_id=? AND report_id IS NOT NULL ORDER BY report_id", (scan_id,)
    ).fetchall()
    architecture = _artifact(architecture_path)
    coverage = _artifact(coverage_path)
    candidates = _artifact(candidates_path)
    comparison = _artifact(comparison_path)
    narrative = _artifact(narrative_path)
    if narrative_path and not isinstance(narrative, dict):
        raise ValueError("report narrative must be a JSON object")
    if narrative_path:
        if narrative.get("schema") != "balls.report-narrative.v1":
            raise ValueError("unsupported narrative schema; expected balls.report-narrative.v1")
        if narrative.get("scan") != scan_id:
            raise ValueError("narrative scan ID does not match requested scan")

    bysev = {s: 0 for s in rl.SEVERITY_ORDER}
    for f in findings:
        bysev[f["severity"]] = bysev.get(f["severity"], 0) + 1
    sev_rows = "\n".join("| %s | %d |" % (s, bysev.get(s, 0))
                         for s in ["Critical", "High", "Medium", "Low", "Info"])

    ctxs = [_finding_ctx(f, root) for f in findings]  # one file read per finding
    summary = _finding_index(ctxs)
    detailed = _group_detailed_findings(findings, root, narrative)

    if chains:
        ch_tmpl = rl.load_template("chain.md.tmpl")
        chains_md = "\n\n".join(rl.render_template(ch_tmpl, _chain_ctx(conn, c)).rstrip() for c in chains)
    else:
        chains_md = "_No multi-finding exploit chains were identified._"

    architecture_summary, component_map = _architecture_sections(architecture)
    coverage_md, _ = _coverage_sections(coverage)
    candidates_md, candidate_items, candidate_dispositions = _candidate_sections(candidates)
    open_statuses = {"PENDING", "POSSIBLE", "NEEDS_VALIDATION"}
    open_candidate_count = sum(1 for item in candidate_items
                               if str(item.get("status", "NEEDS_VALIDATION")).upper() in open_statuses)
    architecture_json = architecture or {}
    coverage_json = coverage or {}
    confidence_counts = {}
    vote_counts = {}
    for finding in findings:
        confidence_counts[finding["confidence"] or "Unknown"] = confidence_counts.get(
            finding["confidence"] or "Unknown", 0) + 1
        vote_counts[finding["council_vote"] or "Unknown"] = vote_counts.get(
            finding["council_vote"] or "Unknown", 0) + 1
    confidence_md = ", ".join("%s: %d" % (k, confidence_counts[k]) for k in sorted(confidence_counts)) or "None"
    vote_md = ", ".join("%s: %d" % (k, vote_counts[k]) for k in sorted(vote_counts)) or "None"

    key_stats = "\n".join([
        "| Metric | Value |", "|---|---:|",
        "| Components analyzed | %d |" % len((architecture or {}).get("components", [])),
        "| Component/category work units | %d |" % len((coverage or {}).get("units", [])),
        "| Raw hunter findings | %d |" % raw_count,
        "| Candidate ledger records | %d |" % len(candidate_items),
        "| Reported findings after review | %d |" % len(findings),
        "| Needs-validation candidates | %d |" % open_candidate_count,
        "| False positives dismissed | %d |" % dismissed,
        "| Suppressed findings | %d |" % len(suppressed),
        "| Exploit chains | %d |" % len(chains),
    ])
    executive = _narrative_block(narrative, "executive_summary",
                                 _executive_summary(scan, architecture, coverage, findings, chains,
                                                    open_candidate_count))
    scope_fallback = (
        "The review covered **%d components** (%s), with a recorded stack of %s and **%d component-by-category work units**. "
        "It was a static source review; the application and its dependencies were not executed or installed."
    ) % (len((architecture or {}).get("components", [])),
         ", ".join(c.get("name", "component") for c in (architecture or {}).get("components", [])) or "none recorded",
         ", ".join(str(x) for x in (architecture or {}).get("stack", [])[:5]) or "not recorded",
         len((coverage or {}).get("units", [])))
    scope_summary = _narrative_block(narrative, "scope_summary", scope_fallback)
    execution = (coverage or {}).get("execution") or {}
    method_fallback = (
        "The scan mapped the source structure, reviewed each component, hunted assigned weakness classes, and independently assessed candidates. "
        "It recorded %d component reviewers, %d category-hunter assignments, and %s verifier agents; direct model API calls: %s."
    ) % (execution.get("focusedComponentReviewers", 0), execution.get("categoryHunterAssignments", 0),
         execution.get("independentVerifierAgents", "not recorded"),
         execution.get("directModelApiCalls", "not recorded"))
    methodology_summary = _narrative_block(narrative, "methodology_summary", method_fallback)
    counts_by_component = {}
    for finding in findings:
        counts_by_component.setdefault(finding["component"] or "unassigned", []).append(finding)
    component_counts = "; ".join("%s: %d finding(s)" % (name, len(items))
                                  for name, items in sorted(counts_by_component.items())) or "no findings were promoted"
    findings_fallback = (
        "The verified set contains %d finding(s): %s. Severity and attack-vector indexes below show their distribution; "
        "the detailed entries include source evidence, impact, and remediation."
    ) % (len(findings), component_counts)
    findings_overview = _narrative_block(narrative, "findings_overview", findings_fallback)
    if chains:
        chain_fallback = "The review documented %d exploit chain(s): %s. Each chain below records the linked findings and the security impact gained at each step." % (
            len(chains), "; ".join(c["title"] for c in chains))
    else:
        chain_fallback = "No multi-finding exploit chains were validated from the available source evidence."
    chain_overview = _narrative_block(narrative, "chain_overview", chain_fallback)
    unresolved_items = [item for item in candidate_items
                        if str(item.get("status", "NEEDS_VALIDATION")).upper() in open_statuses]
    candidate_titles = "; ".join(item.get("title", "Untitled lead") for item in unresolved_items[:4])
    candidate_fallback = (
        "%d open candidate(s) remain outside the verified totals. They concern source paths whose practical impact or exploitability depends on deployment, external-service, or runtime evidence%s."
    ) % (open_candidate_count, (": " + candidate_titles) if candidate_titles else "")
    candidate_overview = _narrative_block(narrative, "candidate_overview", candidate_fallback)
    high_findings = [f for f in findings if f["severity"] in ("Critical", "High")]
    priority_actions = ["**%s:** %s" % (f["report_id"], f["remediation"])
                       for f in high_findings[:3] if f["remediation"]]
    remediation_fallback = (
        "Address Critical/High findings first, then complete the Medium and Low hardening items below. "
        "The first actions are %s."
    ) % (" ".join(priority_actions) if priority_actions else "the highest-severity remediation items listed below")
    remediation_overview = _narrative_block(narrative, "remediation_overview", remediation_fallback)
    component_overviews = _component_overviews(narrative, architecture or {}, findings)
    raw_validated = "\n".join([
        "| Pipeline stage | Count | Meaning |", "|---|---:|---|",
        "| Raw findings | %d | Candidate reports entered by hunters before deterministic deduplication. |" % raw_count,
        "| Candidate ledger records | %d | Hypotheses and verified/merged dispositions retained for audit. |" % len(candidate_items),
        "| Promoted findings | %d | Independently dispositioned rows included in the report. |" % len(findings),
        "| Confirmed | %d | Independently supported findings promoted to the report. |" % vote_counts.get("CONFIRMED", 0),
        "| Likely | %d | Promoted with one stated unresolved assumption. |" % vote_counts.get("LIKELY", 0),
        "| Possible | %d | Unpromoted leads retained in the candidate ledger. |" % vote_counts.get("POSSIBLE", 0),
        "| Needs validation | %d | Separate leads excluded from verified totals. |" % open_candidate_count,
        "| False positives | %d | Rejected by verification. |" % dismissed,
        "| Final unique findings | %d | Verified findings after deduplication. |" % len(findings),
    ])
    scope_constraints = (architecture or {}).get("execution_constraints", {})
    limitations = [
        "- Static source review only; target code and dependencies were not executed or installed.",
        "- CodeGraph was installed during follow-up; earlier assignments used direct source inspection and later resource-exhaustion hunters used graph queries.",
        "- External employee-directory behavior, deployment logging, proxy controls, and runtime credentials are not established by the source.",
        "- Confirmed findings and needs-validation candidates are reported separately.",
    ]
    tech = _technology_stack(architecture)
    component_table = _component_table(architecture, findings)
    category_summary = _category_summary(coverage)
    data_flows = _render_data_flows(ctxs)
    cwe_reference = _cwe_reference(findings)
    out_of_scope = _out_of_scope(architecture)
    scan_metadata = "\n".join([
        "- **Scan ID:** `%s`" % scan_id,
        "- **Target:** `%s`" % (scan["target_path"] or "not recorded"),
        "- **Raw findings:** %d; **reported findings:** %d; **unresolved candidates:** %d; **candidate ledger records:** %d." % (
            raw_count, len(findings), open_candidate_count, len(candidate_items)),
        "- **CodeGraph:** %s." % json.dumps((architecture or {}).get("codegraph", {}), ensure_ascii=False),
        "- **Execution constraints:** %s." % json.dumps(scope_constraints, ensure_ascii=False),
        "- **Coverage assignments:** %d; **independent verifier assignments:** %s; **direct model API calls:** %s." % (
            len((coverage or {}).get("assignments", [])),
            (coverage or {}).get("execution", {}).get("independentVerifierAgents", "not recorded"),
            (coverage or {}).get("execution", {}).get("directModelApiCalls", "not recorded")),
    ])
    architecture_text = json.dumps(architecture or {}, indent=2, ensure_ascii=False)

    ctx = {
        "project": {"name": scan["slug"] or scan["id"], "remote": scan["remote"],
                    "targetPath": scan["target_path"]},
        "scanId": scan_id, "candidateCount": open_candidate_count,
        "generatedAt": now(), "riskRating": scan["risk_rating"] or "None",
        "total": len(findings), "dismissed": dismissed, "suppressed": len(suppressed),
        "SEVERITY_TABLE": sev_rows, "FINDINGS_SUMMARY": summary,
        "DETAILED_FINDINGS": detailed, "CHAINS": chains_md,
        "CONFIDENCE_COUNTS": confidence_md, "VERDICT_COUNTS": vote_md,
        "COMPONENT_SUMMARY": architecture_summary, "COMPONENT_MAP": component_map,
        "COVERAGE": coverage_md, "CANDIDATES": candidates_md,
        "CANDIDATE_DISPOSITIONS": candidate_dispositions,
        "REMEDIATION_PRIORITIES": _remediation_priorities(findings),
        "executiveSummary": executive, "KEY_STATISTICS": key_stats,
        "TOP_FINDINGS": _top_findings(findings), "METHODOLOGY": _methodology(coverage, architecture),
        "SCOPE_SUMMARY": scope_summary, "METHODOLOGY_SUMMARY": methodology_summary,
        "FINDINGS_OVERVIEW": findings_overview, "CHAIN_OVERVIEW": chain_overview,
        "CANDIDATE_OVERVIEW": candidate_overview, "REMEDIATION_OVERVIEW": remediation_overview,
        "COMPONENT_OVERVIEWS": component_overviews,
        "COMPONENT_TABLE": component_table, "CATEGORY_SUMMARY": category_summary,
        "RAW_VALIDATED_TABLE": raw_validated, "LIMITATIONS": "\n".join(limitations),
        "TECHNOLOGY_STACK": tech, "INTERACTION_MAP": _interaction_map(architecture),
        "OUT_OF_SCOPE": out_of_scope, "BY_SEVERITY": _severity_breakdown(findings),
        "BY_ATTACK_VECTOR": _group_table(findings, lambda f: f["attack_vector"], "Attack vector"),
        "BY_COMPONENT": _group_table(findings, lambda f: f["component"], "Component"),
        "BY_CWE": _group_table(findings, lambda f: "%s — %s" % (f["cwe_id"], f["cwe_name"]), "CWE"),
        "DATA_FLOW_DIAGRAMS": data_flows, "APPENDIX_ARCHITECTURE": component_table,
        "SCAN_METADATA": scan_metadata, "CWE_REFERENCE": cwe_reference,
        "GLOSSARY": _glossary(), "ARCHITECTURE_JSON": architecture_text,
        "REFERENCE_COMPARISON": _comparison_section(comparison),
    }
    md = rl.render_template(rl.load_template("report.md.tmpl"), ctx)
    data = {
        "schema": "balls.report.v1", "scan": scan_id, "generatedAt": ctx["generatedAt"],
        "riskRating": ctx["riskRating"],
        "stats": {"total": len(findings), "raw": raw_count, "needsValidation": open_candidate_count, "candidateLedgerTotal": len(candidate_items), "bySeverity": bysev, "dismissed": dismissed,
                  "suppressed": len(suppressed), "byConfidence": confidence_counts,
                  "byVerdict": vote_counts},
        "architecture": architecture_json, "coverage": coverage_json,
        "candidates": candidate_items,
        "candidateSummary": {status: sum(1 for item in candidate_items if str(item.get("status", "PENDING")).upper() == status)
                              for status in sorted({str(item.get("status", "PENDING")).upper() for item in candidate_items})},
        "referenceComparison": comparison or {}, "narrative": narrative or {},
        "findings": [{**dict(f), "references": _finding_references(f)[0]} for f in findings],
        "suppressed": [dict(s) for s in suppressed],
        "chains": [_chain_data(conn, c) for c in chains],
    }
    return md, data


def _chain_ctx(conn, ch):
    members = conn.execute(
        "SELECT cm.*, f.report_id AS rid FROM chain_members cm "
        "LEFT JOIN findings f ON f.scan_id=? AND f.fingerprint=cm.fingerprint "
        "WHERE cm.chain_id=? ORDER BY cm.step_order", (ch["scan_id"], ch["id"])
    ).fetchall()
    ids = ", ".join(m["rid"] or m["fingerprint"] for m in members)
    steps = "\n".join("%d. %s" % (i, m["gains"] or "") for i, m in enumerate(members, 1))
    return {"id": ch["report_id"] or "", "title": ch["title"] or "",
            "combined_severity": ch["combined_severity"] or "", "findings": ids,
            "steps": steps, "rationale": ch["rationale"] or ""}


def _chain_data(conn, ch):
    members = conn.execute("SELECT * FROM chain_members WHERE chain_id=? ORDER BY step_order", (ch["id"],)).fetchall()
    return {"id": ch["report_id"], "title": ch["title"], "combined_severity": ch["combined_severity"],
            "rationale": ch["rationale"], "members": [dict(m) for m in members]}
