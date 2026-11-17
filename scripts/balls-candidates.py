#!/usr/bin/env python3
"""Maintain a complete, auditable candidate disposition ledger for one scan."""

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timezone

STATUSES = ("PENDING", "CONFIRMED", "LIKELY", "POSSIBLE", "NEEDS_VALIDATION", "REJECTED", "MERGED")


def now():
    return datetime.now(timezone.utc).isoformat()


def load(path, scan=None):
    if not os.path.exists(path):
        if not scan:
            raise SystemExit("ledger missing; run init first")
        return {"schema": "balls.candidates.v2", "scan": scan, "candidates": []}
    with open(path, encoding="utf-8") as stream:
        data = json.load(stream)
    if data.get("schema") != "balls.candidates.v2":
        raise SystemExit("unsupported ledger schema; expected balls.candidates.v2")
    return data


def save(path, data):
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    data["candidate_count"] = len(data.get("candidates", []))
    fd, temporary = tempfile.mkstemp(prefix=".balls-candidates-", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def find(data, candidate_id):
    for item in data["candidates"]:
        if item["id"] == candidate_id:
            return item
    raise SystemExit("candidate not found: " + candidate_id)


def parse_optional_object(raw, flag):
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit("%s must be valid JSON: %s" % (flag, exc))
    if not isinstance(value, dict):
        raise SystemExit("%s must decode to a JSON object" % flag)
    return value


def cmd_init(args):
    if os.path.exists(args.ledger) and not args.force:
        raise SystemExit("ledger already exists; use --force to replace it")
    save(args.ledger, {"schema": "balls.candidates.v2", "scan": args.scan, "candidates": []})
    print("initialized " + args.ledger)


def cmd_add(args):
    data = load(args.ledger, args.scan)
    if any(item["id"] == args.id for item in data["candidates"]):
        raise SystemExit("duplicate candidate id: " + args.id)
    item = {
        "id": args.id,
        "title": args.title,
        "status": args.status,
        "component": args.component,
        "category": args.category,
        "source_agent": args.source_agent,
        "file": args.file,
        "line_start": args.line_start,
        "line_end": args.line_end,
        "severity": args.severity,
        "confidence": args.confidence,
        "cwe_id": args.cwe_id,
        "source": args.source,
        "sink": args.sink,
        "sanitization": args.sanitization,
        "proof": args.proof,
        "impact": args.impact,
        "remediation": args.remediation,
        "rationale": args.rationale,
        "finding_id": None,
        "duplicate_of": None,
        "created_at": now(),
        "updated_at": now(),
        "history": [{"status": args.status, "at": now(), "rationale": args.rationale}],
    }
    reproduction = parse_optional_object(args.reproduction_json, "--reproduction-json")
    fix_example = parse_optional_object(args.fix_example_json, "--fix-example-json")
    if reproduction is not None:
        item["reproduction"] = reproduction
    if fix_example is not None:
        item["fix_example"] = fix_example
    data["candidates"].append(item)
    save(args.ledger, data)
    print(item["id"])


def cmd_decide(args):
    data = load(args.ledger)
    item = find(data, args.id)
    if args.status == "MERGED" and not args.duplicate_of:
        raise SystemExit("MERGED candidates require --duplicate-of")
    if args.status in ("CONFIRMED", "LIKELY", "POSSIBLE") and not args.finding_id:
        if args.status in ("CONFIRMED", "LIKELY"):
            raise SystemExit(args.status + " candidates require --finding-id")
    if args.status in ("POSSIBLE", "REJECTED", "NEEDS_VALIDATION", "MERGED", "LIKELY", "CONFIRMED") and not args.rationale:
        raise SystemExit(args.status + " candidates require --rationale")
    at = now()
    item.setdefault("history", []).append({"status": args.status, "at": at, "rationale": args.rationale,
                                           "finding_id": args.finding_id, "duplicate_of": args.duplicate_of})
    item.update({"status": args.status, "rationale": args.rationale,
                 "finding_id": args.finding_id, "duplicate_of": args.duplicate_of,
                 "updated_at": at})
    save(args.ledger, data)
    print("%s -> %s" % (item["id"], item["status"]))


def cmd_summary(args):
    data = load(args.ledger)
    counts = {status: 0 for status in STATUSES}
    for item in data["candidates"]:
        counts[item.get("status", "PENDING")] = counts.get(item.get("status", "PENDING"), 0) + 1
    print("scan", data.get("scan", ""))
    print("total", len(data["candidates"]))
    for status in STATUSES:
        if counts[status]:
            print(status, counts[status])


def build_parser():
    parser = argparse.ArgumentParser(prog="balls-candidates")
    sub = parser.add_subparsers(required=True)
    p = sub.add_parser("init")
    p.add_argument("--scan", required=True)
    p.add_argument("--ledger", required=True)
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)
    p = sub.add_parser("add")
    p.add_argument("--ledger", required=True)
    p.add_argument("--scan")
    p.add_argument("--id", required=True)
    p.add_argument("--title", required=True)
    p.add_argument("--component", required=True)
    p.add_argument("--category", required=True)
    p.add_argument("--source-agent", required=True)
    p.add_argument("--status", choices=STATUSES, default="PENDING")
    p.add_argument("--file")
    p.add_argument("--line-start", type=int)
    p.add_argument("--line-end", type=int)
    p.add_argument("--severity", choices=("Critical", "High", "Medium", "Low", "Info"))
    p.add_argument("--confidence", choices=("High", "Medium", "Low"))
    p.add_argument("--cwe-id")
    p.add_argument("--source")
    p.add_argument("--sink")
    p.add_argument("--sanitization")
    p.add_argument("--proof")
    p.add_argument("--impact")
    p.add_argument("--remediation")
    p.add_argument("--rationale")
    p.add_argument("--reproduction-json", help="optional JSON object: preconditions, steps, limitations")
    p.add_argument("--fix-example-json", help="optional JSON object: language, code, notes")
    p.set_defaults(func=cmd_add)
    p = sub.add_parser("decide")
    p.add_argument("--ledger", required=True)
    p.add_argument("--id", required=True)
    p.add_argument("--status", required=True, choices=STATUSES[1:])
    p.add_argument("--rationale")
    p.add_argument("--finding-id")
    p.add_argument("--duplicate-of")
    p.set_defaults(func=cmd_decide)
    p = sub.add_parser("summary")
    p.add_argument("--ledger", required=True)
    p.set_defaults(func=cmd_summary)
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    args.func(args)
