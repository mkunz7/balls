#!/usr/bin/env python3
"""BALLS assembly library (stdlib only).

Shared helpers for the deterministic merge/render pipeline: JSON IO, a compact
JSON-Schema-subset validator (no jsonschema dependency), stable finding
fingerprints, severity ordering, and a tiny dependency-free template renderer
(no jinja2 dependency). Kept stdlib-only so the pipeline runs anywhere Python 3
is available.
"""

import hashlib
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMAS_DIR = os.path.normpath(os.path.join(HERE, "..", "schemas"))
TEMPLATES_DIR = os.path.normpath(os.path.join(HERE, "..", "templates"))

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
CONFIDENCE_ORDER = {"High": 0, "Medium": 1, "Low": 2}
VOTE_ORDER = {"CONFIRMED": 0, "LIKELY": 1, "POSSIBLE": 2, "FALSE_POSITIVE": 3}
VECTOR_ORDER = {"INTERNET": 0, "AUTHENTICATED": 1, "CHAINED": 2, "INTERNAL_NETWORK": 3, "LOCAL_ACCESS": 4}


# --- JSON IO ---

def load_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def dump_json(path, obj):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


# --- Stable fingerprint (dedup / idempotency key) ---

def fingerprint(finding):
    """Deterministic id for a finding: component|cwe|file|startLine|type.

    Independent of description wording so re-scans update in place instead of
    duplicating. Callers should prefer an existing 'fingerprint' field but may
    use this to compute or verify one.
    """
    cwe = finding.get("cwe") or {}
    line = finding.get("line") or {}
    key = "|".join([
        str(finding.get("component", "")).strip().lower(),
        str(cwe.get("id", "")).strip().lower(),
        str(finding.get("file", "")).strip().lower().replace("\\", "/"),
        str(line.get("start", "")),
        str(finding.get("type", "")).strip().lower(),
    ])
    return "fp_" + hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]


# --- Compact JSON-Schema-subset validator ---

_TYPE_CHECKS = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}

_schema_cache = {}


def load_schema(name, schemas_dir=SCHEMAS_DIR):
    """Load a schema file by name (e.g. 'council.schema.json')."""
    path = name if os.path.isabs(name) else os.path.join(schemas_dir, name)
    if path not in _schema_cache:
        _schema_cache[path] = load_json(path)
    return _schema_cache[path]


def validate(instance, schema, schemas_dir=SCHEMAS_DIR, path="$", errors=None):
    """Validate `instance` against `schema`. Returns a list of error strings.

    Supports the subset BALLS uses: type (incl. unions), required, properties,
    items, enum, and $ref to a sibling schema file.
    """
    if errors is None:
        errors = []

    if isinstance(schema, dict) and "$ref" in schema:
        schema = load_schema(schema["$ref"], schemas_dir)

    t = schema.get("type")
    if t is not None:
        types = t if isinstance(t, list) else [t]
        if not any(_TYPE_CHECKS.get(tt, lambda v: False)(instance) for tt in types):
            errors.append("%s: expected type %s, got %s" % (path, t, type(instance).__name__))
            return errors  # structural mismatch — deeper checks are meaningless

    if "enum" in schema and instance not in schema["enum"]:
        errors.append("%s: %r not one of %s" % (path, instance, schema["enum"]))

    if isinstance(instance, dict):
        for req in schema.get("required", []):
            if req not in instance:
                errors.append("%s: missing required property '%s'" % (path, req))
        for key, subschema in schema.get("properties", {}).items():
            if key in instance:
                validate(instance[key], subschema, schemas_dir, "%s.%s" % (path, key), errors)

    if isinstance(instance, list) and "items" in schema:
        for i, item in enumerate(instance):
            validate(item, schema["items"], schemas_dir, "%s[%d]" % (path, i), errors)

    return errors


def validate_or_raise(instance, schema_name, schemas_dir=SCHEMAS_DIR, label=None):
    schema = load_schema(schema_name, schemas_dir)
    errs = validate(instance, schema, schemas_dir)
    if errs:
        where = " (%s)" % label if label else ""
        raise ValueError("Schema validation failed against %s%s:\n  - %s" % (
            schema_name, where, "\n  - ".join(errs)))


# --- Tiny dependency-free template renderer ---
#
# Supports:
#   {{ key }}            scalar substitution (dotted paths: {{ project.name }})
#   {{ key | default }}  fallback when the value is missing/empty
# Repeating blocks are pre-rendered in Python and injected via a scalar token,
# so no loop/if grammar is needed here (keeps it small and unambiguous).

_TOKEN = re.compile(r"\{\{\s*([a-zA-Z0-9_.]+)\s*(?:\|\s*([^}]*?))?\s*\}\}")


def _resolve(ctx, dotted):
    cur = ctx
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def render_template(text, ctx):
    def repl(m):
        key, default = m.group(1), m.group(2)
        val = _resolve(ctx, key)
        if val is None or val == "":
            return default if default is not None else ""
        return str(val)
    return _TOKEN.sub(repl, text)


def load_template(name, templates_dir=TEMPLATES_DIR):
    with open(os.path.join(templates_dir, name), "r", encoding="utf-8") as fh:
        return fh.read()
