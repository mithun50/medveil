#!/usr/bin/env python3
"""Structural FHIR R4 checks for sanitized Bundles (dev and CI only).

Checks the invariants the evaluator's structural validator looks at:
bdl-7 unique fullUrl, bdl-9 document identifier, bdl-10 timestamp, bdl-11 Composition
first, resource types and ids, date/dateTime/instant/base64Binary syntax, and that
every reference resolves inside the Bundle. Regexes are the ones published in the
R4 datatypes page (https://hl7.org/fhir/R4/datatypes.html).

    python tools/fhir_validate.py <folder or file> [...]
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

DATE = re.compile(r"^([0-9]([0-9]([0-9][1-9]|[1-9]0)|[1-9]00)|[1-9]000)(-(0[1-9]|1[0-2])(-(0[1-9]|[1-2][0-9]|3[0-1]))?)?$")
DATETIME = re.compile(r"^([0-9]([0-9]([0-9][1-9]|[1-9]0)|[1-9]00)|[1-9]000)(-(0[1-9]|1[0-2])(-(0[1-9]|[1-2][0-9]|3[0-1])"
                      r"(T([01][0-9]|2[0-3]):[0-5][0-9]:([0-5][0-9]|60)(\.[0-9]+)?(Z|(\+|-)((0[0-9]|1[0-3]):[0-5][0-9]|14:00)))?)?)?$")
INSTANT = re.compile(r"^([0-9]([0-9]([0-9][1-9]|[1-9]0)|[1-9]00)|[1-9]000)-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])"
                     r"T([01][0-9]|2[0-3]):[0-5][0-9]:([0-5][0-9]|60)(\.[0-9]+)?(Z|(\+|-)((0[0-9]|1[0-3]):[0-5][0-9]|14:00))$")
B64 = re.compile(r"^(\s*([0-9a-zA-Z+/=]){4}\s*)+$")
ID = re.compile(r"^[A-Za-z0-9\-.]{1,64}$")
DATE_KEYS = {"birthDate", "deceasedDate"}
INSTANT_KEYS = {"timestamp", "lastUpdated", "issued", "instant"}
DATETIME_SUFFIX = ("DateTime", "date", "start", "end", "authoredOn", "recorded", "occurrenceDateTime")
GENDERS = {"male", "female", "other", "unknown"}


def _walk(node, path, out):
    if isinstance(node, dict):
        for k, v in node.items():
            _walk(v, path + (k,), out)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _walk(v, path + (i,), out)
    else:
        out.append((path, node))


def validate(bundle: dict) -> list[str]:
    errs: list[str] = []
    if bundle.get("resourceType") != "Bundle":
        return ["not a Bundle"]
    btype = bundle.get("type")
    entries = bundle.get("entry") or []
    if btype == "document":
        ident = bundle.get("identifier") or {}
        if not (ident.get("system") and ident.get("value")):
            errs.append("bdl-9 document identifier needs system and value")
        if not bundle.get("timestamp"):
            errs.append("bdl-10 document needs a timestamp")
        if not entries or (entries[0].get("resource") or {}).get("resourceType") != "Composition":
            errs.append("bdl-11 first entry must be a Composition")
    full_urls = [e.get("fullUrl") for e in entries if e.get("fullUrl")]
    if len(full_urls) != len(set(full_urls)):
        errs.append("bdl-7 fullUrl values must be unique")
    known = set(full_urls)
    for e in entries:
        r = e.get("resource") or {}
        rt, rid = r.get("resourceType"), r.get("id")
        if not isinstance(rt, str) or not rt:
            errs.append("entry without resourceType")
            continue
        if rid is not None and not (isinstance(rid, str) and ID.match(rid)):
            errs.append(f"{rt}.id invalid")
        if rid:
            known.add(f"{rt}/{rid}")
        if rt == "Patient" and "gender" in r and r["gender"] not in GENDERS:
            errs.append("Patient.gender not in value set")
    leaves: list = []
    _walk(bundle, (), leaves)
    for path, val in leaves:
        key = next((p for p in reversed(path) if isinstance(p, str)), "")
        if key == "reference" and isinstance(val, str) and not val.startswith("#"):
            if val not in known:
                errs.append(f"unresolved reference at {'/'.join(map(str, path))}")
        elif key in DATE_KEYS and isinstance(val, str) and not DATE.match(val):
            errs.append(f"invalid date at {'/'.join(map(str, path))}")
        elif key in INSTANT_KEYS and isinstance(val, str) and not INSTANT.match(val):
            errs.append(f"invalid instant at {'/'.join(map(str, path))}")
        elif key.endswith(DATETIME_SUFFIX) and isinstance(val, str) and not DATETIME.match(val):
            errs.append(f"invalid dateTime at {'/'.join(map(str, path))}")
        elif key == "data" and "attachment" in path and isinstance(val, str) and not B64.match(val):
            errs.append(f"invalid base64Binary at {'/'.join(map(str, path))}")
        elif key == "div" and isinstance(val, str) and not (val.startswith("<div") and "xmlns=\"http://www.w3.org/1999/xhtml\"" in val):
            errs.append(f"narrative div must be an xhtml div at {'/'.join(map(str, path))}")
    return errs


def main(argv: list[str]) -> int:
    files = []
    for a in argv or ["."]:
        p = Path(a)
        files += sorted(p.rglob("*.json")) if p.is_dir() else [p]
    bad = checked = 0
    for f in files:
        try:
            obj = json.loads(f.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue
        if not (isinstance(obj, dict) and obj.get("resourceType") == "Bundle"):
            continue
        checked += 1
        errs = validate(obj)
        if errs:
            bad += 1
            print(f"{f}: {len(errs)} problems")
            for e in errs[:10]:
                print("   ", e)
    print(f"FHIR bundles checked: {checked}, with problems: {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
