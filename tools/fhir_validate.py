#!/usr/bin/env python3
"""Structural FHIR R4 checks for sanitized Bundles (dev and CI only).

Checks the invariants the evaluator's structural validator looks at:
bdl-7 unique fullUrl, bdl-9 document identifier, bdl-10 timestamp, bdl-11 Composition
first, resource types and ids, date/dateTime/instant/base64Binary syntax, and that
every reference resolves inside the Bundle. A local "#id" reference must name a resource
in the "contained" list of the entry resource it sits in ("#" alone is the container).
Regexes are the ones published in the R4 datatypes page
(https://hl7.org/fhir/R4/datatypes.html), applied to the whole value (fullmatch).

Date-typed elements are recognised by name, not by a full schema:
  date      birthDate, valueDate
  instant   lastUpdated, timestamp, any "...Instant" choice (valueInstant,
            effectiveInstant), issued in Observation / DiagnosticReport / Media,
            recorded in Provenance / AuditEvent
  dateTime  any "...DateTime" choice (effectiveDateTime, onsetDateTime,
            abatementDateTime, performedDateTime, occurrenceDateTime, deceasedDateTime,
            ...), date, dateTime, created, creation, authoredOn, recordedDate, authored,
            sent, received, start, end, issued / recorded in other resources and
            ValueSet.expansion.timestamp
An element that is an instant in some resources and a dateTime in others is checked as
a dateTime, which also accepts every valid instant: the heuristic can miss an error but
does not invent one.

Scans *.json, *.fhir and *.geojson under each folder. A file that does not parse as
JSON but mentions "resourceType" counts as a bundle with problems.

    python tools/fhir_validate.py <folder or file> [...]

Last line: "FHIR bundles checked: N, with problems: M" (plus ", unparseable: U").
Exit code 1 when any bundle has problems.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import sys
from pathlib import Path

DATE = re.compile(r"([0-9]([0-9]([0-9][1-9]|[1-9]0)|[1-9]00)|[1-9]000)(-(0[1-9]|1[0-2])(-(0[1-9]|[1-2][0-9]|3[0-1]))?)?")
DATETIME = re.compile(r"([0-9]([0-9]([0-9][1-9]|[1-9]0)|[1-9]00)|[1-9]000)(-(0[1-9]|1[0-2])(-(0[1-9]|[1-2][0-9]|3[0-1])"
                      r"(T([01][0-9]|2[0-3]):[0-5][0-9]:([0-5][0-9]|60)(\.[0-9]+)?(Z|(\+|-)((0[0-9]|1[0-3]):[0-5][0-9]|14:00)))?)?)?")
INSTANT = re.compile(r"([0-9]([0-9]([0-9][1-9]|[1-9]0)|[1-9]00)|[1-9]000)-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])"
                     r"T([01][0-9]|2[0-3]):[0-5][0-9]:([0-5][0-9]|60)(\.[0-9]+)?(Z|(\+|-)((0[0-9]|1[0-3]):[0-5][0-9]|14:00))")
# base64Binary after removing whitespace: groups of 4, padding only at the end. No nested
# quantifiers, so a long invalid value cannot make the regex backtrack.
B64 = re.compile(r"[A-Za-z0-9+/]*={0,2}")
WHITESPACE = re.compile(r"\s+")
ID = re.compile(r"[A-Za-z0-9\-.]{1,64}")
CHECKS = {"date": DATE, "dateTime": DATETIME, "instant": INSTANT}

DATE_KEYS = {"birthDate", "valueDate"}
INSTANT_KEYS = {"lastUpdated", "timestamp", "instant"}
DATETIME_KEYS = {"date", "dateTime", "created", "creation", "authoredOn", "recordedDate", "authored",
                 "sent", "received", "start", "end"}
# elements that are an instant only in some resources (dateTime everywhere else)
INSTANT_IN = {"issued": {"Observation", "DiagnosticReport", "Media"},
              "recorded": {"Provenance", "AuditEvent"}}
# elements that are a dateTime in these resources although INSTANT_KEYS lists them
DATETIME_IN = {"timestamp": {"ValueSet"}}
GENDERS = {"male", "female", "other", "unknown"}
SCAN_PATTERNS = ("*.json", "*.fhir", "*.geojson")


def temporal_kind(key: str, rtype: str | None) -> str | None:
    """FHIR primitive type of a date-like element, or None when the key is not one."""
    if key in INSTANT_IN:
        return "instant" if rtype in INSTANT_IN[key] else "dateTime"
    if key in DATETIME_IN and rtype in DATETIME_IN[key]:
        return "dateTime"
    if key in DATE_KEYS:
        return "date"
    if key in INSTANT_KEYS or key.endswith("Instant"):
        return "instant"
    if key in DATETIME_KEYS or key.endswith("DateTime"):
        return "dateTime"
    return None


def valid_base64(val: str) -> bool:
    s = WHITESPACE.sub("", val)
    if not s or len(s) % 4 or not B64.fullmatch(s):
        return False
    try:
        base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return False
    return True


def _contained_ids(resource: dict) -> set:
    return {c.get("id") for c in resource.get("contained") or []
            if isinstance(c, dict) and isinstance(c.get("id"), str)}


def _walk(node, path, rtype, local, out):
    """Collect (path, value, enclosing resourceType, local ids) for every scalar leaf."""
    if isinstance(node, dict):
        if isinstance(node.get("resourceType"), str):
            rtype = node["resourceType"]
            # a contained resource resolves "#id" against its container's list
            if not (len(path) >= 2 and path[-2] == "contained"):
                local = _contained_ids(node)
        for k, v in node.items():
            _walk(v, path + (k,), rtype, local, out)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _walk(v, path + (i,), rtype, local, out)
    else:
        out.append((path, node, rtype, local))


def validate(bundle: dict) -> list[str]:
    errs: list[str] = []
    if bundle.get("resourceType") != "Bundle":
        return ["not a Bundle"]
    btype = bundle.get("type")
    entries = bundle.get("entry") or []
    if not isinstance(entries, list):
        return ["Bundle.entry must be an array"]
    bad_entries = [i for i, e in enumerate(entries) if not isinstance(e, dict)]
    if bad_entries:
        errs.append(f"{len(bad_entries)} entries are not objects")
    entries = [e for e in entries if isinstance(e, dict)]
    if btype == "document":
        ident = bundle.get("identifier")
        if not (isinstance(ident, dict) and ident.get("system") and ident.get("value")):
            errs.append("bdl-9 document identifier needs system and value")
        if not bundle.get("timestamp"):
            errs.append("bdl-10 document needs a timestamp")
        first = entries[0].get("resource") if entries else None
        if not (isinstance(first, dict) and first.get("resourceType") == "Composition"):
            errs.append("bdl-11 first entry must be a Composition")
    full_urls = [e.get("fullUrl") for e in entries if e.get("fullUrl")]
    if any(not isinstance(u, str) for u in full_urls):
        errs.append("fullUrl must be a string")
        full_urls = [u for u in full_urls if isinstance(u, str)]
    if len(full_urls) != len(set(full_urls)):
        errs.append("bdl-7 fullUrl values must be unique")
    known = set(full_urls)
    for e in entries:
        r = e.get("resource")
        if not isinstance(r, dict):
            errs.append("entry without a resource object")
            continue
        rt, rid = r.get("resourceType"), r.get("id")
        if not isinstance(rt, str) or not rt:
            errs.append("entry without resourceType")
            continue
        if rid is not None and not (isinstance(rid, str) and ID.fullmatch(rid)):
            errs.append(f"{rt}.id invalid")
        if isinstance(rid, str) and rid:
            known.add(f"{rt}/{rid}")
        if rt == "Patient" and "gender" in r:
            g = r["gender"]
            if not isinstance(g, str):
                errs.append("Patient.gender must be a string code")
            elif g not in GENDERS:
                errs.append("Patient.gender not in value set")
    leaves: list = []
    _walk(bundle, (), None, set(), leaves)
    for path, val, rtype, local in leaves:
        key = next((p for p in reversed(path) if isinstance(p, str)), "")
        where = "/".join(map(str, path))
        if not isinstance(val, str):
            continue
        if key == "reference":
            if val.startswith("#"):
                if val != "#" and val[1:] not in local:
                    errs.append(f"unresolved local reference at {where}")
            elif val not in known:
                errs.append(f"unresolved reference at {where}")
            continue
        kind = temporal_kind(key, rtype)
        if kind:
            if not CHECKS[kind].fullmatch(val):
                errs.append(f"invalid {kind} at {where}")
        elif key == "data" and "attachment" in path and not valid_base64(val):
            errs.append(f"invalid base64Binary at {where}")
        elif key == "div" and not (val.startswith("<div") and "xmlns=\"http://www.w3.org/1999/xhtml\"" in val):
            errs.append(f"narrative div must be an xhtml div at {where}")
    return errs


def collect(argv: list[str]) -> list[Path]:
    files: list[Path] = []
    for a in argv or ["."]:
        p = Path(a)
        if p.is_dir():
            found: set[Path] = set()
            for pat in SCAN_PATTERNS:
                found.update(x for x in p.rglob(pat) if x.is_file())
            files += sorted(found)
        else:
            files.append(p)
    return files


def report(f: Path, errs: list[str]) -> None:
    print(f"{f}: {len(errs)} problems")
    for e in errs[:10]:
        print("   ", e)


def main(argv: list[str]) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    bad = checked = unparseable = 0
    for f in collect(argv):
        try:
            raw = f.read_bytes()
        except OSError as exc:
            checked += 1
            bad += 1
            report(f, [f"cannot read file ({exc.__class__.__name__})"])
            continue
        try:
            obj = json.loads(raw.decode("utf-8-sig"))
        except (ValueError, RecursionError) as exc:
            # UnicodeDecodeError is a ValueError; error messages carry positions only
            if "resourceType" in raw.decode("utf-8", errors="replace"):
                checked += 1
                bad += 1
                unparseable += 1
                report(f, [f"mentions resourceType but is not valid UTF-8 JSON ({exc.__class__.__name__})"])
            continue
        if not (isinstance(obj, dict) and obj.get("resourceType") == "Bundle"):
            continue
        checked += 1
        try:
            errs = validate(obj)
        except RecursionError:
            errs = ["Bundle is nested too deeply to check"]
        if errs:
            bad += 1
            report(f, errs)
    tail = f", unparseable: {unparseable}" if unparseable else ""
    print(f"FHIR bundles checked: {checked}, with problems: {bad}{tail}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
