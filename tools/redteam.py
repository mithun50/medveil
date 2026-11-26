#!/usr/bin/env python3
r"""Dev-only red-team attacker for the Secret Wards privacy project.

This is a faithful re-implementation of the A1-A7 attacks described in the
toolkit's docs/ATTACKS.md, scored like docs/SCORING.md section 3 ("Privacy
attack arena"). It is a practice / self-assessment tool only. It never touches
the medveil pipeline package, writes nothing on disk except an optional --json
result, uses only the Python standard library, needs no network, and is
deterministic.

What it does
------------
It reads the hidden-seed answer key (dev/truth/truth.json), the attacker's
auxiliary knowledge (dev/attacker/registry.csv and known_facts.jsonl) and then
runs the registry-based re-identification attacks against:
  * the RAW input (dev/input) - the normalisation denominator, and
  * your sanitised release folder (--output).
Each relative component risk is "ours / raw", so the number means "how much of
the attack surface you removed". The overall risk is the published weighted mean
and the estimated privacy sub-score is 25 * (1 - risk).

Usage (PowerShell 7 on Windows; set UTF-8 first)
------------------------------------------------
  $env:PYTHONIOENCODING = "utf-8"
  .\.venv\Scripts\python.exe tools/redteam.py --output out_rt_a `
      [--other out_rt_b] [--kit ..\Secret-Wards-ToolKit] [--json result.json]

  # sanity check: attack the raw input as if it were the submission
  .\.venv\Scripts\python.exe tools/redteam.py --output out_rt_a --raw

Flags
-----
  --output   the sanitised release folder to attack (required)
  --other    a second release built with a different RAKSHA_SECRET, enables A7
  --kit      path to the toolkit (default ..\Secret-Wards-ToolKit)
  --json     write the full numeric result to this JSON file
  --raw      report the raw-input attack as "ours" (ratios become 1.0); use it
             to confirm the raw baseline matches dev/truth/raw_attack.json

Dev-only. Do not ship. Plain ASCII only, hyphen '-' never a dash.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import re
import unicodedata
from collections import defaultdict
from datetime import date, timedelta
from pathlib import Path


# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------

def norm(s: str) -> str:
    """NFKC + casefold + whitespace collapse, the scorer's normalisation."""
    return " ".join(unicodedata.normalize("NFKC", str(s)).casefold().split())


def digits_only(s: str) -> str:
    return re.sub(r"\D", "", s)


def decode_input(b: bytes) -> str:
    """Decode a raw input file: utf-8-sig, utf-16 (BOM), cp1252 fallback."""
    if b[:3] == b"\xef\xbb\xbf":
        return b[3:].decode("utf-8", "replace")
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return b.decode("utf-16", "replace")
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("cp1252", "replace")


def decode_output(b: bytes) -> str:
    return b.decode("utf-8-sig", "replace")


def json_pointer(obj, pointer: str):
    """Resolve an RFC-6901 JSON pointer; return (ok, value)."""
    cur = obj
    for raw in pointer.split("/")[1:]:
        tok = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, list):
            try:
                cur = cur[int(tok)]
            except (ValueError, IndexError):
                return False, None
        elif isinstance(cur, dict):
            if tok not in cur:
                return False, None
            cur = cur[tok]
        else:
            return False, None
    return True, cur


# ----------------------------------------------------------------------------
# Evidence extraction (generic, format-aware), as in ATTACKS.md
# ----------------------------------------------------------------------------

MONTHS = {m: i for i, m in enumerate(
    ["january", "february", "march", "april", "may", "june", "july", "august",
     "september", "october", "november", "december"], start=1)}
MONTHS.update({m[:3]: i for m, i in list(MONTHS.items())})

# ages: only in age forms, never history durations or lab reference ranges.
# \u0935\u0930\u094d\u0937 = "varsh" (years), \u0938\u093e\u0932 = "saal" (years),
# \u0909\u092e\u094d\u0930 = "umar", \u0906\u092f\u0941 = "aayu".
_AGE_LABELS = r"age|age[ _]?sex|umar|\u0909\u092e\u094d\u0930|\u0906\u092f\u0941|janm"
_YR = r"yrs?|years?|\u0935\u0930\u094d\u0937|\u0938\u093e\u0932"
RE_BAND_LABEL = re.compile(r"(?:" + _AGE_LABELS + r")[\"'\s:\-]{0,8}?(\d{1,3})\s*[-\u2013]\s*(\d{1,3})", re.I)
RE_BAND_UNIT = re.compile(r"(?<![\d.])(\d{1,3})\s*[-\u2013]\s*(\d{1,3})\s*(?:" + _YR + r"|/\s*[mf])", re.I)
RE_BRACKET = re.compile(r"\[\s*(\d{1,3})\s*,\s*(\d{1,3})\s*[\)\]]")
RE_PLUS = re.compile(r"(?<![\d.])(\d{1,3})\+")
RE_AGE_SEX = re.compile(r"(?<![\d.])(\d{1,3})\s*/\s*[MFmf]\b")
RE_AGE_UNIT_SEX = re.compile(r"(?<![\d.])(\d{1,3})\s*(?:" + _YR + r")\s*/\s*[MFmf]", re.I)
RE_AGE_HINDI = re.compile(r"(?<![\d.])(\d{1,3})\s*(?:\u0935\u0930\u094d\u0937|\u0938\u093e\u0932)")
RE_AGE_LABEL = re.compile(r"(?:" + _AGE_LABELS + r")[\"'\s:\-]{0,4}?(\d{1,3})(?!\s*[-\u2013+/\d])", re.I)
RE_AGE_YRS = re.compile(r"(?<![\d.])(\d{1,3})\s*(?:" + _YR + r")\b", re.I)  # guarded against "x 9 yrs"

RE_PHONE = re.compile(r"(?<!\d)(?:\+?91[\-\s]?)?([6-9]\d[\-\s]?\d{4}[\-\s]?\d{4}|[6-9]\d{9})(?!\d)")
RE_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
RE_AADHAAR_MASK = re.compile(r"(?:[xX*\u00d7]{2,}[\s\-]*){2,}(\d{4})(?!\d)")
RE_AADHAAR_FULL = re.compile(r"(?<!\d)(\d{4}[\s\-]?\d{4}[\s\-]?\d{4})(?!\d)")
RE_PIN = re.compile(r"(?<!\d)([1-9]\d{5})(?!\d)")
RE_PIN_PREFIX = re.compile(r"(?<!\d)([1-9]\d{2})\s*\*{2,3}")
RE_HOUSE = re.compile(
    r"(?:h\.?\s*no\.?|house|makan\s*no\.?|\u092e\u0915\u093e\u0928\s*\u0928\u0902?\.?)\s*[:\-]?\s*(\d{1,5})", re.I)
RE_REL = re.compile(r"\b([SDWCsdwc])\s*[/.]\s*[OolL0]\b[\s.:]*([^,\n]{0,40})")

RE_DATE_NUM = re.compile(r"(?<!\d)(\d{1,4})[/.\-](\d{1,2})[/.\-](\d{2,4})(?!\d)")
RE_DATE_TXT = re.compile(
    r"\b(\d{1,2})\s+([A-Za-z]{3,9})\b|\b([A-Za-z]{3,9})\s+(\d{1,2})\b")
RE_REF = re.compile(r"\b([A-Z]{2,}[0-9]*[-/][0-9A-Z][0-9A-Z/\-]*\d)\b")
RE_PSN = re.compile(r"\bPSN-[A-Z0-9]{4,}\b")
RE_WORD = re.compile(r"[A-Za-z]+")

# location anchors: a gazetteer name counts as district/tehsil/village evidence
# only when it follows an address-style anchor, so that a hospital's own city in a
# header line ("... HOSPITAL, LUCKNOW") does not masquerade as the patient's district.
RE_LOC_ANCHOR = re.compile(
    r"(distt|dist|district|jila|\u091c\u093f\u0932\u093e|city|zip|\bpin\b|pincode|pin code|"
    r"tehsil|\bteh\b|\u0924\u0939\u0938\u0940\u0932|gram|gaon|\u0917\u093e\u0902\u0935|\u0917\u093e\u0901\u0935|"
    r"village|vill|mohalla|\u092e\u094b\u0939\u0932\u094d\u0932\u093e|pata|\u092a\u0924\u093e|address|addr)",
    re.I)


def anchored_locations(ntext: str, vocab):
    """Find district/tehsil/village gazetteer names near address anchors."""
    found = {"districts": set(), "tehsils": set(), "villages": set()}
    for m in RE_LOC_ANCHOR.finditer(ntext):
        window = ntext[m.end():m.end() + 45]
        for d in vocab["districts"]:
            if d in window:
                found["districts"].add(d)
        for t in vocab["tehsils"]:
            if t in window:
                found["tehsils"].add(t)
        for v in vocab["villages"]:
            if v in window:
                found["villages"].add(v)
    return found


def plausible_age(a: int) -> bool:
    return 0 < a <= 120


def plausible_band(lo: int, hi: int) -> bool:
    return 0 < lo < hi <= 120 and (hi - lo) <= 60


def _add_band(ranges, lo, hi):
    if plausible_band(lo, hi):
        ranges.append((lo, hi))


def parse_age_ranges(text: str):
    ranges = []
    for m in RE_BRACKET.finditer(text):
        _add_band(ranges, int(m.group(1)), int(m.group(2)))
    for m in RE_BAND_LABEL.finditer(text):
        _add_band(ranges, int(m.group(1)), int(m.group(2)))
    for m in RE_BAND_UNIT.finditer(text):
        _add_band(ranges, int(m.group(1)), int(m.group(2)))
    for m in RE_PLUS.finditer(text):
        p = int(m.group(1))
        if plausible_age(p):
            ranges.append((p, 120))
    for rx in (RE_AGE_UNIT_SEX, RE_AGE_SEX, RE_AGE_HINDI, RE_AGE_LABEL):
        for m in rx.finditer(text):
            a = int(m.group(1))
            if plausible_age(a):
                ranges.append((a, a))
    # NOTE: a bare "NN yrs" (no sex marker, no age label) is, in these clinical
    # notes, almost always a history duration ("H/O TB 8 yrs back", "DM2 x 12 yrs")
    # or a lab value, never a real age - so it is deliberately not read here.
    return ranges


def _mk_date(y, mth, d):
    try:
        if y < 100:
            y += 2000
        if 1900 <= y <= 2100 and 1 <= mth <= 12 and 1 <= d <= 31:
            return date(y, mth, d)
    except ValueError:
        pass
    return None


def parse_dates(text: str, ref_year: int):
    """Return (ordered_raw_strings, set_of_date_objects, ordered_best_dates)."""
    raw_order = []
    date_set = set()
    best_order = []
    for m in RE_DATE_NUM.finditer(text):
        a, b, c = int(m.group(1)), int(m.group(2)), int(m.group(3))
        raw_order.append(m.group(0))
        cand = []
        iso = _mk_date(a, b, c)       # y-m-d
        dmy = _mk_date(c, b, a)       # d-m-y
        mdy = _mk_date(c, a, b)       # m-d-y
        for dt in (dmy, mdy, iso):
            if dt:
                date_set.add(dt)
                cand.append(dt)
        best_order.append(cand[0] if cand else None)
    for m in RE_DATE_TXT.finditer(text):
        if m.group(1):
            dd, mon = int(m.group(1)), m.group(2).lower()
        else:
            dd, mon = int(m.group(4)), m.group(3).lower()
        if mon in MONTHS:
            dt = _mk_date(ref_year, MONTHS[mon], dd)
            if dt:
                raw_order.append(m.group(0))
                date_set.add(dt)
                best_order.append(dt)
    return raw_order, date_set, [d for d in best_order if d]


def parse_birth_years(text: str, ref_year: int):
    years = set()
    for m in RE_DATE_NUM.finditer(text):
        a, c = int(m.group(1)), int(m.group(3))
        for y in (a, c):
            if 1900 <= y <= ref_year - 3:
                years.add(y)
    return years


def extract_evidence(text: str, name_vocab, ref_year: int):
    """Pull every (field, value) clue the registry attacker can use."""
    givens, surnames = name_vocab["given"], name_vocab["surname"]
    low = text.lower()
    ntext = norm(text)
    ev = {
        "phones": set(), "emails": set(), "last4": set(),
        "districts": set(), "tehsils": set(), "villages": set(),
        "pins": set(), "pin_prefixes": set(), "genders": set(),
        "age_ranges": parse_age_ranges(text), "birth_years": parse_birth_years(text, ref_year),
        "given": set(), "surname": set(), "fullnames": set(),
        "rel_given": set(), "rel_surname": set(), "houses": set(),
    }

    for m in RE_PHONE.finditer(text):
        d = digits_only(m.group(0))
        if len(d) >= 11 and d.startswith("91"):
            d = d[-10:]
        if len(d) == 10 and d[0] in "6789":
            ev["phones"].add(d)
    for m in RE_EMAIL.finditer(text):
        ev["emails"].add(m.group(0).lower())
    for m in RE_AADHAAR_MASK.finditer(text):
        ev["last4"].add(m.group(1))
    for m in RE_AADHAAR_FULL.finditer(text):
        ev["last4"].add(digits_only(m.group(1))[-4:])
    for m in RE_PIN.finditer(text):
        ev["pins"].add(m.group(1))
        ev["pin_prefixes"].add(m.group(1)[:3])
    for m in RE_PIN_PREFIX.finditer(text):
        ev["pin_prefixes"].add(m.group(1))
    for m in RE_HOUSE.finditer(text):
        ev["houses"].add(m.group(1))

    # gender from explicit fields, suffixes, Hindi words, relation, honorifics
    if re.search(r"/\s*m\b|\bmale\b|\bgender\s*[:\-]?\s*m\b|\bsex\s*[:\-]?\s*m\b|\u092a\u0941\u0930\u0941\u0937|sahab|saheb|\bbhai\b|bhaiya", low):
        ev["genders"].add("M")
    if re.search(r"/\s*f\b|\bfemale\b|\bgender\s*[:\-]?\s*f\b|\bsex\s*[:\-]?\s*f\b|\u092e\u0939\u093f\u0932\u093e|behenji|behen\b|\bbehan\b", low):
        ev["genders"].add("F")

    # district / tehsil / village against the registry gazetteer, anchored so a
    # hospital header city does not leak in as the patient's district
    loc = anchored_locations(ntext, name_vocab)
    ev["districts"] |= loc["districts"]
    ev["tehsils"] |= loc["tehsils"]
    ev["villages"] |= loc["villages"]

    # relative names after S/o D/o W/o C/O (and gender implied by the relation)
    for m in RE_REL.finditer(text):
        rel = m.group(1).upper()
        if rel == "S":
            ev["genders"].add("M")
        elif rel in ("W", "D"):
            ev["genders"].add("F")
        toks = [w.lower() for w in RE_WORD.findall(m.group(2))]
        toks = [w for w in toks if w in givens or w in surnames]
        if toks:
            ev["rel_given"].add(toks[0])
            if len(toks) >= 2:
                ev["rel_surname"].add(toks[-1])

    # patient name tokens via vocabulary lookup, skipping doctor names after Dr
    words = RE_WORD.findall(text)
    keep = []
    skip = False
    for w in words:
        lw = w.lower()
        if lw == "dr":
            skip = True
            continue
        is_name = lw in givens or lw in surnames
        if skip:
            if is_name:
                continue
            skip = False
        keep.append((lw, is_name))
    for i, (lw, is_name) in enumerate(keep):
        if not is_name:
            continue
        if lw in givens:
            ev["given"].add(lw)
        if lw in surnames:
            ev["surname"].add(lw)
        if i + 1 < len(keep) and keep[i + 1][1]:
            ev["fullnames"].add((lw, keep[i + 1][0]))
    return ev


def merge_evidence(evs):
    """Pool evidence over a profile: union sets, intersect age ranges."""
    pooled = {k: set() for k in (
        "phones", "emails", "last4", "districts", "tehsils", "villages",
        "pins", "pin_prefixes", "genders", "birth_years", "given", "surname",
        "fullnames", "rel_given", "rel_surname", "houses")}
    ranges_all = []
    for ev in evs:
        for k in pooled:
            pooled[k] |= ev[k]
        ranges_all.append(ev["age_ranges"])
    # intersect: tightest window the patient must fall in
    lo = max((min(r[0] for r in rs) for rs in ranges_all if rs), default=None)
    hi = min((max(r[1] for r in rs) for rs in ranges_all if rs), default=None)
    if lo is not None and hi is not None and lo <= hi:
        pooled["age_ranges"] = [(lo, hi)]
    else:
        pooled["age_ranges"] = [r for rs in ranges_all for r in rs]
    return pooled


# ----------------------------------------------------------------------------
# Registry and candidate weighting (A2/A3)
# ----------------------------------------------------------------------------

def load_registry(path: Path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            name = r["name"].split()
            rel = r["relative_name"].split()
            rows.append({
                "rid": r["rid"],
                "given": name[0].lower() if name else "",
                "surname": name[-1].lower() if name else "",
                "rel_given": rel[0].lower() if rel else "",
                "rel_surname": rel[-1].lower() if rel else "",
                "gender": (r["gender"] or "").strip().upper(),
                "age": int(r["age"]) if r["age"].strip().isdigit() else None,
                "house": digits_only(r["house_no"]),
                "village": norm(r["village"]),
                "tehsil": norm(r["tehsil"]),
                "district": norm(r["district"]),
                "pin": (r["pin"] or "").strip(),
                "phone": digits_only(r["phone"]),
                "email": (r["email"] or "").strip().lower(),
                "last4": (r["aadhaar_last4"] or "").strip(),
            })
    return rows


def name_vocab_from_registry(rows):
    given, surname = set(), set()
    districts, tehsils, villages = set(), set(), set()
    for r in rows:
        if r["given"]:
            given.add(r["given"])
        if r["surname"]:
            surname.add(r["surname"])
        if r["district"]:
            districts.add(r["district"])
        if r["tehsil"]:
            tehsils.add(r["tehsil"])
        if r["village"]:
            villages.add(r["village"])
    return {"given": given, "surname": surname,
            "districts": districts, "tehsils": tehsils, "villages": villages}


def age_in_ranges(age, ranges, widen=True):
    if age is None:
        return False
    for lo, hi in ranges:
        if widen:
            lo, hi = lo - 1, hi + 2
        if lo <= age <= hi:
            return True
    return False


def filter_candidates(ev, rows):
    """Narrow the registry in the documented order; skip an empty filter."""
    cand = list(range(len(rows)))

    def apply(pred):
        nonlocal cand
        kept = [i for i in cand if pred(rows[i])]
        if kept:
            cand = kept

    if ev["phones"]:
        apply(lambda r: r["phone"] and r["phone"] in ev["phones"])
    if ev["emails"]:
        apply(lambda r: r["email"] and r["email"] in ev["emails"])
    if ev["last4"]:
        apply(lambda r: r["last4"] and r["last4"] in ev["last4"])
    if ev["districts"]:
        apply(lambda r: r["district"] in ev["districts"])
    if ev["genders"]:
        apply(lambda r: r["gender"] in ev["genders"])
    if ev["age_ranges"]:
        apply(lambda r: age_in_ranges(r["age"], ev["age_ranges"]))
    if ev["birth_years"]:
        apply(lambda r: r["age"] is not None and any(
            abs((REF_YEAR[0] - r["age"]) - by) <= 1 for by in ev["birth_years"]))
    if ev["tehsils"]:
        apply(lambda r: r["tehsil"] in ev["tehsils"])
    if ev["villages"]:
        apply(lambda r: r["village"] in ev["villages"])
    if ev["pins"]:
        apply(lambda r: r["pin"] in ev["pins"])
    if ev["pin_prefixes"]:
        apply(lambda r: r["pin"][:3] in ev["pin_prefixes"])
    return cand


REF_YEAR = [2026]  # set from truth at startup


def candidate_weights(ev, rows):
    cand = filter_candidates(ev, rows)
    # Name is applied as one more skip-empty filter (same mechanism ATTACKS.md
    # uses for the demographic evidence). A near-unique full name collapses the
    # candidate pool to one or two people; this is what reproduces the published
    # raw baseline (a pure "base-1 weight, no name pruning" reading scores the
    # name-only records such as the bulk lab export far too low). See redteam
    # report for this deviation from the literal weighting text.
    if ev["fullnames"]:
        fn = [i for i in cand if (rows[i]["given"], rows[i]["surname"]) in ev["fullnames"]]
        if fn:
            cand = fn
        else:
            nm = [i for i in cand if (rows[i]["given"] and rows[i]["given"] in ev["given"])
                  or (rows[i]["surname"] and rows[i]["surname"] in ev["surname"])]
            if nm:
                cand = nm
    elif ev["given"] or ev["surname"]:
        nm = [i for i in cand if (rows[i]["given"] and rows[i]["given"] in ev["given"])
              or (rows[i]["surname"] and rows[i]["surname"] in ev["surname"])]
        if nm:
            cand = nm
    elif ev["rel_given"]:
        rl = [i for i in cand if rows[i]["rel_given"] and rows[i]["rel_given"] in ev["rel_given"]]
        if rl:
            cand = rl

    weights = {}
    for i in cand:
        r = rows[i]
        w = 1.0
        if (r["given"], r["surname"]) in ev["fullnames"]:
            w *= 60.0
        else:
            if r["given"] and r["given"] in ev["given"]:
                w *= 8.0
            if r["surname"] and r["surname"] in ev["surname"]:
                w *= 3.0
        if r["rel_given"] and r["rel_given"] in ev["rel_given"]:
            w *= 8.0
        if r["house"] and r["house"] in ev["houses"]:
            w *= 2.0
        weights[i] = w
    return weights


def risk_on(rows_idx, weights):
    total = sum(weights.values())
    if total <= 0 or rows_idx is None or rows_idx not in weights:
        return 0.0
    return weights[rows_idx] / total


# ----------------------------------------------------------------------------
# Record model
# ----------------------------------------------------------------------------

class Record:
    __slots__ = ("file", "loc", "true_pt", "true_rid", "true_idx", "psn",
                 "text", "ev", "dates_raw", "dates_set", "dates_best",
                 "intervals", "join_keys", "rec_risk", "prof_risk")

    def __init__(self, file, loc, true_pt, true_rid, true_idx):
        self.file = file
        self.loc = loc
        self.true_pt = true_pt
        self.true_rid = true_rid
        self.true_idx = true_idx
        self.psn = None
        self.text = ""
        self.ev = None
        self.dates_raw = []
        self.dates_set = set()
        self.dates_best = []
        self.intervals = set()
        self.join_keys = set()
        self.rec_risk = 0.0
        self.prof_risk = 0.0


def record_text(parsed_cache, raw_text, fmt, loc, delim):
    """Extract the record's text for a locator."""
    if loc.startswith("row:"):
        n = int(loc.split(":", 1)[1])
        rows = parsed_cache.get("rows")
        if rows is None:
            rows = list(csv.reader(io.StringIO(raw_text), delimiter=delim or ","))
            parsed_cache["rows"] = rows
        if not rows or n + 1 >= len(rows):
            return raw_text
        header, data = rows[0], rows[n + 1]
        pairs = []
        for i, cell in enumerate(data):
            h = header[i] if i < len(header) else f"col{i}"
            pairs.append(f"{h}: {cell}")
        return "\n".join(pairs)
    if loc.startswith("/"):
        obj = parsed_cache.get("json", False)
        if obj is False:
            try:
                obj = json.loads(raw_text)
            except ValueError:
                obj = None
            parsed_cache["json"] = obj
        if obj is not None:
            ok, val = json_pointer(obj, loc)
            if ok:
                return val if isinstance(val, str) else json.dumps(val, ensure_ascii=False)
        return raw_text
    return raw_text  # doc


def build_records(units, truth, name_vocab, ref_year, rid_to_idx, patient_rid,
                  *, source, input_dir=None, output_dir=None):
    """Build the attack record list from the truth units.

    source='raw'      -> read dev/input directly (original names, no pseudonyms)
    source='release'  -> read the sanitised output via report.json sha mapping
    """
    records = []
    psn_by_pt = {}
    file_text_cache = {}

    renamed = {}
    rec_psn = {}
    if source == "release":
        try:
            report = json.loads((output_dir / "report.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            report = {"files": []}
        renamed = {e.get("input_sha256"): e.get("output") for e in report.get("files") or []}
        try:
            for line in (output_dir / "records.jsonl").read_text(encoding="utf-8").splitlines():
                if line.strip():
                    o = json.loads(line)
                    rel = str(o["file"]).replace("sanitized/", "", 1)
                    rec_psn[(rel, o["loc"])] = o.get("patient")
        except (OSError, ValueError, KeyError):
            pass

    for rel, f in truth["files"].items():
        fmt = f["format"]
        delim = f.get("delimiter") or ("\t" if fmt == "tsv" else ",")
        # locate and read the file text once
        if source == "raw":
            path = input_dir / rel
            out_rel = rel
            try:
                text = decode_input(path.read_bytes())
            except OSError:
                text = ""
        else:
            declared = renamed.get(f["sha256"])
            out_rel = str(declared).replace("sanitized/", "", 1) if declared else rel
            path = output_dir / "sanitized" / out_rel
            try:
                text = decode_output(path.read_bytes())
            except OSError:
                text = ""
        if path not in file_text_cache:
            file_text_cache[path] = text
        parsed_cache = {}

        for loc, u in f["units"].items():
            if loc.startswith("@") or not u.get("patient"):
                continue
            pt = u["patient"]
            true_rid = patient_rid.get(pt)
            rec = Record(rel, loc, pt, true_rid, rid_to_idx.get(true_rid))
            rec.text = record_text(parsed_cache, text, fmt, loc, delim) if text else ""
            rec.ev = extract_evidence(rec.text, name_vocab, ref_year)
            rec.dates_raw, rec.dates_set, rec.dates_best = parse_dates(rec.text, ref_year)
            # length-of-stay signal: any interval between two dates in this record
            bs = sorted(set(rec.dates_best))
            for a in range(len(bs)):
                for b in range(a + 1, len(bs)):
                    rec.intervals.add(abs((bs[b] - bs[a]).days))
            # join keys
            refs = set(RE_REF.findall(rec.text))
            psns = set(RE_PSN.findall(rec.text))
            if source == "release":
                claimed = rec_psn.get((out_rel, loc))
                if claimed:
                    psns.add(claimed)
                    rec.psn = claimed
                    psn_by_pt.setdefault(pt, claimed)
                rec.join_keys = refs | psns
            else:
                rec.join_keys = refs
            records.append(rec)
    return records, psn_by_pt, file_text_cache


# ----------------------------------------------------------------------------
# Profiles (union-find on shared join keys)
# ----------------------------------------------------------------------------

class Profile:
    __slots__ = ("members", "ev", "weights", "risk", "rid", "text", "dates_set",
                 "intervals", "districts", "genders", "age_ranges")

    def __init__(self):
        self.members = []


def build_profiles(records, rows):
    parent = list(range(len(records)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    key_to_members = defaultdict(list)
    for i, r in enumerate(records):
        for k in r.join_keys:
            key_to_members[k].append(i)
    for members in key_to_members.values():
        for j in members[1:]:
            union(members[0], j)

    groups = defaultdict(list)
    for i in range(len(records)):
        groups[find(i)].append(i)

    profiles = []
    rec_to_profile = {}
    for members in groups.values():
        p = Profile()
        p.members = members
        p.ev = merge_evidence([records[i].ev for i in members])
        p.weights = candidate_weights(p.ev, rows)
        # representative true person = most common true rid in the group
        rid_votes = defaultdict(float)
        for i in members:
            if records[i].true_idx is not None:
                rid_votes[records[i].true_idx] += 1
        p.rid = max(rid_votes, key=rid_votes.get) if rid_votes else None
        p.risk = risk_on(p.rid, p.weights)
        p.text = "\n".join(records[i].text for i in members)
        p.dates_set = set().union(*[records[i].dates_set for i in members]) if members else set()
        p.intervals = set().union(*[records[i].intervals for i in members]) if members else set()
        p.districts = p.ev["districts"]
        p.genders = p.ev["genders"]
        p.age_ranges = p.ev["age_ranges"]
        for i in members:
            rec_to_profile[i] = p
        profiles.append(p)
    return profiles, rec_to_profile


# ----------------------------------------------------------------------------
# The attack
# ----------------------------------------------------------------------------

HOSPITAL_TOKENS = {
    "sanjeevani multispeciality hospital": "sanjeevani",
    "jeevan jyoti charitable hospital": "jeevan jyoti",
    "arogya seva sadan": "arogya",
    "district hospital hardoi": "district hospital hardoi",
}


def run_record_attacks(records, rows):
    """A2/A3 record linkage and A4 profile aggregation."""
    for r in records:
        r.rec_risk = risk_on(r.true_idx, candidate_weights(r.ev, rows))
    profiles, rec_to_profile = build_profiles(records, rows)
    for i, r in enumerate(records):
        p = rec_to_profile[i]
        r.prof_risk = max(r.rec_risk, risk_on(r.true_idx, p.weights))
    a2a3 = sum(r.rec_risk for r in records) / len(records) if records else 0.0

    by_pt = defaultdict(float)
    for r in records:
        by_pt[r.true_pt] = max(by_pt[r.true_pt], r.prof_risk)
    patients = len(by_pt)
    reident = sum(1 for v in by_pt.values() if v >= 0.5) / patients if patients else 0.0
    return a2a3, reident, profiles, rec_to_profile, by_pt


def consistent_with(reg_row, profile):
    """A5: the profile's evidence must not contradict the target registry row."""
    if profile.genders and reg_row["gender"] and reg_row["gender"] not in profile.genders:
        return False
    if profile.age_ranges and not age_in_ranges(reg_row["age"], profile.age_ranges):
        return False
    if profile.districts and reg_row["district"] and reg_row["district"] not in profile.districts:
        return False
    return True


def hospital_in(text_low, hospital):
    key = HOSPITAL_TOKENS.get(hospital.lower())
    if key and key in text_low:
        return True
    first = hospital.split()[0].lower()
    return first in text_low


def run_targeted(records, profiles, known, rid_set, ref_year):
    """A5 targeted attack with global date-shift recovery."""
    # condition rarity across profiles
    cond_share = defaultdict(int)
    cond_values = {k.get("condition_hint") for k in known if k.get("condition_hint")}
    prof_text_low = [p.text.lower() for p in profiles]
    for cond in cond_values:
        c = cond.lower()
        for t in prof_text_low:
            if c in t:
                cond_share[cond] += 1

    rid_to_profiles = defaultdict(list)
    for p in profiles:
        if p.rid is not None:
            rid_to_profiles[id(p)] = p

    # map registry index -> rid handled by caller; here profiles carry true rid via record true_rid
    prof_true_rids = []
    for p in profiles:
        rids = set()
        for i in p.members:
            if records[i].true_rid:
                rids.add(records[i].true_rid)
        prof_true_rids.append(rids)

    # 1) global shift recovery from confidently re-identified profiles (>=0.9)
    known_by_rid = {}
    for k in known:
        known_by_rid.setdefault(k["rid"], []).append(k)
    offset_votes = defaultdict(set)
    for pi, p in enumerate(profiles):
        if p.risk < 0.9:
            continue
        for rid in prof_true_rids[pi]:
            if rid not in known_by_rid:
                continue
            for k in known_by_rid[rid]:
                for vd in k["visit_dates"]:
                    y, m, d = (int(x) for x in vd.split("-"))
                    kd = date(y, m, d)
                    if not p.dates_set:
                        continue
                    closest = min(p.dates_set, key=lambda dd: abs((kd - dd).days))
                    offset_votes[(kd - closest).days].add(rid)
    global_shift = 0
    best = [(off, len(v)) for off, v in offset_votes.items() if len(v) >= 2]
    if best:
        best.sort(key=lambda t: (-t[1], abs(t[0])))
        global_shift = best[0][0]

    return _score_targets(records, profiles, prof_true_rids, prof_text_low,
                          cond_share, known, rid_set, global_shift), global_shift


def _score_targets(records, profiles, prof_true_rids, prof_text_low,
                   cond_share, known, rid_set, global_shift):
    # need the target registry row for consistency; look it up by rid
    from_rid = REGISTRY_BY_RID[0]
    successes = []
    decoy_claims = 0
    decoys = 0
    signal_hits = {"date": 0, "condition": 0, "stay": 0}

    for k in known:
        rid = k["rid"]
        reg = from_rid.get(rid)
        is_decoy = rid not in rid_set
        target_dates = set()
        for vd in k["visit_dates"]:
            y, m, d = (int(x) for x in vd.split("-"))
            target_dates.add(date(y, m, d))
        cond = k.get("condition_hint")
        stay = k.get("stay_days")
        hospital = k.get("hospital", "")

        total_w = 0.0
        true_w = 0.0
        for pi, p in enumerate(profiles):
            if reg is not None and not consistent_with(reg, p):
                continue
            # un-shift the release dates by the recovered global offset
            date_hit = any((td - timedelta(days=global_shift)) in p.dates_set or td in p.dates_set
                           for td in target_dates)
            cond_hit = bool(cond) and cond.lower() in prof_text_low[pi]
            stay_hit = bool(stay) and stay in p.intervals
            if not (date_hit or cond_hit or stay_hit):
                continue
            w = 0.0
            if date_hit:
                w += 1.0
                signal_hits["date"] += 1
            if cond_hit:
                w += 8.0 if cond_share.get(cond, 0) <= 3 else 1.0
                signal_hits["condition"] += 1
            if stay_hit:
                w += 1.0
                signal_hits["stay"] += 1
            if hospital and hospital_in(prof_text_low[pi], hospital):
                w *= 2.0
            total_w += w
            if rid in prof_true_rids[pi]:
                true_w += w

        if is_decoy:
            decoys += 1
            if total_w > 0:
                decoy_claims += 1
        else:
            successes.append(true_w / total_w if total_w > 0 else 0.0)
            if os.environ.get("REDTEAM_DEBUG"):
                print(f"   A5 target {rid} cond={cond!r} stay={stay} share={successes[-1]:.2f} "
                      f"cond_profiles={cond_share.get(cond, 0) if cond else '-'}")

    targeted = sum(successes) / len(successes) if successes else 0.0
    decoy_rate = decoy_claims / decoys if decoys else 0.0
    return targeted, decoy_rate, signal_hits


REGISTRY_BY_RID = [{}]  # filled at startup


# ----------------------------------------------------------------------------
# A1 direct exposure, A6 pseudonym inversion, A7 cross-release
# ----------------------------------------------------------------------------

DIGIT_TYPES = {"PHONE", "AADHAAR", "ABHA_NUMBER", "MRN"}


def run_direct_exposure(truth, file_text_cache, renamed_map, output_dir, patient_rid):
    """A1: share of patients with a surviving critical entity in the release."""
    # map truth rel -> output file text
    rel_text = {}
    for rel, f in truth["files"].items():
        declared = renamed_map.get(f["sha256"])
        out_rel = str(declared).replace("sanitized/", "", 1) if declared else rel
        path = output_dir / "sanitized" / out_rel
        rel_text[rel] = (file_text_cache.get(path, ""), out_rel)

    exposed = set()
    all_pts = set()
    for rel, f in truth["files"].items():
        text, out_rel = rel_text[rel]
        ntext = norm(text)
        dtext = digits_only(text)
        nname = norm(out_rel)
        for loc, u in f["units"].items():
            pt = u.get("patient")
            if loc.startswith("@") or not pt:
                continue
            all_pts.add(pt)
            if pt in exposed:
                continue
            for e in u["entities"]:
                if not e.get("critical") or e.get("type") == "CANARY":
                    continue
                hay_n = nname if e.get("channel") == "filename" else ntext
                if e.get("type") in DIGIT_TYPES and e.get("key"):
                    if e["key"] in dtext:
                        exposed.add(pt)
                        break
                else:
                    surf = norm(e.get("surface", ""))
                    if surf and surf in hay_n:
                        exposed.add(pt)
                        break
    return (len(exposed) / len(all_pts)) if all_pts else 0.0


def transforms_of(original: str):
    out = set()
    s = original
    out.add(s.lower())
    dg = digits_only(s)
    if dg:
        out.add(dg)
    out.add(s[::-1].lower())
    try:
        out.add(base64.b64encode(s.encode()).decode().lower())
    except Exception:
        pass
    for algo in ("md5", "sha1", "sha256", "sha512"):
        h = hashlib.new(algo, s.encode()).hexdigest()
        out.add(h)
    return out


def run_pseudonym_inversion(records, truth, patient_rid, psn_by_pt, name_vocab, rows_by_rid):
    """A6: share of pseudonyms reversible to their patient's originals."""
    # originals per patient: uhids, critical digit keys, latin full name
    originals = defaultdict(set)
    for pt, info in truth["patients"].items():
        for lst in (info.get("uhids") or {}).values():
            for u in lst:
                originals[pt].add(u)
    for rel, f in truth["files"].items():
        for loc, u in f["units"].items():
            pt = u.get("patient")
            if not pt:
                continue
            for e in u["entities"]:
                if e.get("type") in ("PHONE", "AADHAAR", "ABHA_NUMBER") and e.get("key"):
                    originals[pt].add(e["key"])
                if e.get("type") == "PATIENT_NAME" and e.get("full") and e.get("script") == "latin":
                    originals[pt].add(e.get("surface", ""))

    psns = {pt: psn for pt, psn in psn_by_pt.items() if psn}
    if not psns:
        return 0.0, 0
    inverted = 0
    for pt, psn in psns.items():
        core = psn[4:] if psn.upper().startswith("PSN-") else psn
        variants = {psn.casefold(), core.casefold()}
        hit = False
        for orig in originals.get(pt, ()):
            if not orig:
                continue
            od = digits_only(orig)
            for var in variants:
                if od and len(od) >= 4 and od in digits_only(psn):
                    hit = True
                for t in transforms_of(orig):
                    if not t:
                        continue
                    if var == t or t.startswith(var) or (len(var) >= 8 and var.startswith(t)):
                        hit = True
                    if len(t) >= 8 and (t.startswith(var) or var.startswith(t[:8])):
                        hit = True
                if hit:
                    break
            if hit:
                break
        if hit:
            inverted += 1
    return inverted / len(psns), len(psns)


def run_cross_release(truth, psn_a, psn_b, records_a, records_b, ref_year):
    """A7: stable pseudonyms and stable date shifts across two secrets."""
    pts = set(psn_a) | set(psn_b)
    stable_psn = sum(1 for pt in pts if psn_a.get(pt) and psn_a.get(pt) == psn_b.get(pt))
    psn_share = stable_psn / len(pts) if pts else 0.0

    # dates: compare per-record output date strings in order
    idx_b = {(r.file, r.loc): r for r in records_b}
    total = same = 0
    for ra in records_a:
        rb = idx_b.get((ra.file, ra.loc))
        if rb is None:
            continue
        u = truth["files"][ra.file]["units"][ra.loc]
        ndates = len(u.get("dates") or [])
        if ndates == 0:
            continue
        a_dates = ra.dates_raw
        b_dates = rb.dates_raw
        for i in range(ndates):
            total += 1
            if i < len(a_dates) and i < len(b_dates) and a_dates[i] == b_dates[i]:
                same += 1
    date_share = same / total if total else 0.0
    return max(psn_share, date_share), psn_share, date_share


# ----------------------------------------------------------------------------
# Orchestration and reporting
# ----------------------------------------------------------------------------

def attack_source(label, records, rows, known, rid_set, ref_year):
    a2a3, reident, profiles, rec_to_profile, by_pt = run_record_attacks(records, rows)
    (targeted, decoy_rate, signal_hits), shift = run_targeted(
        records, profiles, known, rid_set, ref_year)
    return {
        "label": label,
        "records": len(records),
        "patients": len(by_pt),
        "record_linkage_risk": a2a3,
        "patients_reidentified": reident,
        "targeted_success": targeted,
        "decoy_false_claims": decoy_rate,
        "recovered_global_shift_days": shift,
        "targeted_signal_hits": signal_hits,
        "clusters": len(profiles),
    }


def fmt_pct(x):
    return f"{100 * x:6.2f}%"


def main() -> int:
    ap = argparse.ArgumentParser(description="Dev-only red-team attacker (A1-A7).")
    ap.add_argument("--output", required=True, help="sanitised release folder to attack")
    ap.add_argument("--other", help="second release (different secret) to enable A7")
    ap.add_argument("--kit", default=r"..\Secret-Wards-ToolKit", help="toolkit path")
    ap.add_argument("--json", dest="json_out", help="write full result to this file")
    ap.add_argument("--raw", action="store_true",
                    help="report the raw-input attack as 'ours' (sanity check)")
    args = ap.parse_args()

    kit = Path(args.kit)
    truth = json.loads((kit / "dev" / "truth" / "truth.json").read_text(encoding="utf-8"))
    rows = load_registry(kit / "dev" / "attacker" / "registry.csv")
    known = [json.loads(ln) for ln in
             (kit / "dev" / "attacker" / "known_facts.jsonl").read_text(encoding="utf-8").splitlines()
             if ln.strip()]
    ref_year = int(str(truth.get("ref_date", "2026"))[:4])
    REF_YEAR[0] = ref_year

    name_vocab = name_vocab_from_registry(rows)
    patient_rid = {pt: info["rid"] for pt, info in truth["patients"].items()}
    rid_set = set(patient_rid.values())
    rid_to_idx = {}
    REGISTRY_BY_RID[0] = {}
    for i, r in enumerate(rows):
        rid_to_idx.setdefault(r["rid"], i)
        REGISTRY_BY_RID[0][r["rid"]] = r

    units = []  # (rel, loc) kept implicitly inside build_records

    # RAW baseline
    raw_records, _, _ = build_records(
        units, truth, name_vocab, ref_year, rid_to_idx, patient_rid,
        source="raw", input_dir=kit / "dev" / "input")
    raw = attack_source("RAW", raw_records, rows, known, rid_set, ref_year)
    raw["direct_exposure"] = 1.0  # raw exposes every patient by definition

    # Release under attack (or raw-as-submission with --raw)
    out_dir = Path(args.output)
    rel_records, psn_by_pt, rel_cache = build_records(
        units, truth, name_vocab, ref_year, rid_to_idx, patient_rid,
        source="release", output_dir=out_dir)
    renamed_map = {}
    try:
        report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
        renamed_map = {e.get("input_sha256"): e.get("output") for e in report.get("files") or []}
    except (OSError, ValueError):
        pass

    if args.raw:
        ours = attack_source("RAW(as submission)", raw_records, rows, known, rid_set, ref_year)
        ours["direct_exposure"] = 1.0
        ours_records = raw_records
    else:
        ours = attack_source("OURS", rel_records, rows, known, rid_set, ref_year)
        ours["direct_exposure"] = run_direct_exposure(
            truth, rel_cache, renamed_map, out_dir, patient_rid)
        ours_records = rel_records

    # A6 pseudonym inversion (release only)
    inv_rate, n_psn = run_pseudonym_inversion(
        rel_records, truth, patient_rid, psn_by_pt, name_vocab, REGISTRY_BY_RID[0])
    ours["pseudonym_inversion"] = inv_rate
    ours["pseudonyms"] = n_psn

    # A7 cross-release
    a7 = None
    if args.other and not args.raw:
        other_records, psn_by_pt_b, _ = build_records(
            units, truth, name_vocab, ref_year, rid_to_idx, patient_rid,
            source="release", output_dir=Path(args.other))
        a7_risk, a7_psn, a7_date = run_cross_release(
            truth, psn_by_pt, psn_by_pt_b, rel_records, other_records, ref_year)
        a7 = {"risk": a7_risk, "stable_pseudonyms": a7_psn, "stable_dates": a7_date}
        ours["cross_release"] = a7

    # ---- assemble components: name, raw risk, our risk, ratio, weight ----
    def ratio(o, r):
        return (o / r) if r > 0 else 0.0

    comps = []
    comps.append(("A1 direct exposure", raw["direct_exposure"], ours["direct_exposure"],
                  ours["direct_exposure"], 0.20, "absolute"))
    comps.append(("A2/A3 record linkage", raw["record_linkage_risk"], ours["record_linkage_risk"],
                  ratio(ours["record_linkage_risk"], raw["record_linkage_risk"]), 0.20, "ratio"))
    comps.append(("A4 profile re-id", raw["patients_reidentified"], ours["patients_reidentified"],
                  ratio(ours["patients_reidentified"], raw["patients_reidentified"]), 0.20, "ratio"))
    comps.append(("A5 targeted attack", raw["targeted_success"], ours["targeted_success"],
                  ratio(ours["targeted_success"], raw["targeted_success"]), 0.20, "ratio"))
    comps.append(("A6 pseudonym inversion", 0.0, ours["pseudonym_inversion"],
                  ours["pseudonym_inversion"], 0.10, "absolute"))
    if a7 is not None:
        comps.append(("A7 cross-release", 0.0, a7["risk"], a7["risk"], 0.10, "absolute"))

    wsum = sum(c[4] for c in comps)
    risk = sum(min(1.0, max(0.0, c[3])) * c[4] for c in comps) / wsum if wsum else 0.0
    privacy_points = 25.0 * (1.0 - risk)

    # ---- print ----
    tag = ours["label"]
    print("=" * 74)
    print(" Secret Wards red-team attacker (dev-only) - A1-A7")
    print(f" raw records={raw['records']} patients={raw['patients']} | "
          f"attacking {tag}: records={ours['records']} patients={ours['patients']} "
          f"pseudonyms={n_psn}")
    print("=" * 74)
    print(f"{'component':<24}{'raw':>9}{'ours':>9}{'ratio':>9}{'weight':>8}  kind")
    print("-" * 74)
    for name, rr, orr, rat, w, kind in comps:
        print(f"{name:<24}{fmt_pct(rr):>9}{fmt_pct(orr):>9}{rat*100:8.1f}%{w:8.2f}  {kind}")
    print("-" * 74)
    print(f"overall attack risk           : {fmt_pct(risk)}")
    print(f"estimated privacy points      : {privacy_points:6.2f} / 25   (25 * (1 - risk))")
    print(f"A5 decoy false-claim rate     : {fmt_pct(ours['decoy_false_claims'])}  "
          f"(raw {fmt_pct(raw['decoy_false_claims'])})")
    print(f"recovered global shift (days) : raw={raw['recovered_global_shift_days']}  "
          f"ours={ours['recovered_global_shift_days']}")
    print(f"A5 signal hits (ours)         : {ours['targeted_signal_hits']}")
    if a7 is not None:
        print(f"A7 stable pseudonyms={fmt_pct(a7['stable_pseudonyms'])}  "
              f"stable dates={fmt_pct(a7['stable_dates'])}")

    # ---- top 10 most exposed records (no registry personal data; rid only) ----
    ranked = sorted(ours_records, key=lambda r: r.prof_risk, reverse=True)[:10]
    print("\nTop 10 most exposed records (file, loc, risk, true rid):")
    for r in ranked:
        print(f"  {r.prof_risk:6.3f}  {r.true_rid or '-':<12}  {r.file}  {r.loc}")

    if args.json_out:
        result = {"raw": raw, "ours": ours,
                  "components": [{"name": n, "raw": rr, "ours": orr, "ratio": rat,
                                  "weight": w, "kind": k} for n, rr, orr, rat, w, k in comps],
                  "overall_risk": risk, "privacy_points": privacy_points}
        Path(args.json_out).write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
