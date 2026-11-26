#!/usr/bin/env python3
r"""Dev-only estimator of the official RAKSHA "Secret Wards" score (docs/SCORING.md).

It scores a release folder against the practice answer key (truth.json) with every
category of the toolkit's docs/SCORING.md and the weights in scoring.toml, and prints a
scorecard: sub-scores, category scores in [0, 1], weighted points, penalties, the
estimated total out of 100 and the ten biggest point losses. It never prints personal
data: only entity types, file names that carry no PII, locators and counts.

Usage (Windows PowerShell, cwd = repository root)
-------------------------------------------------
  $env:PYTHONIOENCODING = "utf-8"
  .\.venv\Scripts\python.exe tools/scorecard.py --output out_a `
      --input ..\Secret-Wards-ToolKit\dev\input --truth ..\Secret-Wards-ToolKit\dev\truth\truth.json `
      [--other out_b] [--repeat out_a2] [--profile small|standard] [--json result.json]

  --other          same input run with a different RAKSHA_SECRET (privacy A7)
  --repeat         same input run again with the same secret (determinism)
  --profile        performance thresholds from scoring.toml (default: small)
  --json           write the full numeric result (no personal data) to this file
  --stdout         a file with the run's captured stdout+stderr (side-channel scan)
  --kit            toolkit folder (scoring.toml, attacker files); default derived from --truth
  --config         scoring.toml path (default <kit>/scoring.toml)
  --redteam-json   reuse a saved `tools/redteam.py --json` result instead of running it
  --exit-code      the pipeline's exit code (default 0)

Calibration helper: build one of the published anchor baselines from an input folder
  tools/scorecard.py --make-baseline passthrough|redact|redact-all --input <in> --output <new dir>
      [--truth <truth.json>]
  passthrough  byte copy of the input, every file declared sanitized, patient null
  redact       same structure, every value destroyed (CSV cells and text lines "X",
               JSON strings "X" and numbers 0); keys and file names kept
  redact-all   like redact, and JSON keys and file names destroyed too (closest to the
               organisers' baselines/redact_all: "destroys every value, key and file name")

ASSUMPTIONS AND DEVIATIONS (where SCORING.md leaves room for a reading)
-----------------------------------------------------------------------
Leak counting
  L1  Name keys are the truth entity "tokens" list; the generator already drops generic
      parts (devi, kumar, md., ji, bano, singh, kaur, sahab, ...). Tokens match as whole
      words; "_" and punctuation separate words, Devanagari letters and signs do not.
  L2  Digit keys match with up to 3 non-alphanumeric characters between any two digits
      and no digit directly before or after; PIN ("digits_exact") must be contiguous.
      Text keys (email, PAN, house, locality, village, ...) match as normalised phrases.
      DOB matches any dmy / mdy / ISO / "12 Apr 1977" / yyyymmdd date resolving to it.
  L3  A record's haystack is the normalised text, plus a second variant with \uXXXX,
      HTML entities and %-escapes decoded (occurrences = max over the two variants, so
      nothing is counted twice), plus base64 / hex payloads decoded (added).
  L4  allowed = occurrences of the key inside the unit's distinct preserve-probe texts,
      times how often each probe text occurs in the input record; pii_occ is at least 1.
  L5  A unit is located by its output locator (the records.jsonl "out" of the claim with
      the same input loc, else the loc itself). Unlocatable units use the whole output
      file. A file that was not exported leaks nothing.
  L6  Truth files map to output files through report.json (input_sha256 -> output);
      for duplicate SHA-256 values the same relative path wins, then the first unused one.
Detection
  D1  Per-type and per-script recall are entity-weight-weighted means of (1 - mention
      leak); CANARY entities count (scoring.toml lists CANARY in type_weights).
  D2  A trap probe "survives" when its normalised text is anywhere in the output record.
      The clean group is the multiset token retention of the clean files.
Identity
  I1  Evaluated units: non-file-level units with link required/ambiguous, plus any unit
      with a pseudonym (a pseudonym on a no-patient unit only creates false pairs).
  I2  Precision: a same-pseudonym pair is correct when both units have the same true
      patient. Recall and the trap recalls use pairs of required units with the same
      "cid" (linkable component). B-cubed precision uses true patients, recall uses cid.
  I3  A claim counts only if its pseudonym is a substring of the normalised output record
      named by the claim (out, else loc); otherwise it is treated as null (reported).
  I4  A trap with no linkable pair scores 1.0. No valid pseudonym at all: category 0.
Privacy
  P1  overall_risk is recomputed from the tools/redteam.py components with its own formula;
      A6 is dropped when the release has no pseudonyms (SCORING: "only if pseudonyms
      exist"). A1 there scans sanitized/ only. Without --other, A7 is not applicable and the
      remaining weights are renormalised. If redteam.py crashes on non-UTF-8 sanitized
      files, it is re-run on a temporary copy where only those files are re-encoded.
Utility
  U1  Probe scores: 1.0 at the original field (path), 0.8 elsewhere in the record (or in
      the whole file when the record cannot be located), 0 lost. Without a path: 1.0 if in
      the located record, 0.8 if only found through the whole-file fallback.
  U2  Temporal intervals are pooled over all patients' event pairs; a missing or
      unparseable output date scores 0. Yearless dates ("5 September") take the year
      closest to the true date. Anchored dates are the first date within 400 characters
      after the anchor. LOS pairs: admission + discharge of one unit, then leftovers of one
      patient within 0..60 days.
  U3  Generalisation: age bands are inclusive ("45-49" has width 5); "[45,50)" is
      half-open; "80+" scores 0.3 only if it contains the true age. Village tehsil and
      district names come from the attacker registry and the input record. A missing or
      blank output field scores 0.
  U4  Statistics: ICD and LOS terms are (1 - TVD) x coverage; LOS bins are days 0..30 and
      31+. Lab medians compare numeric values per test name; tests come from the sibling
      lab_test probe or the input record's "test" key.
  U5  Token retention is pooled over files (micro), excluding expect="either" files.
  U6  Record retention covers non-file-level units (the 815 "records" of the manifest).
Integrity
  G1  Format validity covers every file under sanitized/. PDF / image formats are never
      valid (not UTF-8 text). Schema: CSV = mean(column count, header names, row count,
      row shape); a header holding PII is exempt from the names check. JSON = mean(key-path
      Jaccard, unchanged value types), ignoring generalisable paths and keys holding PII.
      Text = line-count ratio. Only exported "sanitize" files are compared.
  G2  FHIR validity: share of the input FHIR bundles exported and passing
      tools/fhir_validate.validate (missing bundles count as invalid).
  G3  Pseudonym consistency is 0 when records.jsonl has no non-null claim.
  G4  Side channels are scanned for critical identifiers, full patient names and canary
      identities; 64-hex hashes are ignored. stdout/stderr is clean unless --stdout is
      given; TMPDIR/HOME are assumed clean. "Other output files" excludes quarantine/.
  G5  Report honesty: files_total = input files, files_sanitized = input files actually
      exported, files_quarantined = input files not exported.
Performance
  F1  Sub-weights 0.3/0.3/0.2/0.2 from SCORING.md (not in scoring.toml); scaling is not
      measured. Time and memory come from report.json unless overridden. Without --repeat,
      determinism is not measured and scores 1.0 (flagged in the notes).
Penalties
  N1  Unique leaked identifier: a critical, non-canary entity whose every key leaked in its
      unit (names: full=True), or found by a side-channel scan; unique by key value.
  N2  Canaries: a canary identity (full name or its number) anywhere in the output folder
      except quarantine/ (SPEC: quarantine is not scanned), including file names, report,
      records and --stdout. False success (-10): report.json missing or input files
      silently dropped. Input tampering (-5): input file hashes differ from truth.

Dev-only. Plain ASCII only.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import csv
import functools
import hashlib
import html
import importlib.util
import io
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unicodedata
import urllib.parse
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback below
    tomllib = None

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_KIT = ROOT.parent / "Secret-Wards-ToolKit"

csv.field_size_limit(2 ** 31 - 1)

# Fixed mixes that SCORING.md states but scoring.toml does not carry.
IDENTITY_MIX = {"f05": 0.4, "b3_f1": 0.3, "language_trap": 0.1, "fragmented_trap": 0.1,
                "homonym_separation": 0.1}
TEMPORAL_MIX = {"intervals": 0.6, "length_of_stay": 0.4}
QUARANTINE_MIX = {"handled_safely": 0.5, "no_silent_drop": 0.3, "no_unprocessed_copy": 0.2}
REPORT_MIX = {"completeness": 0.5, "honesty": 0.5}
PERF_WEIGHTS = {"reliability": 0.30, "wall_time": 0.30, "peak_memory": 0.20, "determinism": 0.20}
TRAP_GROUPS = ("doctor", "doctor-vs-relative", "c/o-complaint", "k/c/o", "h/o", "hospital-ward",
               "dose", "1-0-1", "eponym", "asha")
REPORT_COUNTS = ["files_total", "files_sanitized", "files_quarantined", "records_processed",
                 "identifiers_detected", "records_linked", "records_generalized",
                 "records_suppressed", "records_quarantined"]
STATUSES = {"sanitized", "quarantined", "suppressed"}


def _as_dict(x) -> dict:
    return x if isinstance(x, dict) else {}


def _reject_json_constant(name: str):
    raise ValueError("JSON has no %s" % name)


def _finite_json_float(s: str) -> float:
    v = float(s)
    if not math.isfinite(v):
        raise ValueError("number out of range")
    return v
BOM = b"\xef\xbb\xbf"

# ----------------------------------------------------------------------------
# Normalisation (both sides), SCORING.md "How leaks are counted"
# ----------------------------------------------------------------------------

_ZERO_WIDTH = ("\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e\u200e\u200f"
               "\u202a\u202b\u202c\u202d\u202e\u2061\u2062\u2063\u2064\u034f")
# hyphen, non-breaking hyphen, figure dash, en dash, em dash, bar, minus, ... -> "-"
_DASHES = "\u2010\u2011\u2012\u2013\u2014\u2015\u2212\u2043\u02d7\ufe58\ufe63\uff0d\u2796"
_HOMOGLYPHS = {
    # Cyrillic
    "\u0430": "a", "\u0410": "A", "\u0412": "B", "\u0432": "b", "\u0435": "e", "\u0415": "E",
    "\u041a": "K", "\u043a": "k", "\u041c": "M", "\u043c": "m", "\u041d": "H", "\u043d": "h",
    "\u043e": "o", "\u041e": "O", "\u0440": "p", "\u0420": "P", "\u0441": "c", "\u0421": "C",
    "\u0422": "T", "\u0442": "t", "\u0443": "y", "\u0423": "Y", "\u0445": "x", "\u0425": "X",
    "\u0456": "i", "\u0406": "I", "\u0457": "i", "\u0407": "I", "\u0458": "j", "\u0408": "J",
    "\u0455": "s", "\u0405": "S", "\u0501": "d", "\u0500": "D", "\u04bb": "h", "\u04ba": "H",
    "\u051b": "q", "\u051a": "Q", "\u051d": "w", "\u051c": "W", "\u04cf": "l", "\u04c0": "I",
    "\u0475": "v", "\u0474": "V",
    # Greek
    "\u03b1": "a", "\u0391": "A", "\u0392": "B", "\u03b5": "e", "\u0395": "E", "\u0396": "Z",
    "\u0397": "H", "\u03b9": "i", "\u0399": "I", "\u03ba": "k", "\u039a": "K", "\u039c": "M",
    "\u03bd": "v", "\u039d": "N", "\u03bf": "o", "\u039f": "O", "\u03c1": "p", "\u03a1": "P",
    "\u03c4": "t", "\u03a4": "T", "\u03c5": "u", "\u03a5": "Y", "\u03c7": "x", "\u03a7": "X",
    "\u03f2": "c", "\u03f9": "C", "\u03f3": "j", "\u03c9": "w",
    # Latin lookalikes
    "\u0131": "i", "\u0261": "g", "\u0251": "a", "\u01c0": "l",
}
# first code point of each 0-9 run: Arabic-Indic, Extended Arabic-Indic, NKo, Devanagari,
# Bengali, Gurmukhi, Gujarati, Oriya, Tamil, Telugu, Kannada, Malayalam, Sinhala, Thai, Lao,
# Tibetan, Myanmar, Khmer, Mongolian, Saurashtra, Javanese
_DIGIT_BLOCKS = (0x0660, 0x06F0, 0x07C0, 0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6, 0x0C66,
                 0x0CE6, 0x0D66, 0x0DE6, 0x0E50, 0x0ED0, 0x0F20, 0x1040, 0x17E0, 0x1810, 0xA8D0,
                 0xA9D0)


def _build_table() -> dict:
    t = {ord(c): None for c in _ZERO_WIDTH}
    t.update({ord(c): "-" for c in _DASHES})
    t.update({ord(k): v for k, v in _HOMOGLYPHS.items()})
    for start in _DIGIT_BLOCKS:
        for i in range(10):
            t[start + i] = str(i)
    return t


_TABLE = _build_table()
_LATIN_MARKS = re.compile(r"[\u0300-\u036f]")


def norm(s) -> str:
    """NFKC, zero-width removed, homoglyphs / Indic digits / dashes folded, casefolded,
    Latin diacritics stripped, whitespace collapsed."""
    if not s:
        return ""
    s = unicodedata.normalize("NFKC", str(s)).translate(_TABLE).casefold()
    if not s.isascii():
        d = unicodedata.normalize("NFD", s)
        if _LATIN_MARKS.search(d):
            s = unicodedata.normalize("NFC", _LATIN_MARKS.sub("", d))
    return " ".join(s.split())


_WCH = "0-9a-z\u0900-\u097f"          # word characters after norm()
LB = "(?<![" + _WCH + "])"            # left word boundary
LA = "(?![" + _WCH + "])"             # right word boundary
_DSEP = "[^" + _WCH + "]{0,3}"        # separators allowed between digits of a digit key
_PSEP = "[^" + _WCH + "]+(?:[" + _WCH + "]+[^" + _WCH + "]+)?"  # name phrase: 1 word may intervene
_TOKEN = re.compile("[" + _WCH + "]+")
_IS_WORD = re.compile("[" + _WCH + "]")


def tokens_of(normalised: str) -> list:
    return _TOKEN.findall(normalised)


def letters_only(s) -> str:
    return re.sub("[^" + _WCH + "]", "", norm(s))


# ----------------------------------------------------------------------------
# Hidden payloads: base64, hex, \uXXXX, HTML entities, %-encoding
# ----------------------------------------------------------------------------

_B64_RUN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_RUN = re.compile(r"(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Za-z])")
_UESC_RUN = re.compile(r"(?:\\u[0-9a-fA-F]{4})+")
_HTML_ENT = re.compile(r"&(?:#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z][A-Za-z0-9]{1,30});")
_PCT = re.compile(r"%[0-9A-Fa-f]{2}")
_LONG_HEX = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{32,}(?![0-9A-Za-z])")


def _printable(s: str) -> bool:
    if len(s) < 3:
        return False
    good = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return good >= 0.85 * len(s)


def decode_payloads(text: str) -> list:
    """Decoded base64 and hex runs that are readable UTF-8 text."""
    out = []
    for m in _B64_RUN.finditer(text):
        core = m.group(0).rstrip("=")
        if len(core) < 16 or len(core) % 4 == 1:
            continue
        alt = "-" in core or "_" in core
        if alt and ("+" in core or "/" in core):
            continue
        try:
            raw = (base64.urlsafe_b64decode if alt else base64.b64decode)(core + "=" * (-len(core) % 4))
            s = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if _printable(s):
            out.append(s)
    for m in _HEX_RUN.finditer(text):
        try:
            s = bytes.fromhex(m.group(0)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _printable(s):
            out.append(s)
    return out


def _uesc(m) -> str:
    try:
        return json.loads('"' + m.group(0) + '"')
    except ValueError:
        return m.group(0)


def full_decode(text: str) -> str:
    """Decode \\uXXXX runs, HTML entities and %-escapes in place."""
    t = text
    if "\\u" in t:
        t = _UESC_RUN.sub(_uesc, t)
    if "&" in t and _HTML_ENT.search(t):
        t = html.unescape(t)
    if "%" in t and _PCT.search(t):
        t = urllib.parse.unquote(t, errors="replace")
    return t


@functools.lru_cache(maxsize=None)
def key_regex(kind: str, value: str):
    """Compiled matcher for one key. kinds: w word, d digits, x exact digits, t text, s substring."""
    if not value:
        return None
    if kind == "w":
        return re.compile(LB + re.escape(value) + LA)
    if kind == "d":
        digits = re.sub(r"\D", "", value)
        if len(digits) < 4:
            return None
        # a mobile number may carry a trunk / country prefix glued on: 0, 91, 091, 0091
        pre = "(?:(?:0091|091|91|0)" + _DSEP + ")?" if len(digits) == 10 and digits[0] in "6789" else ""
        return re.compile("(?<![0-9])" + pre + _DSEP.join(digits) + "(?![0-9])")
    if kind == "x":
        return re.compile("(?<![0-9])" + re.escape(value) + "(?![0-9])")
    if kind == "t":
        pre = LB if _IS_WORD.match(value[0]) else ""
        post = LA if _IS_WORD.match(value[-1]) else ""
        return re.compile(pre + re.escape(value) + post)
    if kind == "s":
        return re.compile(re.escape(value))
    raise ValueError(kind)


@functools.lru_cache(maxsize=None)
def phrase_regex(tokens: tuple):
    return re.compile(LB + _PSEP.join(re.escape(t) for t in tokens) + LA)


class Hay:
    """A normalised haystack: text variants (max-counted) plus decoded payloads (added)."""
    __slots__ = ("variants", "payload", "_dates")

    def __init__(self, raw):
        raw = raw or ""
        v0 = norm(raw)
        dec = full_decode(raw)
        self.variants = (v0,) if dec == raw else (v0, norm(dec))
        pays, seen = [], set()
        for src in ((raw,) if dec == raw else (raw, dec)):
            for p in decode_payloads(src):
                for q in [full_decode(p)] + decode_payloads(p):
                    if q not in seen:
                        seen.add(q)
                        pays.append(q)
        self.payload = norm("\n".join(pays)) if pays else ""
        self._dates = None

    def _texts(self):
        return self.variants + ((self.payload,) if self.payload else ())

    def count(self, kind: str, value: str) -> int:
        if kind == "b":
            return self._count_dob(value)
        rx = key_regex(kind, value)
        if rx is None:
            return 0
        best = max(sum(1 for _ in rx.finditer(v)) for v in self.variants)
        if self.payload:
            best += sum(1 for _ in rx.finditer(self.payload))
        return best

    def probe_spans(self, probe_texts) -> list:
        """Merged character spans of every occurrence of the probe texts in the primary text."""
        v0 = self.variants[0]
        spans = []
        for t in probe_texts:
            if not t:
                continue
            start = v0.find(t)
            while start >= 0:
                spans.append((start, start + len(t)))
                start = v0.find(t, start + 1)
        spans.sort()
        merged = []
        for a, b in spans:
            if merged and a <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], b))
            else:
                merged.append((a, b))
        return merged

    def count_inside(self, kind: str, value: str, spans: list) -> int:
        """Occurrences of a key (primary text) that lie fully inside one of the spans."""
        if not spans or kind == "b":
            return 0
        rx = key_regex(kind, value)
        if rx is None:
            return 0
        return sum(1 for m in rx.finditer(self.variants[0])
                   if any(a <= m.start() and m.end() <= b for a, b in spans))

    def contains(self, normalised: str) -> bool:
        return bool(normalised) and any(normalised in t for t in self._texts())

    def has_phrase(self, toks) -> bool:
        toks = tuple(t for t in toks if t)
        if not toks:
            return False
        orders = [toks] if len(toks) != 2 else [toks, toks[::-1]]
        for o in orders:
            rx = phrase_regex(o)
            if any(rx.search(t) for t in self._texts()):
                return True
        return False

    def _count_dob(self, iso: str) -> int:
        target = parse_iso(iso)
        if target is None:
            return 0
        if self._dates is None:
            self._dates = [date_mentions(t) for t in self._texts()]
        n_var = len(self.variants)
        counts = [sum(1 for cands in ds if target in cands) for ds in self._dates]
        return max(counts[:n_var]) + (counts[n_var] if len(counts) > n_var else 0)


# ----------------------------------------------------------------------------
# Dates
# ----------------------------------------------------------------------------

_EN_MONTHS = ["january", "february", "march", "april", "may", "june", "july", "august",
              "september", "october", "november", "december"]
# Hindi month names (Devanagari, escaped to keep this file ASCII)
_HI_MONTHS = {
    "\u091c\u0928\u0935\u0930\u0940": 1, "\u092b\u0930\u0935\u0930\u0940": 2,
    "\u092b\u093c\u0930\u0935\u0930\u0940": 2, "\u092e\u093e\u0930\u094d\u091a": 3,
    "\u0905\u092a\u094d\u0930\u0948\u0932": 4, "\u0905\u092a\u094d\u0930\u0947\u0932": 4,
    "\u092e\u0908": 5, "\u091c\u0942\u0928": 6, "\u091c\u0941\u0932\u093e\u0908": 7,
    "\u0905\u0917\u0938\u094d\u0924": 8, "\u0938\u093f\u0924\u0902\u092c\u0930": 9,
    "\u0938\u093f\u0924\u092e\u094d\u092c\u0930": 9, "\u0905\u0915\u094d\u091f\u0942\u092c\u0930": 10,
    "\u0905\u0915\u094d\u0924\u0942\u092c\u0930": 10, "\u0928\u0935\u0902\u092c\u0930": 11,
    "\u0928\u0935\u092e\u094d\u092c\u0930": 11, "\u0926\u093f\u0938\u0902\u092c\u0930": 12,
    "\u0926\u093f\u0938\u092e\u094d\u092c\u0930": 12,
}
MONTHS = {}
for _i, _m in enumerate(_EN_MONTHS, 1):
    MONTHS[_m] = _i
    MONTHS[_m[:3]] = _i
MONTHS["sept"] = 9
for _k, _v in _HI_MONTHS.items():
    MONTHS[norm(_k)] = _v
_MON_ALT = "|".join(sorted((re.escape(k) for k in MONTHS), key=len, reverse=True))
_RX_DATES = re.compile(
    r"(?<![0-9])(?P<iy>\d{4})[-/.](?P<im>\d{1,2})[-/.](?P<id>\d{1,2})(?![0-9])"
    r"|(?<![0-9])(?P<a>\d{1,2})(?P<s1>[-/.])(?P<b>\d{1,2})(?P=s1)(?P<c>\d{4}|\d{2})(?![0-9])"
    r"|(?<![0-9a-z])(?P<dd>\d{1,2})(?:st|nd|rd|th)?[ \-/.,]*(?P<mon>" + _MON_ALT + ")" + LA
    + r"(?:[ \-/.,']*(?P<yy>\d{4}|\d{2})(?![0-9]))?"
    r"|" + LB + "(?P<mon2>" + _MON_ALT + ")" + LA
    + r"[ \-/.]*(?P<dd2>\d{1,2})(?:st|nd|rd|th)?(?![0-9])(?:[ ,]*(?P<yy2>\d{4})(?![0-9]))?"
    r"|(?<![0-9])(?P<compact>\d{8})(?![0-9])")


def parse_iso(s):
    try:
        return date.fromisoformat(str(s)[:10])
    except (ValueError, TypeError):
        return None


def _year(y: str) -> int:
    n = int(y)
    if len(y) == 2:
        return 2000 + n if n <= 69 else 1900 + n
    return n


def _candidates(m, order: str = "dmy"):
    """(year or None, month, day) readings of a date match, most likely first."""
    g = m.groupdict()
    if g["iy"]:
        return [(int(g["iy"]), int(g["im"]), int(g["id"]))]
    if g["a"]:
        a, b, y = int(g["a"]), int(g["b"]), _year(g["c"])
        return [(y, a, b), (y, b, a)] if order == "mdy" else [(y, b, a), (y, a, b)]
    if g["mon"]:
        return [(_year(g["yy"]) if g["yy"] else None, MONTHS[g["mon"]], int(g["dd"]))]
    if g["mon2"]:
        return [(_year(g["yy2"]) if g["yy2"] else None, MONTHS[g["mon2"]], int(g["dd2"]))]
    s = g["compact"]
    return [(int(s[:4]), int(s[4:6]), int(s[6:])), (int(s[4:]), int(s[2:4]), int(s[:2]))]


def _mk(y, mo, d):
    try:
        return date(y, mo, d)
    except (ValueError, TypeError):
        return None


def date_mentions(normalised: str) -> list:
    """For every date mention, the set of full dates it can resolve to (any order)."""
    out = []
    for m in _RX_DATES.finditer(normalised):
        cands = set()
        for y, mo, d in _candidates(m):
            if y is not None:
                dt = _mk(y, mo, d)
                if dt:
                    cands.add(dt)
        if cands:
            out.append(cands)
    return out


def parse_date_value(value, hint: str, ref):
    """First date in a value, read with the file's hint order (dmy / mdy) and ISO.
    A yearless date takes the year closest to the reference (true) date."""
    s = norm(value)
    if not s:
        return None
    for m in _RX_DATES.finditer(s):
        for y, mo, d in _candidates(m, hint or "dmy"):
            if y is None:
                if ref is None:
                    continue
                opts = [_mk(ref.year + k, mo, d) for k in (-1, 0, 1)]
                opts = [o for o in opts if o]
                if opts:
                    return min(opts, key=lambda o: abs((o - ref).days))
                continue
            dt = _mk(y, mo, d)
            if dt:
                return dt
    return None


# ----------------------------------------------------------------------------
# JSON helpers (iterative: the input has a 1,500-deep document)
# ----------------------------------------------------------------------------

class _Key(str):
    pass


def _num(n) -> str:
    if isinstance(n, float) and n.is_integer() and abs(n) >= 1e6:
        return str(int(n))
    return str(n)


def flatten(node) -> str:
    """Keys and scalar values of a JSON value, one per line, in document order."""
    parts, stack = [], [node]
    while stack:
        n = stack.pop()
        if isinstance(n, _Key):
            parts.append(str.__str__(n))
        elif isinstance(n, dict):
            for k in reversed(list(n.keys())):
                stack.append(n[k])
                stack.append(_Key(k))
        elif isinstance(n, list):
            stack.extend(reversed(n))
        elif n is None:
            continue
        elif isinstance(n, bool):
            parts.append("true" if n else "false")
        elif isinstance(n, (int, float)):
            parts.append(_num(n))
        else:
            parts.append(str(n))
    return "\n".join(parts)


def scalar_text(node) -> str:
    if node is None:
        return ""
    if isinstance(node, bool):
        return "true" if node else "false"
    if isinstance(node, (int, float)):
        return _num(node)
    if isinstance(node, str):
        return node
    return flatten(node)


def jptr(obj, ptr: str):
    """RFC 6901 pointer -> (ok, value)."""
    cur = obj
    if ptr in ("", None):
        return True, cur
    for raw in ptr.split("/")[1:]:
        tok = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, list):
            try:
                i = int(tok)
            except ValueError:
                return False, None
            if not 0 <= i < len(cur):
                return False, None
            cur = cur[i]
        elif isinstance(cur, dict):
            if tok not in cur:
                return False, None
            cur = cur[tok]
        else:
            return False, None
    return True, cur


def _tname(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, (int, float)):
        return "num"
    if isinstance(v, str):
        return "str"
    return "obj" if isinstance(v, dict) else "arr"


def key_paths(obj) -> dict:
    """Generic key paths (array indices as []) -> set of value type names."""
    paths, stack = {}, [(obj, "")]
    while stack:
        node, p = stack.pop()
        if isinstance(node, dict):
            for k, v in node.items():
                q = p + "/" + str(k)
                paths.setdefault(q, set()).add(_tname(v))
                stack.append((v, q))
        elif isinstance(node, list):
            for v in node:
                q = p + "/[]"
                paths.setdefault(q, set()).add(_tname(v))
                stack.append((v, q))
    return paths


# ----------------------------------------------------------------------------
# Files
# ----------------------------------------------------------------------------

def decode_input(raw: bytes, encoding=None) -> str:
    if raw.startswith(BOM):
        return raw[3:].decode("utf-8", "replace")
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", "replace")
    encs = [encoding] if encoding and encoding not in ("utf-8", "utf-8-sig", "utf-16") else []
    for enc in ["utf-8"] + encs + ["cp1252"]:
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "replace")


def decode_output(raw: bytes):
    """-> (text, is_utf8). A BOM is allowed."""
    body = raw[3:] if raw.startswith(BOM) else raw
    try:
        return body.decode("utf-8"), True
    except UnicodeDecodeError:
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
            return raw.decode("utf-16", "replace"), False
        return body.decode("utf-8", "replace"), False


def fmt_from_ext(rel: str) -> str:
    ext = Path(rel).suffix.lower()
    return {".csv": "csv", ".tsv": "tsv", ".json": "json", ".txt": "text", ".xml": "xml",
            ".pdf": "pdf"}.get(ext, "binary")


def walk_files(root: Path) -> list:
    out = []
    if not root.is_dir():
        return out
    for dp, dn, fn in os.walk(root):
        dn.sort()
        for n in sorted(fn):
            out.append(Path(dp) / n)
    return out


_UNSET = object()


class Doc:
    """One file, parsed lazily in its truth format, with per-record haystacks."""

    def __init__(self, raw: bytes, fmt: str, delim, name: str, side: str, encoding=None):
        self.raw = raw
        self.fmt = fmt
        self.delim = delim or ("\t" if fmt == "tsv" else ",")
        self.name = name
        if side == "in":
            self.text, self.utf8_ok = decode_input(raw, encoding), None
        else:
            self.text, self.utf8_ok = decode_output(raw)
        self._rows = None
        self._obj = _UNSET
        self.json_ok = False
        self._rec = {}
        self._hay = {}

    @property
    def rows(self) -> list:
        if self._rows is None:
            self._rows = []
            if self.fmt in ("csv", "tsv"):
                try:
                    self._rows = list(csv.reader(io.StringIO(self.text, newline=""), delimiter=self.delim))
                except csv.Error:
                    self._rows = []
        return self._rows

    @property
    def obj(self):
        if self._obj is _UNSET:
            self._obj = None
            if self.fmt in ("json", "fhir"):
                try:
                    self._obj = json.loads(self.text)
                    self.json_ok = True
                except (ValueError, RecursionError):
                    self._obj = None
        return self._obj

    def parsed(self) -> bool:
        _ = self.obj
        return self.json_ok

    def whole(self) -> str:
        if "\0whole" not in self._rec:
            self._rec["\0whole"] = flatten(self.obj) if self.parsed() else self.text
        return self._rec["\0whole"]

    def locate(self, loc: str):
        """-> (located, record text). Unlocatable records fall back to the whole file."""
        if loc not in self._rec:
            self._rec[loc] = self._locate(loc)
        return self._rec[loc]

    def _locate(self, loc: str):
        if loc in ("doc", "@file"):
            return True, self.whole()
        if loc == "@filename":
            return True, self.name
        if loc == "@header":
            rows = self.rows
            return (True, "\n".join(rows[0])) if rows else (False, self.whole())
        if loc.startswith("row:"):
            try:
                n = int(loc[4:])
            except ValueError:
                return False, self.whole()
            rows = self.rows
            if 0 <= n and n + 1 < len(rows):
                return True, "\n".join(rows[n + 1])
            return False, self.whole()
        if loc.startswith("/") and self.parsed():
            ok, node = jptr(self.obj, loc)
            if ok:
                return True, flatten(node) if isinstance(node, (dict, list)) else scalar_text(node)
        return False, self.whole()

    def hay(self, loc: str) -> Hay:
        located, text = self.locate(loc)
        key = loc if located and loc not in ("doc", "@file") else "\0whole"
        h = self._hay.get(key)
        if h is None:
            h = self._hay[key] = Hay(text if located else self.whole())
        return h

    def col_index(self, name: str, fallback=None):
        rows = self.rows
        if not rows:
            return None
        header = rows[0]
        if name in header:
            return header.index(name)
        n = norm(name)
        for i, h in enumerate(header):
            if norm(h) == n:
                return i
        return fallback

    def field(self, loc: str, path, fallback_idx=None):
        """Value at a truth path inside the record at `loc` (str), or None."""
        if not path:
            return None
        if path.startswith("col:"):
            if not loc.startswith("row:"):
                return None
            rows = self.rows
            try:
                n = int(loc[4:])
            except ValueError:
                return None
            if not (0 <= n and n + 1 < len(rows)):
                return None
            idx = self.col_index(path[4:], fallback_idx)
            row = rows[n + 1]
            return row[idx] if idx is not None and idx < len(row) else None
        if path.startswith("/") and self.parsed():
            base = loc if loc.startswith("/") else ""
            ok, node = jptr(self.obj, base + path)
            return scalar_text(node) if ok else None
        return None


def _strip_san(o) -> str:
    o = str(o).replace("\\", "/")
    return o[len("sanitized/"):] if o.startswith("sanitized/") else o


class Release:
    """report.json, records.jsonl and the truth-file -> output-file mapping of one release."""

    def __init__(self, out_dir: Path, truth: dict):
        self.dir = out_dir
        self.report, self.report_error = None, None
        try:
            rep = json.loads((out_dir / "report.json").read_text(encoding="utf-8-sig"))
            if isinstance(rep, dict):
                self.report = rep
            else:
                self.report_error = "not an object"
        except FileNotFoundError:
            self.report_error = "missing"
        except (OSError, ValueError):
            self.report_error = "invalid JSON"
        rep = self.report or {}
        files = rep.get("files")
        self.entries = [e for e in files if isinstance(e, dict)] if isinstance(files, list) else []
        self.san = out_dir / "sanitized"
        self.san_files = {p.relative_to(self.san).as_posix() for p in walk_files(self.san)}
        self.by_sha = defaultdict(list)
        for e in self.entries:
            self.by_sha[str(e.get("input_sha256", "")).lower()].append(e)
        self.mapping = {}
        used = set()
        for rel in sorted(truth["files"]):
            sha = truth["files"][rel].get("sha256", "")
            cands = []
            for e in self.by_sha.get(sha, []):
                o = e.get("output")
                if o:
                    o = _strip_san(o)
                    if o in self.san_files and o not in cands:
                        cands.append(o)
            if rel in self.san_files and (not cands or rel in cands):
                m = rel
            elif cands:
                m = next((c for c in cands if c not in used), cands[0])
            else:
                m = None
            self.mapping[rel] = m
            if m:
                used.add(m)
        self.reverse = {}
        for rel, m in self.mapping.items():
            if m and m not in self.reverse:
                self.reverse[m] = rel
        # records.jsonl
        self.claims = defaultdict(dict)
        self.claim_list = []
        self.records_error = None
        try:
            lines = (out_dir / "records.jsonl").read_text(encoding="utf-8-sig").splitlines()
        except FileNotFoundError:
            lines, self.records_error = [], "missing"
        except UnicodeDecodeError:
            lines, self.records_error = [], "not UTF-8"
        except OSError:
            lines, self.records_error = [], "unreadable"
        for line in lines:
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except ValueError:
                self.records_error = "invalid line"
                continue
            if not isinstance(r, dict) or "file" not in r or "loc" not in r:
                continue
            psn = r.get("patient")
            c = {"file": _strip_san(r["file"]), "loc": str(r["loc"]),
                 "out": str(r.get("out") or r["loc"]),
                 "patient": str(psn) if psn not in (None, "") else None}
            self.claims[c["file"]][c["loc"]] = c
            self.claim_list.append(c)

    def declared_status(self, sha: str) -> set:
        return {str(e.get("status")) for e in self.by_sha.get(sha, [])}

    def lookup_claim(self, out_rel, loc: str):
        """Longest reported locator covering `loc`: exact, JSON-pointer ancestor, then doc."""
        recs = self.claims.get(out_rel) or {}
        if loc in recs:
            return recs[loc]
        if loc.startswith("/"):
            parts = loc.split("/")
            for i in range(len(parts) - 1, 1, -1):
                anc = "/".join(parts[:i])
                if anc in recs:
                    return recs[anc]
        return recs.get("doc")

    def out_loc(self, out_rel, loc: str) -> str:
        c = (self.claims.get(out_rel) or {}).get(loc)
        return c["out"] if c and c.get("out") else loc


# ----------------------------------------------------------------------------
# Scoring context
# ----------------------------------------------------------------------------

def load_toml(path: Path) -> dict:
    data = path.read_bytes()
    if tomllib is not None:
        return tomllib.loads(data.decode("utf-8"))
    return _mini_toml(data.decode("utf-8"))  # pragma: no cover


def _mini_toml(text: str) -> dict:
    """Python 3.10 fallback for the flat tables / numbers / strings scoring.toml uses."""
    out, cur = {}, None
    cur = out
    for line in text.splitlines():
        s = line.split("#", 1)[0].strip()
        if not s:
            continue
        if s.startswith("[") and s.endswith("]"):
            cur = out
            for part in s[1:-1].strip().split("."):
                cur = cur.setdefault(part.strip(), {})
            continue
        k, _, v = s.partition("=")
        k, v = k.strip(), v.strip()
        if v.startswith('"') and v.endswith('"'):
            val = v[1:-1]
        elif v in ("true", "false"):
            val = v == "true"
        else:
            try:
                val = int(v)
            except ValueError:
                val = float(v)
        cur[k] = val
    return out


class Ctx:
    def __init__(self, truth: dict, truth_path: Path, input_dir: Path, out_dir: Path, cfg: dict,
                 cfg_sha: str, kit: Path):
        self.truth = truth
        self.truth_path = truth_path
        self.files = truth["files"]
        self.input_dir = input_dir
        self.out_dir = out_dir
        self.cfg = cfg
        self.cfg_sha = cfg_sha
        self.kit = kit
        self.rel = Release(out_dir, truth)
        self._in = {}
        self._out = {}
        self._claim_ok = {}
        self.notes = []
        self.registry = load_registry(kit / "dev" / "attacker" / "registry.csv")
        # display names: input names that carry PII are never printed
        self.pii_named = {rel for rel, f in self.files.items()
                          if any(u.get("entities") for loc, u in f["units"].items() if loc == "@filename")}

    def disp(self, rel: str) -> str:
        if rel in self.pii_named:
            f = self.files[rel]
            parent = rel.rsplit("/", 1)[0] if "/" in rel else ""
            return f"{parent}/<sha {f.get('sha256', '')[:8]}>"
        return rel

    def in_doc(self, rel: str):
        if rel not in self._in:
            f = self.files[rel]
            p = self.input_dir / rel
            try:
                raw = p.read_bytes()
            except OSError:
                raw = None
            self._in[rel] = None if raw is None else Doc(raw, f["format"], f.get("delimiter"), rel, "in",
                                                          f.get("encoding"))
        return self._in[rel]

    def out_doc_rel(self, out_rel):
        if not out_rel:
            return None
        if out_rel not in self._out:
            src = self.rel.reverse.get(out_rel)
            f = self.files.get(src) if src else None
            fmt = f["format"] if f else fmt_from_ext(out_rel)
            delim = (f.get("delimiter") if f else None) or ("\t" if fmt == "tsv" else ",")
            try:
                raw = (self.rel.san / out_rel).read_bytes()
            except OSError:
                raw = None
            self._out[out_rel] = None if raw is None else Doc(raw, fmt, delim, out_rel, "out")
        return self._out[out_rel]

    def out_doc(self, rel: str):
        return self.out_doc_rel(self.rel.mapping.get(rel))

    def out_loc(self, rel: str, loc: str) -> str:
        return self.rel.out_loc(self.rel.mapping.get(rel), loc)

    def claim_valid(self, claim) -> bool:
        key = (claim["file"], claim["out"], claim["patient"])
        if key not in self._claim_ok:
            ok = False
            doc = self.out_doc_rel(claim["file"]) if claim["file"] in self.rel.san_files else None
            if doc is not None and claim["patient"]:
                located, _ = doc.locate(claim["out"])
                ok = located and doc.hay(claim["out"]).contains(norm(claim["patient"]))
            self._claim_ok[key] = ok
        return self._claim_ok[key]

    def col_fallback(self, rel: str, path):
        if not path or not path.startswith("col:"):
            return None
        d = self.in_doc(rel)
        return d.col_index(path[4:]) if d is not None else None


def load_registry(path: Path) -> dict:
    """letters-only village name -> set of (tehsil, district) from the attacker registry."""
    out = defaultdict(set)
    try:
        with open(path, encoding="utf-8", newline="") as fh:
            for r in csv.DictReader(fh):
                v = letters_only(r.get("village", ""))
                if v:
                    out[v].add((r.get("tehsil", ""), r.get("district", "")))
    except OSError:
        pass
    return out


# ----------------------------------------------------------------------------
# Leak counting (shared)
# ----------------------------------------------------------------------------

def entity_keys(e: dict) -> list:
    m = e.get("match")
    if m == "name":
        toks = [norm(t) for t in (e.get("tokens") or [])]
        toks = [t for t in dict.fromkeys(toks) if t]
        if toks:
            return [("w", t) for t in toks]
        s = norm(e.get("surface"))
        return [("t", s)] if s else []
    if m == "digits":
        k = re.sub(r"\D", "", norm(e.get("key") or e.get("surface")))
        return [("d", k)] if k else []
    if m == "digits_exact":
        k = re.sub(r"\D", "", norm(e.get("key") or e.get("surface")))
        return [("x", k)] if k else []
    if m == "dob":
        return [("b", str(e.get("key")))] if e.get("key") else []
    k = norm(e.get("key") or e.get("surface"))
    return [("t", k)] if k else []


def is_canary(e: dict) -> bool:
    return bool(e.get("canary")) or e.get("type") == "CANARY"


def compute_leaks(ctx: Ctx):
    """Per-entity mention leak and per-unit locatability."""
    ents, located = [], {}
    for rel in sorted(ctx.files):
        f = ctx.files[rel]
        ind, outd = ctx.in_doc(rel), ctx.out_doc(rel)
        for loc, u in f["units"].items():
            oloc = ctx.out_loc(rel, loc)
            if outd is not None:
                loc_ok, _ = outd.locate(oloc)
                ohay = outd.hay(oloc)
            else:
                loc_ok, ohay = False, None
            located[(rel, loc)] = loc_ok
            if not u.get("entities"):
                continue
            ihay = ind.hay(loc) if ind is not None else Hay("")
            spans = None
            cache = {}
            for e in u["entities"]:
                stats = []
                for k in entity_keys(e):
                    if k not in cache:
                        in_occ = ihay.count(*k)
                        allowed = 0
                        if in_occ and u.get("preserve"):
                            if spans is None:
                                spans = ihay.probe_spans({norm(p.get("text")) for p in u["preserve"]})
                            allowed = min(in_occ, ihay.count_inside(*k, spans))
                        pii = max(1, in_occ - allowed)
                        out_occ = ohay.count(*k) if ohay is not None else 0
                        leaked = min(max(out_occ - allowed, 0), pii)
                        cache[k] = (leaked, pii)
                    stats.append((k, cache[k]))
                leak = sum(n / p for _, (n, p) in stats) / len(stats) if stats else 0.0
                ents.append({
                    "rel": rel, "loc": loc, "type": e.get("type"), "script": e.get("script") or "latin",
                    "channel": e.get("channel") or "content", "weight": float(e.get("weight", 1.0)),
                    "critical": bool(e.get("critical")), "full": e.get("full"), "canary": is_canary(e),
                    "person": e.get("person"), "match": e.get("match"), "keys": [k for k, _ in stats],
                    "item": item_id(e),
                    "all_leaked": bool(stats) and all(n > 0 for _, (n, _p) in stats),
                    "leak": leak, "out_located": loc_ok, "exported": outd is not None,
                })
    return ents, located


# ----------------------------------------------------------------------------
# Shared probe and token helpers
# ----------------------------------------------------------------------------

def probe_score(ctx: Ctx, rel: str, loc: str, p: dict) -> float:
    """1.0 at the original field, 0.8 elsewhere in the record, 0 lost."""
    outd = ctx.out_doc(rel)
    if outd is None:
        return 0.0
    t = norm(p.get("text"))
    if not t:
        return 0.0
    oloc = ctx.out_loc(rel, loc)
    located, _ = outd.locate(oloc)
    hay = outd.hay(oloc)
    if p.get("path"):
        if located:
            val = outd.field(oloc, p["path"], ctx.col_fallback(rel, p["path"]))
            if val is not None and t in norm(val):
                return 1.0
        return 0.8 if hay.contains(t) else 0.0
    if hay.contains(t):
        return 1.0 if located else 0.8
    return 0.0


def token_retention(ctx: Ctx) -> dict:
    """rel -> (kept, total) multiset token counts of non-PII input tokens."""
    res = {}
    for rel in sorted(ctx.files):
        f = ctx.files[rel]
        if f.get("expect") == "either":
            continue
        ind = ctx.in_doc(rel)
        if ind is None:
            continue
        cin = Counter(tokens_of(norm(ind.whole())))
        excl = Counter()
        for u in f["units"].values():
            for e in u.get("entities") or []:
                excl.update(tokens_of(norm(e.get("surface"))))
            for x in u.get("exclude") or []:
                excl.update(tokens_of(norm(x)))
        cin.subtract(excl)
        cin = +cin
        total = sum(cin.values())
        outd = ctx.out_doc(rel)
        cout = Counter(tokens_of(norm(outd.whole()))) if outd is not None else Counter()
        kept = sum(min(c, cout.get(t, 0)) for t, c in cin.items())
        res[rel] = (kept, total)
    return res


def fbeta(p: float, r: float, beta: float) -> float:
    b2 = beta * beta
    den = b2 * p + r
    return (1 + b2) * p * r / den if den > 0 else 0.0


def top_items(counter, n=3) -> str:
    items = [(k, v) for k, v in counter.items() if v]
    items.sort(key=lambda kv: (-kv[1], str(kv[0])))
    return ", ".join(f"{k} ({v:g})" for k, v in items[:n]) or "-"


# ----------------------------------------------------------------------------
# 1. Detection & contextual intelligence
# ----------------------------------------------------------------------------

def cat_detection(ctx: Ctx, ents: list, tokret: dict, maxpts: float) -> dict:
    dcfg = ctx.cfg.get("detection", {})
    beta = float(dcfg.get("beta", 2.0))
    mix = float(dcfg.get("type_mix", 0.5))
    tw = dcfg.get("type_weights", {})
    tnum, tden, snum, sden = (defaultdict(float) for _ in range(4))
    for e in ents:
        w, r = e["weight"], 1.0 - e["leak"]
        tnum[e["type"]] += w * r
        tden[e["type"]] += w
        snum[e["script"]] += w * r
        sden[e["script"]] += w

    def recall_of(tn, sn):
        types = [t for t in tden if tden[t] > 0]
        tsum = sum(float(tw.get(t, 1.0)) for t in types)
        mt = sum(float(tw.get(t, 1.0)) * tn[t] / tden[t] for t in types) / tsum if tsum else 1.0
        scr = [s for s in sden if sden[s] > 0]
        ms = sum(sn[s] / sden[s] for s in scr) / len(scr) if scr else 1.0
        return mix * mt + (1 - mix) * ms, mt, ms

    recall, macro_t, macro_s = recall_of(tnum, snum)
    groups = defaultdict(list)
    lost_files = defaultdict(Counter)
    for rel in sorted(ctx.files):
        for loc, u in ctx.files[rel]["units"].items():
            for p in u.get("preserve") or []:
                g = p.get("trap")
                if not g:
                    continue
                ok = probe_score(ctx, rel, loc, p) > 0
                groups[g].append(1.0 if ok else 0.0)
                if not ok:
                    lost_files[g][ctx.disp(rel)] += 1
    share = {g: sum(v) / len(v) for g, v in groups.items() if v}
    clean = [(k, t) for rel, (k, t) in tokret.items() if ctx.files[rel].get("clean")]
    ck, ct = sum(k for k, _ in clean), sum(t for _, t in clean)
    if ct:
        share["clean-docs"] = ck / ct
    precision = sum(share.values()) / len(share) if share else 1.0
    score = fbeta(precision, recall, beta)

    losses = []
    leaky = [e for e in ents if e["leak"] > 0]
    for t in sorted(tden):
        tn2, sn2 = dict(tnum), dict(snum)
        tn2[t] = tden[t]
        sn2 = defaultdict(float, sn2)
        for e in ents:
            if e["type"] == t:
                sn2[e["script"]] += e["weight"] * e["leak"]
        r2, _, _ = recall_of(defaultdict(float, tn2), sn2)
        gain = maxpts * (fbeta(precision, r2, beta) - score)
        lt = [e for e in leaky if e["type"] == t]
        if gain > 1e-6 and lt:
            n = sum(1 for e in ents if e["type"] == t)
            losses.append((gain, f"detection.recall[{t}]",
                           f"recall {tnum[t] / tden[t]:.3f}: {len(lt)} of {n} mentions still leak "
                           f"(scripts: {top_items(Counter(e['script'] for e in lt))}; channels: "
                           f"{top_items(Counter(e['channel'] for e in lt))}); top files: "
                           f"{top_items(Counter(ctx.disp(e['rel']) for e in lt))}"))
    if precision < 1.0:
        gain = maxpts * (fbeta(1.0, recall, beta) - score)
        bad = []
        for g in sorted(share, key=lambda k: (share[k], k)):
            if share[g] >= 1.0:
                continue
            if g == "clean-docs":
                bad.append(f"clean-docs {share[g]:.2f} ({ct - ck} tokens lost)")
            else:
                n = len(groups[g])
                bad.append(f"{g} {share[g]:.2f} ({n - int(sum(groups[g]))}/{n} lost; {top_items(lost_files[g], 2)})")
        losses.append((gain, "detection.precision",
                       f"{precision:.3f} over {len(share)} groups; failing: " + "; ".join(bad[:6])))

    return {
        "score": score,
        "parts": {"recall": recall, "contextual_precision": precision},
        "details": {
            "beta": beta, "type_mix": mix, "recall_type_macro": macro_t, "recall_script_macro": macro_s,
            "recall_by_type": {t: tnum[t] / tden[t] for t in sorted(tden)},
            "recall_by_script": {s: snum[s] / sden[s] for s in sorted(sden)},
            "mentions": len(ents), "mentions_leaking": len(leaky),
            "precision_groups": share,
        },
        "losses": losses,
    }


# ----------------------------------------------------------------------------
# 2. Identity resolution
# ----------------------------------------------------------------------------

def _pairs(n: int) -> int:
    return n * (n - 1) // 2


def cat_identity(ctx: Ctx, maxpts: float) -> dict:
    units = []
    dropped = Counter()
    for rel in sorted(ctx.files):
        out_rel = ctx.rel.mapping.get(rel)
        for loc, u in ctx.files[rel]["units"].items():
            if loc.startswith("@"):
                continue
            claim = ctx.rel.lookup_claim(out_rel, loc) if out_rel else None
            psn = None
            if claim and claim.get("patient"):
                if ctx.claim_valid(claim):
                    psn = claim["patient"]
                else:
                    dropped[ctx.disp(rel)] += 1
            units.append({"rel": rel, "loc": loc, "patient": u.get("patient"), "cid": u.get("cid"),
                          "link": u.get("link"), "psn": psn})
    S = [x for x in units if x["link"] in ("required", "ambiguous") or x["psn"]]
    req = [x for x in S if x["link"] == "required" and x["cid"] is not None]
    any_psn = any(x["psn"] for x in S)
    clusters = defaultdict(list)
    for x in S:
        if x["psn"]:
            clusters[x["psn"]].append(x)
    all_pairs = sum(_pairs(len(v)) for v in clusters.values())
    correct = 0
    merged_clusters = 0
    fm_files = Counter()
    for v in clusters.values():
        byp = Counter(x["patient"] for x in v if x["patient"] is not None)
        correct += sum(_pairs(c) for c in byp.values())
        if len(byp) + sum(1 for x in v if x["patient"] is None) > 1:
            merged_clusters += 1
            for x in v:
                fm_files[ctx.disp(x["rel"])] += 1
    precision = correct / all_pairs if all_pairs else (1.0 if any_psn else 0.0)
    cid_groups = defaultdict(list)
    for x in req:
        cid_groups[x["cid"]].append(x)

    def pair_recall(groups):
        linkable = sum(_pairs(len(v)) for v in groups)
        linked = 0
        for v in groups:
            linked += sum(_pairs(c) for c in Counter(x["psn"] for x in v if x["psn"]).values())
        return (linked / linkable if linkable else 1.0), linkable, linked

    recall, linkable, linked = pair_recall(list(cid_groups.values()))
    f05 = fbeta(precision, recall, 0.5)
    # B-cubed
    bp = []
    for x in S:
        c = clusters[x["psn"]] if x["psn"] else [x]
        same = 1 if x["patient"] is None else sum(1 for y in c if y["patient"] == x["patient"])
        bp.append(same / len(c))
    br = []
    for x in req:
        g = cid_groups[x["cid"]]
        same = 1 if not x["psn"] else sum(1 for y in g if y["psn"] == x["psn"])
        br.append(same / len(g))
    b3p = sum(bp) / len(bp) if bp else 0.0
    b3r = sum(br) / len(br) if br else 0.0
    b3f1 = 2 * b3p * b3r / (b3p + b3r) if b3p + b3r else 0.0
    traps = ctx.truth.get("traps") or {}

    def trap_recall(pts):
        pts = set(pts or [])
        groups = [v for v in cid_groups.values() if v and v[0]["patient"] in pts]
        return pair_recall(groups)

    lang, lang_n, _ = trap_recall(traps.get("language"))
    frag, frag_n, _ = trap_recall(traps.get("fragmented"))
    hom_pairs = traps.get("homonym_pairs") or []
    sep = 0
    for a, b in hom_pairs:
        pa = {x["psn"] for x in S if x["patient"] == a and x["psn"]}
        pb = {x["psn"] for x in S if x["patient"] == b and x["psn"]}
        sep += not (pa & pb)
    homonym = sep / len(hom_pairs) if hom_pairs else 1.0
    parts = {"f05": f05, "b3_f1": b3f1, "language_trap": lang, "fragmented_trap": frag,
             "homonym_separation": homonym}
    score = sum(IDENTITY_MIX[k] * v for k, v in parts.items()) if any_psn else 0.0
    n_claims = sum(1 for c in ctx.rel.claim_list if c["patient"])
    losses = []
    if not any_psn:
        losses.append((maxpts, "identity", "no record carries a valid pseudonym (records.jsonl patient null, "
                       f"or the pseudonym is not inside the record; {sum(dropped.values())} claims dropped)"))
    else:
        msgs = {
            "f05": f"precision {precision:.3f} ({all_pairs - correct} false-merge pairs in {merged_clusters} "
                   f"pseudonyms; files: {top_items(fm_files)}), recall {recall:.3f} ({linkable - linked} of "
                   f"{linkable} linkable pairs missed); {sum(dropped.values())} claims dropped as not in the record "
                   f"({top_items(dropped)})",
            "b3_f1": f"B-cubed precision {b3p:.3f}, recall {b3r:.3f}",
            "language_trap": f"{lang:.3f} of {lang_n} language-trap pairs linked",
            "fragmented_trap": f"{frag:.3f} of {frag_n} fragmented-trap pairs linked",
            "homonym_separation": f"{len(hom_pairs) - sep} of {len(hom_pairs)} homonym pairs share a pseudonym",
        }
        for k, v in parts.items():
            pts = maxpts * IDENTITY_MIX[k] * (1 - v)
            if pts > 1e-6:
                losses.append((pts, f"identity.{k}", f"{v:.3f}: {msgs[k]}"))
    return {
        "score": score, "parts": parts,
        "details": {"pairwise_precision": precision, "pairwise_recall": recall, "same_pseudonym_pairs": all_pairs,
                    "false_merge_pairs": all_pairs - correct, "linkable_pairs": linkable, "linked_pairs": linked,
                    "b3_precision": b3p, "b3_recall": b3r, "units_evaluated": len(S),
                    "claims_with_pseudonym": n_claims,
                    "unit_claims_dropped_not_in_record": sum(dropped.values()),
                    "any_valid_pseudonym": any_psn},
        "losses": losses,
    }


# ----------------------------------------------------------------------------
# 4. Clinical utility
# ----------------------------------------------------------------------------

_NUM = re.compile(r"-?\d+(?:\.\d+)?")
_TEHSIL_LABELS = ("tehsil", "teh", "taluka", norm("\u0924\u0939\u0938\u0940\u0932"))
_DISTRICT_LABELS = ("district", "distt", "dist", "jila", "zila", norm("\u091c\u093f\u0932\u093e"))
_GENDER_WORDS = {
    "m": "M", "male": "M", "man": "M", "boy": "M", "purush": "M", "mard": "M",
    norm("\u092a\u0941\u0930\u0941\u0937"): "M", norm("\u092a\u0941"): "M",
    "f": "F", "female": "F", "woman": "F", "girl": "F", "mahila": "F", "aurat": "F",
    norm("\u092e\u0939\u093f\u0932\u093e"): "F", norm("\u0938\u094d\u0924\u094d\u0930\u0940"): "F",
    "o": "O", "other": "O", "u": "U", "unknown": "U",
}


def first_number(s):
    m = _NUM.search(str(s or ""))
    return float(m.group(0)) if m else None


def record_pairs(doc: Doc, loc: str) -> list:
    """(field name, value) pairs of a record: CSV header -> cell, JSON key -> leaf."""
    if doc is None:
        return []
    if loc.startswith("row:"):
        rows = doc.rows
        try:
            n = int(loc[4:])
        except ValueError:
            return []
        if not rows or n + 1 >= len(rows):
            return []
        return list(zip(rows[0], rows[n + 1]))
    if doc.parsed():
        ok, node = jptr(doc.obj, loc if loc.startswith("/") else "")
        if not ok:
            return []
        out, stack = [], [("", node)]
        while stack:
            k, n = stack.pop()
            if isinstance(n, dict):
                stack.extend((kk, vv) for kk, vv in n.items())
            elif isinstance(n, list):
                stack.extend((k, vv) for vv in n)
            else:
                out.append((k, scalar_text(n)))
        return out
    return []


def parse_age(val):
    s = norm(val)
    if not s:
        return None
    m = re.search(r"\[\s*(\d{1,3})\s*,\s*(\d{1,3})\s*([\)\]])", s)
    if m:
        lo, hi = int(m.group(1)), int(m.group(2))
        return ("band", lo, hi - 1 if m.group(3) == ")" else hi)
    m = re.search(r"(?<![0-9.])(\d{1,3})\s*-\s*(\d{1,3})(?![0-9.])", s)
    if m:
        return ("band", int(m.group(1)), int(m.group(2)))
    m = re.search(r"(?<![0-9.])(\d{1,3})\s*\+", s) or re.search(r"(?:>=|>|above|over)\s*(\d{1,3})", s)
    if m:
        return ("open", int(m.group(1)))
    m = re.search(r"(?<![0-9.\-])(-?\d{1,3})(?![0-9.])", s)
    if m:
        return ("exact", int(m.group(1)))
    return None


def age_score(val, true_age):
    """-> (score, untruthful flag)."""
    a = parse_age(val)
    try:
        t = int(true_age)
    except (TypeError, ValueError):
        return 0.0, False
    if a is None:
        return 0.0, False
    if a[0] == "exact":
        return (1.0, False) if a[1] == t else (0.0, True)
    if a[0] == "open":
        return (0.3, False) if a[1] <= t else (0.0, True)
    lo, hi = min(a[1], a[2]), max(a[1], a[2])
    if not lo <= t <= hi:
        return 0.0, True
    width = hi - lo + 1
    if width <= 1:
        return 1.0, False
    return (0.9 if width <= 5 else 0.8 if width <= 10 else 0.6 if width <= 20 else 0.3), False


def dob_score(val, true_iso, hint):
    t = parse_iso(true_iso)
    if t is None or not norm(val):
        return 0.0, False
    d = parse_date_value(val, hint, None)
    if d is not None:
        diff = abs((d - t).days)
        return (1.0 if diff == 0 else 0.9 if diff <= 365 else 0.0), diff > 365
    m = re.fullmatch(r"\s*(\d{4})(?:[-/.]\d{1,2})?\s*", str(val))
    if m:
        return (0.8, False) if int(m.group(1)) == t.year else (0.0, True)
    return 0.0, False


def gender_of(val):
    s = norm(val)
    if not s:
        return None
    if s in _GENDER_WORDS:
        return _GENDER_WORDS[s]
    for tok in reversed(tokens_of(s)):
        if tok in _GENDER_WORDS:
            return _GENDER_WORDS[tok]
    return None


def location_candidates(ctx: Ctx, rel: str, loc: str, u: dict, village_in: str, true_id: str):
    ind = ctx.in_doc(rel)
    tehsils, districts = set(), set()
    v = letters_only(village_in)
    for t, d in ctx.registry.get(v, ()) if v else ():
        tehsils.add(letters_only(t))
        districts.add(letters_only(d))
    if true_id:
        districts.add(letters_only(str(true_id).split(":")[0]))
    for k, val in record_pairs(ind, loc):
        nk = norm(k)
        if any(lbl == nk or nk.startswith(lbl + " ") or nk.endswith(" " + lbl) for lbl in _TEHSIL_LABELS):
            tehsils.add(letters_only(val))
        if any(lbl == nk or nk.startswith(lbl + " ") or nk.endswith(" " + lbl) for lbl in _DISTRICT_LABELS):
            districts.add(letters_only(val))
    for fl in u.get("fields") or []:
        if fl.get("kind") == "district":
            districts.add(letters_only(fl.get("true")))
            if ind is not None and fl.get("path"):
                districts.add(letters_only(ind.field(loc, fl["path"]) or ""))
    tehsils.discard("")
    districts.discard("")
    return tehsils, districts


def field_score(ctx: Ctx, rel: str, loc: str, u: dict, fl: dict):
    """-> (score, untruthful flag, located)."""
    outd, ind = ctx.out_doc(rel), ctx.in_doc(rel)
    if outd is None:
        return 0.0, False, False
    oloc = ctx.out_loc(rel, loc)
    located, _ = outd.locate(oloc)
    if not located:
        return 0.0, False, False
    path = fl["path"]
    ov = outd.field(oloc, path, ctx.col_fallback(rel, path))
    iv = ind.field(loc, path) if ind is not None else None
    kind, true = fl.get("kind"), fl.get("true")
    if ov is None or not norm(ov):
        return 0.0, False, True
    if kind == "age":
        s, bad = age_score(ov, true)
        return s, bad, True
    if kind == "dob":
        s, bad = dob_score(ov, true, ctx.files[rel].get("date_hint") or "dmy")
        return s, bad, True
    o = letters_only(ov)
    if kind == "village":
        v = letters_only(iv)
        if v and v in o:
            return 1.0, False, True
        tehsils, districts = location_candidates(ctx, rel, loc, u, iv or "", true)
        if any(t in o for t in tehsils):
            return 0.8, False, True
        if any(d in o for d in districts):
            return 0.7, False, True
        return 0.0, False, True
    if kind == "district":
        cands = {letters_only(true), letters_only(iv)} - {""}
        return (1.0 if any(c in o for c in cands) else 0.0), False, True
    if kind == "pin":
        digits = re.sub(r"\D", "", norm(ov))
        t = re.sub(r"\D", "", str(true))
        if len(t) == 6 and digits == t:
            return 1.0, False, True
        if len(t) == 6 and digits == t[:3]:
            return 0.7, False, True
        return 0.0, bool(digits) and len(digits) in (3, 6), True
    if kind == "gender":
        g = gender_of(ov)
        if (g is not None and g == str(true).upper()[:1]) or (iv is not None and norm(ov) == norm(iv)):
            return 1.0, False, True
        return 0.0, g is not None, True
    return (1.0 if iv is not None and norm(ov) == norm(iv) else 0.0), False, True


def out_date(ctx: Ctx, rel: str, loc: str, d: dict, true_d):
    outd = ctx.out_doc(rel)
    if outd is None:
        return None
    oloc = ctx.out_loc(rel, loc)
    located, text = outd.locate(oloc)
    if not located:
        return None
    hint = d.get("hint") or ctx.files[rel].get("date_hint") or "dmy"
    if d.get("path"):
        val = outd.field(oloc, d["path"], ctx.col_fallback(rel, d["path"]))
        return parse_date_value(val, hint, true_d) if val is not None else None
    a = d.get("anchor")
    if a:
        i = text.find(a)
        if i < 0:
            i = text.casefold().find(a.casefold())
        if i < 0:
            return None
        return parse_date_value(text[i + len(a): i + len(a) + 400], hint, true_d)
    return None


def _tvd(a: Counter, b: Counter) -> float:
    sa, sb = sum(a.values()), sum(b.values())
    if not sa or not sb:
        return 1.0
    keys = set(a) | set(b)
    return 0.5 * sum(abs(a[k] / sa - b[k] / sb) for k in keys)


def _los_bin(v: int):
    return "neg" if v < 0 else (v if v <= 30 else "31+")


def _median(xs):
    xs = sorted(xs)
    n = len(xs)
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2


def cat_utility(ctx: Ctx, tokret: dict, located: dict, maxpts: float) -> dict:
    wts = {k: float(v) for k, v in ctx.cfg.get("utility", {}).get("weights", {}).items()}
    # --- clinical probes
    num = den = 0.0
    lost_kind, moved_kind, lost_files = Counter(), Counter(), Counter()
    n_probes = 0
    for rel in sorted(ctx.files):
        for loc, u in ctx.files[rel]["units"].items():
            for p in u.get("preserve") or []:
                s = probe_score(ctx, rel, loc, p)
                w = float(p.get("weight", 1.0))
                num += w * s
                den += w
                n_probes += 1
                if s == 0:
                    lost_kind[p.get("kind")] += 1
                    lost_files[ctx.disp(rel)] += 1
                elif s < 1:
                    moved_kind[p.get("kind")] += 1
    clinical = num / den if den else 1.0

    # --- temporal
    events = defaultdict(list)
    by_unit = defaultdict(list)
    missing_dates = Counter()
    for rel in sorted(ctx.files):
        for loc, u in ctx.files[rel]["units"].items():
            for d in u.get("dates") or []:
                if not (d.get("path") or d.get("anchor")):
                    continue
                tr = parse_iso(d.get("true"))
                if tr is None:
                    continue
                od = out_date(ctx, rel, loc, d, tr)
                ev = {"true": tr, "out": od, "rel": rel, "loc": loc, "event": str(d.get("event", "")),
                      "pt": d.get("patient") or u.get("patient")}
                events[ev["pt"]].append(ev)
                by_unit[(rel, loc)].append(ev)
                if od is None:
                    missing_dates[ctx.disp(rel)] += 1
    isum = ipairs = 0.0
    off_files = Counter()
    off_pairs = 0
    for pt, evs in events.items():
        if pt is None:
            continue
        for i in range(len(evs)):
            a = evs[i]
            for j in range(i + 1, len(evs)):
                b = evs[j]
                ipairs += 1
                if a["out"] is None or b["out"] is None:
                    continue
                diff = abs((b["out"] - a["out"]).days - (b["true"] - a["true"]).days)
                if diff == 0:
                    isum += 1.0
                elif diff == 1:
                    isum += 0.5
                else:
                    off_pairs += 1
                    off_files[ctx.disp(a["rel"])] += 1
                    if b["rel"] != a["rel"]:
                        off_files[ctx.disp(b["rel"])] += 1
    intervals = isum / ipairs if ipairs else 1.0
    los_pairs = []
    left_adm, left_dis = defaultdict(list), defaultdict(list)
    for evs in by_unit.values():
        adm = [e for e in evs if e["event"].startswith("admission")]
        dis = [e for e in evs if e["event"].startswith("discharge")]
        for a, b in zip(adm, dis):
            los_pairs.append((a, b))
        for a in adm[len(dis):]:
            left_adm[a["pt"]].append(a)
        for b in dis[len(adm):]:
            left_dis[b["pt"]].append(b)
    for pt, dl in left_dis.items():
        pool = left_adm.get(pt, [])
        for b in dl:
            ok = [a for a in pool if 0 <= (b["true"] - a["true"]).days <= 60]
            if ok:
                a = max(ok, key=lambda x: x["true"])
                pool.remove(a)
                los_pairs.append((a, b))
    lsum = 0.0
    los_in, los_out = Counter(), Counter()
    los_bad = Counter()
    for a, b in los_pairs:
        tl = (b["true"] - a["true"]).days
        los_in[_los_bin(tl)] += 1
        if a["out"] is None or b["out"] is None:
            los_bad[ctx.disp(a["rel"])] += 1
            continue
        ol = (b["out"] - a["out"]).days
        los_out[_los_bin(ol)] += 1
        lsum += 1.0 if ol == tl else 0.5 if abs(ol - tl) == 1 else 0.0
        if abs(ol - tl) > 1:
            los_bad[ctx.disp(a["rel"])] += 1
    los = lsum / len(los_pairs) if los_pairs else None
    if los is None:
        temporal = intervals
    else:
        temporal = TEMPORAL_MIX["intervals"] * intervals + TEMPORAL_MIX["length_of_stay"] * los

    # --- generalisation
    gsum = gn = 0
    by_kind = defaultdict(list)
    untruthful = Counter()
    gen_lost = Counter()
    for rel in sorted(ctx.files):
        for loc, u in ctx.files[rel]["units"].items():
            for fl in u.get("fields") or []:
                if not fl.get("path"):
                    continue
                s, bad, _ = field_score(ctx, rel, loc, u, fl)
                gsum += s
                gn += 1
                by_kind[fl.get("kind")].append(s)
                if bad:
                    untruthful[fl.get("kind")] += 1
                if s == 0:
                    gen_lost[ctx.disp(rel)] += 1
    generalization = gsum / gn if gn else 1.0

    # --- statistics
    codes_in, codes_out = Counter(), Counter()
    vals_in, vals_out = defaultdict(list), defaultdict(list)
    for rel in sorted(ctx.files):
        ind, outd = ctx.in_doc(rel), ctx.out_doc(rel)
        for loc, u in ctx.files[rel]["units"].items():
            pres = u.get("preserve") or []
            for p in pres:
                if p.get("kind") == "diagnosis_code":
                    c = norm(p.get("text")).upper().replace(" ", "")
                    codes_in[c] += 1
                    if probe_score(ctx, rel, loc, p) > 0:
                        codes_out[c] += 1
            tests = [p for p in pres if p.get("kind") == "lab_test"]
            labs = [p for p in pres if p.get("kind") == "lab"]
            for i, lp in enumerate(labs):
                tv = first_number(lp.get("text"))
                if tv is None:
                    continue
                name = None
                path = lp.get("path")
                if path and path.startswith("/"):
                    parent = path.rsplit("/", 1)[0]
                    for tp in tests:
                        if tp.get("path") and tp["path"].rsplit("/", 1)[0] == parent:
                            name = tp.get("text")
                    if name is None and ind is not None and ind.parsed():
                        ok, node = jptr(ind.obj, (loc if loc.startswith("/") else "") + parent)
                        if ok and isinstance(node, dict):
                            for k in ("test", "test_name", "name", "investigation", "parameter"):
                                if isinstance(node.get(k), str):
                                    name = node[k]
                                    break
                elif path and len(tests) == 1:
                    name = tests[0].get("text")
                if name is None and len(tests) == len(labs):
                    name = tests[i].get("text")
                if name is None:
                    continue
                key = norm(name)
                vals_in[key].append(tv)
                ov = None
                if outd is not None:
                    oloc = ctx.out_loc(rel, loc)
                    if path and outd.locate(oloc)[0]:
                        ov = first_number(outd.field(oloc, path, ctx.col_fallback(rel, path)))
                    elif not path and probe_score(ctx, rel, loc, lp) > 0:
                        ov = tv
                if ov is not None:
                    vals_out[key].append(ov)
    stat_parts = {}
    if codes_in:
        cov = sum(codes_out.values()) / sum(codes_in.values())
        stat_parts["icd_distribution"] = (1 - _tvd(codes_in, codes_out)) * cov if codes_out else 0.0
    if los_pairs:
        cov = sum(los_out.values()) / sum(los_in.values())
        stat_parts["los_histogram"] = (1 - _tvd(los_in, los_out)) * cov if los_out else 0.0
    bad_tests = []
    if vals_in:
        ok = 0
        for k, xs in vals_in.items():
            mi = _median(xs)
            ys = vals_out.get(k)
            if ys and abs(_median(ys) - mi) <= 0.1 * abs(mi) + 1e-9:
                ok += 1
            else:
                bad_tests.append(k)
        stat_parts["lab_medians"] = ok / len(vals_in)
    statistics = sum(stat_parts.values()) / len(stat_parts) if stat_parts else 1.0

    # --- token and record retention
    tk = sum(k for k, _ in tokret.values())
    tt = sum(t for _, t in tokret.values())
    token_ret = tk / tt if tt else 1.0
    rec_units = [(rel, loc) for rel, f in ctx.files.items() for loc in f["units"] if not loc.startswith("@")]
    rec_ok = sum(1 for k in rec_units if located.get(k))
    record_ret = rec_ok / len(rec_units) if rec_units else 1.0
    unloc_files = Counter(ctx.disp(rel) for rel, loc in rec_units if not located.get((rel, loc)))

    parts = {"clinical_probes": clinical, "temporal": temporal, "generalization": generalization,
             "statistics": statistics, "token_retention": token_ret, "record_retention": record_ret}
    wsum = sum(wts.get(k, 0.0) for k in parts)
    score = sum(wts.get(k, 0.0) * v for k, v in parts.items()) / wsum if wsum else 0.0
    worst_tok = Counter({ctx.disp(rel): t - k for rel, (k, t) in tokret.items() if t - k > 0})
    msgs = {
        "clinical_probes": f"{sum(lost_kind.values())} of {n_probes} probes lost (kinds: {top_items(lost_kind, 4)}), "
                           f"{sum(moved_kind.values())} moved off their field; top files: {top_items(lost_files)}",
        "temporal": f"intervals {intervals:.3f}: {off_pairs} of {int(ipairs)} date pairs off by >1 day, "
                    f"{sum(missing_dates.values())} dates not found/parsed (files: {top_items(missing_dates)}); "
                    f"worst files for shifted pairs: {top_items(off_files)}; LOS "
                    + (f"{los:.3f} over {len(los_pairs)} stays (bad: {top_items(los_bad)})"
                       if los is not None else "n/a"),
        "generalization": "by kind: " + ", ".join(f"{k} {sum(v) / len(v):.2f}" for k, v in sorted(by_kind.items()))
                          + f"; untruthful values: {top_items(untruthful)}; top files with 0: {top_items(gen_lost)}",
        "statistics": ", ".join(f"{k} {v:.3f}" for k, v in stat_parts.items())
                      + (f"; lab tests off: {', '.join(bad_tests[:5])}" if bad_tests else ""),
        "token_retention": f"{tt - tk} of {tt} non-PII tokens lost; top files: {top_items(worst_tok)}",
        "record_retention": f"{len(rec_units) - rec_ok} of {len(rec_units)} records not locatable; "
                            f"top files: {top_items(unloc_files)}",
    }
    losses = []
    for k, v in parts.items():
        pts = maxpts * wts.get(k, 0.0) / (wsum or 1) * (1 - v)
        if pts > 1e-6:
            losses.append((pts, f"utility.{k}", f"{v:.3f}: {msgs[k]}"))
    return {
        "score": score, "parts": parts,
        "details": {"probes": n_probes, "intervals": intervals, "length_of_stay": los, "date_pairs": int(ipairs),
                    "date_pairs_off_by_more_than_1": off_pairs, "dates_missing": sum(missing_dates.values()),
                    "los_pairs": len(los_pairs),
                    "generalization_by_kind": {k: sum(v) / len(v) for k, v in by_kind.items()},
                    "untruthful_fields": dict(untruthful), "statistics_parts": stat_parts,
                    "lab_tests": len(vals_in), "tokens_total": tt, "tokens_kept": tk,
                    "records": len(rec_units), "records_locatable": rec_ok},
        "losses": losses,
    }


# ----------------------------------------------------------------------------
# 3. Privacy (tools/redteam.py A1-A7)
# ----------------------------------------------------------------------------

def _transcoded_copy(src: Path, dst: Path) -> int:
    """Copy a release, re-encoding sanitized files that are not UTF-8 (redteam.py reads UTF-8)."""
    n = 0
    for p in walk_files(src):
        rel = p.relative_to(src)
        if rel.parts[0] == "quarantine":
            continue
        raw = p.read_bytes()
        if rel.parts[0] == "sanitized":
            try:
                (raw[3:] if raw.startswith(BOM) else raw).decode("utf-8")
            except UnicodeDecodeError:
                raw = decode_input(raw).encode("utf-8")
                n += 1
        q = dst / rel
        q.parent.mkdir(parents=True, exist_ok=True)
        q.write_bytes(raw)
    return n


def _redteam_once(ctx: Ctx, out_dir: Path, other, tmp: str):
    cmd = [sys.executable, str(ROOT / "tools" / "redteam.py"), "--output", str(out_dir), "--kit", str(ctx.kit),
           "--json", tmp]
    if other:
        cmd += ["--other", str(other)]
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
    return r.returncode


def run_redteam(ctx: Ctx, args):
    if args.redteam_json:
        return json.loads(Path(args.redteam_json).read_text(encoding="utf-8")), None
    fd, tmp = tempfile.mkstemp(prefix="scorecard-rt-", suffix=".json")
    os.close(fd)
    work = None
    try:
        rc = _redteam_once(ctx, ctx.out_dir, args.other, tmp)
        if rc != 0:
            # redteam.py cannot read non-UTF-8 sanitized files (for example a raw UTF-16 copy):
            # retry on a copy where only those files are re-encoded, as an attacker would.
            work = Path(tempfile.mkdtemp(prefix="scorecard-rt-"))
            n = _transcoded_copy(ctx.out_dir, work / "a")
            other = None
            if args.other:
                same = Path(args.other).resolve() == ctx.out_dir.resolve()
                if same:
                    other = work / "a"
                else:
                    n += _transcoded_copy(Path(args.other), work / "b")
                    other = work / "b"
            rc = _redteam_once(ctx, work / "a", other, tmp)
            if rc != 0:
                return None, f"redteam.py exited with {rc}"
            ctx.notes.append(f"redteam.py needed a UTF-8 re-encoded copy of the release ({n} files)")
        return json.loads(Path(tmp).read_text(encoding="utf-8")), None
    except (OSError, ValueError) as exc:
        return None, f"redteam.py failed: {type(exc).__name__}"
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)


def cat_privacy(ctx: Ctx, rt, rt_err, utility: float, maxpts: float) -> dict:
    thr = float(ctx.cfg.get("privacy", {}).get("utility_coupling_threshold", 0.40))
    coupling = min(1.0, utility / thr) if thr > 0 else 1.0
    if rt is None:
        ctx.notes.append(f"privacy not measured ({rt_err}); scored as risk 1.0")
        risk, comps = 1.0, []
    else:
        comps = list(rt.get("components") or [])
        n_psn = (rt.get("ours") or {}).get("pseudonyms")
        if n_psn == 0 and any("A6" in str(c.get("name")) for c in comps):
            # ATTACKS.md / SCORING.md: A6 applies only if pseudonyms exist
            comps = [c for c in comps if "A6" not in str(c.get("name"))]
            ctx.notes.append("privacy A6 dropped: the release has no pseudonyms (SCORING: only if pseudonyms exist)")
        wsum0 = sum(float(c.get("weight", 0)) for c in comps)
        risk = (sum(min(1.0, max(0.0, float(c.get("ratio", 0.0)))) * float(c.get("weight", 0)) for c in comps)
                / wsum0) if wsum0 else float(rt.get("overall_risk", 1.0))
        if not any("A7" in str(c.get("name")) for c in comps):
            ctx.notes.append("privacy A7 (cross-release) not measured: pass --other; weights renormalised")
    score = (1.0 - risk) * coupling
    wsum = sum(float(c.get("weight", 0)) for c in comps) or 1.0
    losses, comp_out = [], {}
    ours = (rt or {}).get("ours") or {}
    cr = ours.get("cross_release") or {}
    extra = {"A5": f"; signal hits {ours.get('targeted_signal_hits')}, recovered global shift "
                   f"{ours.get('recovered_global_shift_days')} days, decoy false claims "
                   f"{float(ours.get('decoy_false_claims') or 0):.2f}",
             "A7": (f"; stable pseudonyms {float(cr.get('stable_pseudonyms') or 0):.3f}, stable dates "
                    f"{float(cr.get('stable_dates') or 0):.3f}") if cr else ""}
    for c in comps:
        r = min(1.0, max(0.0, float(c.get("ratio", 0.0))))
        comp_out[str(c.get("name"))] = {"raw": c.get("raw"), "ours": c.get("ours"), "risk": r,
                                        "weight": c.get("weight")}
        pts = maxpts * coupling * float(c.get("weight", 0)) / wsum * r
        tag = str(c.get("name")).split(" ")[0]
        if pts > 1e-6:
            losses.append((pts, f"privacy.{tag}",
                           f"{c.get('name')} risk {r:.3f} (ours {float(c.get('ours') or 0):.3f} vs raw "
                           f"{float(c.get('raw') or 0):.3f}, weight {c.get('weight')}){extra.get(tag, '')}"))
    if coupling < 1.0:
        losses.append((maxpts * (1 - risk) * (1 - coupling), "privacy.utility_coupling",
                       f"utility {utility:.3f} < {thr:.2f}: privacy credit x {coupling:.3f}"))
    return {"score": score, "parts": {"resistance": 1.0 - risk, "utility_coupling": coupling},
            "details": {"overall_risk": risk, "components": comp_out,
                        "redteam_privacy_points_uncoupled": (rt or {}).get("privacy_points")},
            "losses": losses}


# ----------------------------------------------------------------------------
# Side channels, canaries and critical identifiers
# ----------------------------------------------------------------------------

def item_id(e: dict):
    """Unique key of a critical identifier / full name, as used for penalties and scans."""
    m = e.get("match")
    if m == "name":
        toks = tuple(t for t in (norm(x) for x in e.get("tokens") or []) if t)
        if len(toks) >= 2:
            return ("n", toks)
        s = norm(e.get("surface"))
        return ("t", s) if s else None
    keys = entity_keys(e)
    return keys[0] if keys else None


def critical_items(ctx: Ctx):
    """(items, canaries): items = id -> type for critical non-canary identifiers and full
    patient names; canaries = person -> set of ids."""
    items, canaries = {}, defaultdict(set)
    for f in ctx.files.values():
        for u in f["units"].values():
            for e in u.get("entities") or []:
                iid = item_id(e)
                if iid is None:
                    continue
                if is_canary(e):
                    canaries[e.get("person") or "canary"].add(iid)
                    continue
                if not e.get("critical"):
                    continue
                if e.get("match") == "name" and not e.get("full"):
                    continue
                items.setdefault(iid, e.get("type"))
    return items, canaries


def scan_hay(hay: Hay, ids) -> set:
    found = set()
    for iid in ids:
        kind, val = iid
        hit = hay.has_phrase(val) if kind == "n" else hay.count(kind, val) > 0
        if hit:
            found.add(iid)
    return found


def _read_text(p: Path) -> str:
    try:
        return p.read_bytes()[: 50 * 1024 * 1024].decode("utf-8", "replace")
    except OSError:
        return ""


def scan_side_channels(ctx: Ctx, args, items: dict, canaries: dict) -> dict:
    out = ctx.out_dir
    all_files = walk_files(out)
    groups = defaultdict(list)
    names = []
    for p in all_files:
        rel = p.relative_to(out).as_posix()
        top = rel.split("/", 1)[0]
        if top == "quarantine":
            continue
        names.append(rel)
        if top == "sanitized":
            groups["sanitized"].append(p)
        elif rel == "report.json":
            groups["report.json"].append(p)
        elif rel == "records.jsonl":
            groups["records.jsonl"].append(p)
        elif top == "logs":
            groups["logs"].append(p)
        else:
            groups["other_files"].append(p)
    texts = {}
    for ch in ("report.json", "records.jsonl", "logs", "other_files"):
        texts[ch] = _LONG_HEX.sub(" ", "\n".join(_read_text(p) for p in groups[ch])) if groups[ch] else None
    texts["file_names"] = re.sub(r"[_.\-/]+", " ", "\n".join(names))
    texts["stdout_stderr"] = _read_text(Path(args.stdout)) if args.stdout else None
    channels, hits_all = {}, set()
    hays = {}
    for ch, txt in texts.items():
        if txt is None:
            channels[ch] = (1.0, "absent" if ch != "stdout_stderr" else "not given: assumed clean")
            continue
        h = hays[ch] = Hay(txt)
        hits = scan_hay(h, items)
        can = {pid for pid, ids in canaries.items() if scan_hay(h, ids)}
        hits_all |= hits
        if hits or can:
            channels[ch] = (0.0, f"{len(hits)} identifiers/full names, {len(can)} canaries")
        elif ch == "other_files":
            channels[ch] = (0.5, f"{len(groups[ch])} leftover files without PII")
        else:
            channels[ch] = (1.0, "clean")
    channels["tmpdir_home"] = (1.0, "not observable: assumed clean")
    if not args.stdout:
        ctx.notes.append("stdout/stderr not given (--stdout): assumed clean")
    ctx.notes.append("TMPDIR/HOME not observable: assumed clean")
    # canaries anywhere in the output folder (quarantine/ excluded)
    found = set()
    can_ids = {pid: ids for pid, ids in canaries.items()}
    for h in hays.values():
        for pid, ids in can_ids.items():
            if pid not in found and scan_hay(h, ids):
                found.add(pid)
    for p in groups["sanitized"]:
        if len(found) == len(can_ids):
            break
        rel = p.relative_to(ctx.rel.san).as_posix()
        doc = ctx.out_doc_rel(rel)
        h = doc.hay("doc") if doc is not None else Hay(_read_text(p))
        for pid, ids in can_ids.items():
            if pid not in found and scan_hay(h, ids):
                found.add(pid)
    return {"channels": channels, "hits": hits_all, "canaries_found": found, "canaries_total": len(can_ids)}


# ----------------------------------------------------------------------------
# 5. Integrity
# ----------------------------------------------------------------------------

def format_ok(raw: bytes, fmt: str, delim: str):
    body = raw[3:] if raw.startswith(BOM) else raw
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return False, "not UTF-8"
    if fmt in ("pdf", "binary"):
        return False, f"{fmt} exported"
    if fmt in ("csv", "tsv"):
        try:
            for _ in csv.reader(io.StringIO(text, newline=""), delimiter=delim, strict=True):
                pass
        except csv.Error:
            return False, "CSV does not parse"
    elif fmt in ("json", "fhir"):
        try:
            json.loads(text, parse_constant=_reject_json_constant, parse_float=_finite_json_float)
        except (ValueError, RecursionError):
            return False, "JSON does not parse"
    elif fmt == "xml":
        try:
            ET.fromstring(text)
        except ET.ParseError:
            return False, "XML does not parse"
    return True, ""


def _wildcard(paths: dict, slots: set) -> dict:
    out = {}
    for p, types in paths.items():
        segs = p.split("/")
        for i in range(1, len(segs)):
            if "/".join(segs[:i]) in slots:
                segs[i] = "*"
        out.setdefault("/".join(segs), set()).update(types)
    return out


def json_schema_score(ctx: Ctx, rel: str, ind: Doc, outd: Doc) -> float:
    f = ctx.files[rel]
    if not outd.parsed():
        return 0.0
    pi, po = key_paths(ind.obj), key_paths(outd.obj)
    gen = [g for g in f.get("generalizable") or [] if str(g).startswith("/")]
    pii_keys = [k for u in f["units"].values() for e in u.get("entities") or [] if e.get("channel") == "key"
                for k in entity_keys(e)]
    slots = set()
    if pii_keys:
        for p in pi:
            segs = p.split("/")
            for i in range(1, len(segs)):
                ns = norm(segs[i])
                if any(key_regex(k, v) is not None and key_regex(k, v).search(ns) for k, v in pii_keys
                       if k in ("w", "d", "x", "t")):
                    slots.add("/".join(segs[:i]))
                    break
        pi, po = _wildcard(pi, slots), _wildcard(po, slots)

    def keep(p):
        return not any(p == g or p.startswith(g + "/") for g in gen)

    a = {p: t for p, t in pi.items() if keep(p)}
    b = {p: t for p, t in po.items() if keep(p)}
    union = set(a) | set(b)
    inter = set(a) & set(b)
    jac = len(inter) / len(union) if union else 1.0
    types = sum(1 for p in inter if a[p] == b[p]) / len(inter) if inter else (1.0 if not union else 0.0)
    return (jac + types) / 2


_FHIR_VALIDATE = None


def fhir_validator():
    global _FHIR_VALIDATE
    if _FHIR_VALIDATE is None:
        spec = importlib.util.spec_from_file_location("medveil_fhir_validate", ROOT / "tools" / "fhir_validate.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _FHIR_VALIDATE = mod.validate
    return _FHIR_VALIDATE


def odisp(ctx: Ctx, out_rel: str) -> str:
    src = ctx.rel.reverse.get(out_rel)
    if src is not None and src not in ctx.pii_named:
        return out_rel
    if src is not None:
        return ctx.disp(src)
    return f"<unmapped output {hashlib.sha256(out_rel.encode('utf-8')).hexdigest()[:8]}>"


def cat_integrity(ctx: Ctx, side: dict, maxpts: float) -> dict:
    wts = {k: float(v) for k, v in ctx.cfg.get("integrity", {}).get("weights", {}).items()}
    R = ctx.rel
    # format validity
    fv_bad = Counter()
    fv_files = Counter()
    n_fv = ok_fv = 0
    for out_rel in sorted(R.san_files):
        src = R.reverse.get(out_rel)
        f = ctx.files.get(src) if src else None
        fmt = f["format"] if f else fmt_from_ext(out_rel)
        delim = (f.get("delimiter") if f else None) or ("\t" if fmt == "tsv" else ",")
        try:
            raw = (R.san / out_rel).read_bytes()
        except OSError:
            raw = b"\xff"
        ok, why = format_ok(raw, fmt, delim)
        n_fv += 1
        ok_fv += ok
        if not ok:
            fv_bad[why] += 1
            fv_files[odisp(ctx, out_rel)] += 1
    format_validity = ok_fv / n_fv if n_fv else 0.0
    # schema preservation
    sch, sch_bad = [], Counter()
    for rel in sorted(ctx.files):
        f = ctx.files[rel]
        if f.get("expect") == "either" or not R.mapping.get(rel):
            continue
        ind, outd = ctx.in_doc(rel), ctx.out_doc(rel)
        if ind is None or outd is None:
            continue
        fmt = f["format"]
        if fmt in ("csv", "tsv"):
            ri, ro = ind.rows, outd.rows
            if not ri:
                continue
            hi, ho = ri[0], (ro[0] if ro else [])
            c1 = 1.0 if len(hi) == len(ho) else 0.0
            header_pii = any(u.get("entities") for loc, u in f["units"].items() if loc == "@header")
            c2 = c1 if header_pii else (1.0 if [h.strip() for h in hi] == [h.strip() for h in ho] else 0.0)
            ni, no = len(ri) - 1, max(0, len(ro) - 1)
            c3 = 1.0 if ni == no else 0.0
            m = max(ni, no)
            same = sum(1 for k in range(min(ni, no)) if len(ri[k + 1]) == len(ro[k + 1]))
            c4 = same / m if m else 1.0
            s = (c1 + c2 + c3 + c4) / 4
        elif fmt in ("json", "fhir"):
            if not ind.parsed():
                continue
            s = json_schema_score(ctx, rel, ind, outd)
        elif fmt == "text":
            li, lo = len(ind.text.splitlines()), len(outd.text.splitlines())
            s = min(li, lo) / max(li, lo) if max(li, lo) else 1.0
        else:
            continue
        sch.append(s)
        if s < 1:
            sch_bad[ctx.disp(rel)] += round(1 - s, 3)
    schema = sum(sch) / len(sch) if sch else 0.0
    # FHIR validity
    fhir_rel = [rel for rel, f in ctx.files.items() if f.get("format") == "fhir"]
    fhir_ok, fhir_bad = 0, Counter()
    for rel in fhir_rel:
        outd = ctx.out_doc(rel)
        good = False
        if outd is not None and outd.parsed() and isinstance(outd.obj, dict):
            try:
                good = not fhir_validator()(outd.obj)
            except Exception:  # noqa: BLE001 - a crashing validator means invalid
                good = False
        fhir_ok += good
        if not good:
            fhir_bad[ctx.disp(rel)] += 1
    fhir_validity = fhir_ok / len(fhir_rel) if fhir_rel else 1.0
    # pseudonym consistency
    claims = [c for c in R.claim_list if c["patient"]]
    valid = sum(1 for c in claims if ctx.claim_valid(c))
    consistency = valid / len(claims) if claims else 0.0
    # channel hygiene
    ch = side["channels"]
    hygiene = sum(v[0] for v in ch.values()) / len(ch)
    # quarantine handling
    either = [rel for rel, f in ctx.files.items() if f.get("expect") == "either"]
    safe = copies = 0
    copy_rel = []
    for rel in either:
        f = ctx.files[rel]
        out_rel = R.mapping.get(rel)
        ind = ctx.in_doc(rel)
        is_copy = False
        if out_rel:
            try:
                is_copy = ind is not None and (R.san / out_rel).read_bytes() == ind.raw
            except OSError:
                is_copy = False
            safe += not is_copy
        else:
            safe += bool(R.declared_status(f.get("sha256", "")) & {"quarantined", "suppressed"})
        copies += is_copy
        if is_copy:
            copy_rel.append(rel)
    silent = [rel for rel, f in ctx.files.items()
              if not R.mapping.get(rel)
              and not R.declared_status(f.get("sha256", "")) & {"quarantined", "suppressed"}]
    n_in = len(ctx.files)
    q_parts = {"handled_safely": safe / len(either) if either else 1.0,
               "no_silent_drop": 1 - len(silent) / n_in if n_in else 1.0,
               "no_unprocessed_copy": 1 - copies / len(either) if either else 1.0}
    quarantine = sum(QUARANTINE_MIX[k] * v for k, v in q_parts.items())
    # report quality
    rep = R.report
    if rep is None:
        completeness = honesty = 0.0
        rq_msg = f"report.json {R.report_error}"
    else:
        shas = {f.get("sha256") for f in ctx.files.values()}
        listed = {str(e.get("input_sha256", "")).lower() for e in R.entries if e.get("status") in STATUSES}
        counts = rep.get("counts") if isinstance(rep.get("counts"), dict) else {}
        checks = [
            1.0 if rep.get("schema") == "raksha-report/1" else 0.0,
            len(shas & listed) / len(shas) if shas else 1.0,
            sum(1 for k in REPORT_COUNTS if isinstance(counts.get(k), (int, float))) / len(REPORT_COUNTS),
            1.0 if isinstance(rep.get("entities"), dict) else 0.0,
            1.0 if isinstance(_as_dict(rep.get("timing")).get("seconds"), (int, float)) else 0.0,
            1.0 if isinstance(_as_dict(rep.get("resources")).get("peak_rss_mb"), (int, float)) else 0.0,
        ]
        completeness = sum(checks) / len(checks)
        exported = sum(1 for rel in ctx.files if R.mapping.get(rel))
        truth_counts = {"files_total": n_in, "files_sanitized": exported, "files_quarantined": n_in - exported}
        hon = [1.0 if counts.get(k) == v else 0.0 for k, v in truth_counts.items()]
        honesty = sum(hon) / len(hon)
        rq_msg = (f"completeness {completeness:.3f} (schema, files listed, counts, entities, timing, resources = "
                  + "/".join(f"{c:.2f}" for c in checks) + f"); honesty {honesty:.3f} (reported "
                  + ", ".join(f"{k}={counts.get(k)}" for k in truth_counts) + " vs real "
                  + ", ".join(f"{k}={v}" for k, v in truth_counts.items()) + ")")
    report_quality = REPORT_MIX["completeness"] * completeness + REPORT_MIX["honesty"] * honesty
    parts = {"format_validity": format_validity, "schema_preservation": schema, "fhir_validity": fhir_validity,
             "pseudonym_consistency": consistency, "channel_hygiene": hygiene,
             "quarantine_handling": quarantine, "report_quality": report_quality}
    wsum = sum(wts.get(k, 0.0) for k in parts)
    score = sum(wts.get(k, 0.0) * v for k, v in parts.items()) / wsum if wsum else 0.0
    dirty = [f"{k} ({v[1]})" for k, v in ch.items() if v[0] < 1]
    msgs = {
        "format_validity": f"{n_fv - ok_fv} of {n_fv} sanitized files invalid ({top_items(fv_bad)}); "
                           f"files: {top_items(fv_files)}",
        "schema_preservation": f"{sum(1 for s in sch if s < 1)} of {len(sch)} files changed shape; "
                               f"worst: {top_items(sch_bad)}",
        "fhir_validity": f"{len(fhir_rel) - fhir_ok} of {len(fhir_rel)} FHIR bundles missing or failing the "
                         f"structural checks: {top_items(fhir_bad)}",
        "pseudonym_consistency": f"{len(claims) - valid} of {len(claims)} records.jsonl claims whose pseudonym "
                                 f"is not in the exported record" if claims else "no non-null claims in records.jsonl",
        "channel_hygiene": "dirty channels: " + ("; ".join(dirty) or "-"),
        "quarantine_handling": ", ".join(f"{k} {v:.3f}" for k, v in q_parts.items())
                               + f" ({len(silent)} silently dropped, {copies} raw copies of malformed/unsupported "
                                 f"files: {', '.join(ctx.disp(r) for r in copy_rel[:4]) or '-'})",
        "report_quality": rq_msg,
    }
    losses = []
    for k, v in parts.items():
        pts = maxpts * wts.get(k, 0.0) / (wsum or 1) * (1 - v)
        if pts > 1e-6:
            losses.append((pts, f"integrity.{k}", f"{v:.3f}: {msgs[k]}"))
    return {"score": score, "parts": parts,
            "details": {"sanitized_files": n_fv, "invalid_files": n_fv - ok_fv, "schema_files": len(sch),
                        "fhir_bundles": len(fhir_rel), "fhir_valid": fhir_ok, "claims": len(claims),
                        "claims_valid": valid, "channels": {k: {"score": v[0], "note": v[1]} for k, v in ch.items()},
                        "quarantine_parts": q_parts, "silently_dropped": len(silent),
                        "raw_copies_of_either_files": copies, "report": msgs["report_quality"]},
            "losses": losses, "_silent": silent, "_copies": copy_rel}


# ----------------------------------------------------------------------------
# 6. Performance
# ----------------------------------------------------------------------------

def loglin(x, good, limit) -> float:
    if x <= good:
        return 1.0
    if x >= limit:
        return 0.0
    return 1.0 - (math.log(x) - math.log(good)) / (math.log(limit) - math.log(good))


def _tree_bytes(root: Path) -> dict:
    out = {}
    san = root / "sanitized"
    for p in walk_files(san):
        out["sanitized/" + p.relative_to(san).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    rj = root / "records.jsonl"
    out["records.jsonl"] = hashlib.sha256(rj.read_bytes()).hexdigest() if rj.is_file() else None
    return out


def cat_performance(ctx: Ctx, args, maxpts: float) -> dict:
    profs = ctx.cfg.get("performance", {}).get("profiles", {})
    prof = profs.get(args.profile) or profs.get("small") or {}
    rep = ctx.rel.report or {}
    secs = args.wall_seconds if args.wall_seconds is not None else (rep.get("timing") or {}).get("seconds")
    mem = args.peak_mb if args.peak_mb is not None else (rep.get("resources") or {}).get("peak_rss_mb")
    rc = args.exit_code
    reliability = 1.0 if rc == 0 else (0.0 if rc is None or rc < 0 else 0.3)
    if isinstance(secs, (int, float)):
        wall = loglin(float(secs), float(prof.get("time_good_s", 15)), float(prof.get("time_limit_s", 300)))
    else:
        wall = 1.0
        ctx.notes.append("wall time not in report.json: not measured, scored 1.0")
    if isinstance(mem, (int, float)) and mem > 0:
        memory = loglin(float(mem), float(prof.get("memory_good_mb", 512)), float(prof.get("memory_limit_mb", 4096)))
    else:
        memory = 1.0
        ctx.notes.append("peak memory not in report.json: not measured, scored 1.0")
    det_msg = "not measured"
    if args.repeat:
        a, b = _tree_bytes(ctx.out_dir), _tree_bytes(Path(args.repeat))
        keys = sorted(set(a) | set(b))
        same = sum(1 for k in keys if a.get(k) is not None and a.get(k) == b.get(k))
        determinism = same / len(keys) if keys else 1.0
        det_msg = f"{len(keys) - same} of {len(keys)} sanitized files / records.jsonl differ between runs"
    else:
        determinism = 1.0
        ctx.notes.append("determinism not measured (no --repeat): scored 1.0")
    parts = {"reliability": reliability, "wall_time": wall, "peak_memory": memory, "determinism": determinism}
    wsum = sum(PERF_WEIGHTS.values())
    score = sum(PERF_WEIGHTS[k] * v for k, v in parts.items()) / wsum
    msgs = {"reliability": f"exit code {rc}", "wall_time": f"{secs} s vs good {prof.get('time_good_s')} s / "
            f"limit {prof.get('time_limit_s')} s ({args.profile})",
            "peak_memory": f"{mem} MB vs good {prof.get('memory_good_mb')} MB", "determinism": det_msg}
    losses = [(maxpts * PERF_WEIGHTS[k] / wsum * (1 - v), f"performance.{k}", f"{v:.3f}: {msgs[k]}")
              for k, v in parts.items() if v < 1]
    return {"score": score, "parts": parts,
            "details": {"profile": args.profile, "seconds": secs, "peak_rss_mb": mem, "determinism": det_msg,
                        "scaling": "not measured"},
            "losses": losses}


# ----------------------------------------------------------------------------
# Penalties
# ----------------------------------------------------------------------------

def cat_penalties(ctx: Ctx, ents: list, side: dict, integ: dict, items: dict) -> dict:
    pc = ctx.cfg.get("penalties", {})
    uniq = {}
    for e in ents:
        if not e["critical"] or e["canary"] or not e["all_leaked"]:
            continue
        if e["match"] == "name" and not e["full"]:
            continue
        if e["item"] is not None:
            uniq.setdefault(e["item"], (e["type"], ctx.disp(e["rel"]), e["loc"]))
    for iid in side["hits"]:
        uniq.setdefault(iid, (items.get(iid), "side channel", "-"))
    n_leak = len(uniq)
    leak_pts = min(float(pc.get("leaked_identifier_cap", 25)), n_leak * float(pc.get("per_leaked_identifier", 1.0)))
    n_can = len(side["canaries_found"])
    can_pts = min(float(pc.get("canary_cap", 15)), n_can * float(pc.get("per_canary_leak", 3)))
    unproc = [rel for rel in integ["_copies"]
              if any(u.get("entities") for u in ctx.files[rel]["units"].values())]
    un_pts = min(float(pc.get("unprocessed_cap", 20)), len(unproc) * float(pc.get("per_unprocessed_export", 5)))
    false_success = ctx.rel.report is None or bool(integ["_silent"])
    fs_pts = float(pc.get("false_success", 10)) if false_success else 0.0
    tampered = []
    for rel, f in ctx.files.items():
        d = ctx.in_doc(rel)
        if d is None or hashlib.sha256(d.raw).hexdigest() != f.get("sha256"):
            tampered.append(rel)
    tp_pts = float(pc.get("input_tampering", 5)) if tampered else 0.0
    by_type = Counter(v[0] for v in uniq.values())
    by_file = Counter(v[1] for v in uniq.values())
    pens = {
        "leaked_identifiers": {"count": n_leak, "points": leak_pts,
                               "note": f"unique critical identifiers / full names by type: {top_items(by_type, 6)}; "
                                       f"files: {top_items(by_file, 4)}"},
        "canaries": {"count": n_can, "points": can_pts,
                     "note": f"{n_can} of {side['canaries_total']} canary identities found in the output folder"},
        "unprocessed_exports": {"count": len(unproc), "points": un_pts,
                                "note": "malformed/unsupported PII files copied byte-for-byte: "
                                        + (", ".join(ctx.disp(r) for r in unproc) or "-")},
        "false_success": {"count": int(false_success), "points": fs_pts,
                          "note": ("report.json missing" if ctx.rel.report is None else
                                   f"{len(integ['_silent'])} input files silently dropped")},
        "input_tampering": {"count": len(tampered), "points": tp_pts,
                            "note": f"{len(tampered)} input files differ from the truth hashes"},
    }
    return pens


# ----------------------------------------------------------------------------
# Orchestration
# ----------------------------------------------------------------------------

CATS = [("detection", "1. detection & context"), ("identity_resolution", "2. identity resolution"),
        ("privacy", "3. privacy (attack arena)"), ("utility", "4. clinical utility"),
        ("integrity", "5. integrity & export"), ("performance", "6. performance")]


def guess_kit(truth_path: Path) -> Path:
    try:
        cand = truth_path.resolve().parents[2]
    except IndexError:
        return DEFAULT_KIT
    if (cand / "scoring.toml").is_file() and (cand / "dev" / "attacker").is_dir():
        return cand
    return DEFAULT_KIT


def score_release(args) -> dict:
    t0 = time.monotonic()
    truth_path = Path(args.truth)
    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    kit = Path(args.kit) if args.kit else guess_kit(truth_path)
    cfg_path = Path(args.config) if args.config else kit / "scoring.toml"
    cfg_bytes = cfg_path.read_bytes()
    cfg = load_toml(cfg_path)
    ctx = Ctx(truth, truth_path, Path(args.input), Path(args.output), cfg,
              hashlib.sha256(cfg_bytes).hexdigest(), kit)
    kit_truth = kit / "dev" / "truth" / "truth.json"
    if not kit_truth.is_file() or kit_truth.resolve() != truth_path.resolve():
        ctx.notes.append("redteam.py attacks the kit's practice data; --truth is a different dataset, so the "
                         "privacy number may not describe this release")
    W = {k: float(v) for k, v in cfg.get("weights", {}).items()}
    maxp = {k: 100.0 * W.get(k, 0.0) for k, _ in CATS}

    ents, located = compute_leaks(ctx)
    tokret = token_retention(ctx)
    det = cat_detection(ctx, ents, tokret, maxp["detection"])
    ident = cat_identity(ctx, maxp["identity_resolution"])
    util = cat_utility(ctx, tokret, located, maxp["utility"])
    rt, rt_err = run_redteam(ctx, args)
    priv = cat_privacy(ctx, rt, rt_err, util["score"], maxp["privacy"])
    items, canaries = critical_items(ctx)
    side = scan_side_channels(ctx, args, items, canaries)
    integ = cat_integrity(ctx, side, maxp["integrity"])
    perf = cat_performance(ctx, args, maxp["performance"])
    pens = cat_penalties(ctx, ents, side, integ, items)
    if args.exit_code == 0:
        ctx.notes.append("reliability assumes exit code 0 (pass --exit-code otherwise)")
    ctx.notes.append("performance scaling (optional part) not measured")

    cats = {"detection": det, "identity_resolution": ident, "privacy": priv, "utility": util,
            "integrity": integ, "performance": perf}
    pw = {"identity_resolution": IDENTITY_MIX,
          "utility": {k: float(v) for k, v in cfg.get("utility", {}).get("weights", {}).items()},
          "integrity": {k: float(v) for k, v in cfg.get("integrity", {}).get("weights", {}).items()},
          "performance": PERF_WEIGHTS}
    for k, c in cats.items():
        c["weight"] = W.get(k, 0.0)
        c["points"] = 100.0 * c["weight"] * c["score"]
        c["part_weights"] = pw.get(k, {})
    subtotal = sum(c["points"] for c in cats.values())
    pen_total = sum(p["points"] for p in pens.values())
    losses = []
    for c in cats.values():
        losses.extend(c.pop("losses"))
        c.pop("_silent", None)
        c.pop("_copies", None)
    for k, p in pens.items():
        if p["points"] > 0:
            losses.append((p["points"], f"penalty.{k}", f"{p['count']} x: {p['note']}"))
    losses.sort(key=lambda x: (-x[0], x[1]))
    return {
        "schema": "medveil-scorecard/1",
        "output": str(args.output), "profile": args.profile,
        "scoring_toml_sha256": ctx.cfg_sha,
        "categories": cats, "subtotal": subtotal, "penalties": pens, "penalty_total": pen_total,
        "total": subtotal - pen_total,
        "losses": [{"points": round(p, 4), "key": k, "message": m} for p, k, m in losses],
        "notes": list(dict.fromkeys(ctx.notes)),
        "scoring_seconds": round(time.monotonic() - t0, 2),
    }


def _detail_lines(key: str, c: dict) -> list:
    d = c["details"]
    if key == "detection":
        return [f"recall = {d['type_mix']:.1f} x type macro {d['recall_type_macro']:.3f} + {1 - d['type_mix']:.1f} x "
                f"script macro {d['recall_script_macro']:.3f}; F{d['beta']:g}",
                "scripts: " + ", ".join(f"{k} {v:.3f}" for k, v in d["recall_by_script"].items()),
                "types: " + ", ".join(f"{k} {v:.2f}" for k, v in d["recall_by_type"].items()),
                "precision groups: " + ", ".join(f"{k} {v:.2f}" for k, v in d["precision_groups"].items())]
    if key == "identity_resolution":
        return [f"pairwise P {d['pairwise_precision']:.3f} R {d['pairwise_recall']:.3f}; false-merge pairs "
                f"{d['false_merge_pairs']}; linked {d['linked_pairs']}/{d['linkable_pairs']}; B3 P "
                f"{d['b3_precision']:.3f} R {d['b3_recall']:.3f}",
                f"claims with pseudonym {d['claims_with_pseudonym']}; unit claims dropped (pseudonym not in the "
                f"record): {d['unit_claims_dropped_not_in_record']}"]
    if key == "privacy":
        lines = [f"overall attack risk {d['overall_risk']:.4f}"]
        for n, v in d["components"].items():
            lines.append(f"{n:<24} raw {float(v['raw'] or 0):.3f} ours {float(v['ours'] or 0):.3f} "
                         f"risk {v['risk']:.3f} w {v['weight']}")
        return lines
    if key == "utility":
        s = d["statistics_parts"]
        return [f"temporal: intervals {d['intervals']:.3f} over {d['date_pairs']} pairs, LOS "
                + (f"{d['length_of_stay']:.3f}" if d["length_of_stay"] is not None else "n/a")
                + f" over {d['los_pairs']} stays",
                "generalization: " + ", ".join(f"{k} {v:.2f}" for k, v in sorted(d["generalization_by_kind"].items())),
                "statistics: " + ", ".join(f"{k} {v:.3f}" for k, v in s.items()),
                f"tokens kept {d['tokens_kept']}/{d['tokens_total']}; records locatable "
                f"{d['records_locatable']}/{d['records']}"]
    if key == "integrity":
        ch = d["channels"]
        return ["channels: " + ", ".join(f"{k} {v['score']:g}" for k, v in ch.items()),
                "quarantine: " + ", ".join(f"{k} {v:.2f}" for k, v in d["quarantine_parts"].items()),
                f"FHIR {d['fhir_valid']}/{d['fhir_bundles']} valid; claims consistent "
                f"{d['claims_valid']}/{d['claims']}; invalid files {d['invalid_files']}/{d['sanitized_files']}"]
    if key == "performance":
        return [f"profile {d['profile']}: {d['seconds']} s, {d['peak_rss_mb']} MB; determinism: {d['determinism']}"]
    return []


def _wrap(line: str, width: int) -> list:
    out, cur = [], ""
    for word in line.split(" "):
        if cur and len(cur) + 1 + len(word) > width:
            out.append(cur)
            cur = "  " + word
        else:
            cur = f"{cur} {word}" if cur else word
    if cur:
        out.append(cur)
    return out


def print_card(res: dict, top: int = 10) -> None:
    W = 96
    print("=" * W)
    print(" RAKSHA scorecard ESTIMATE (dev-only; practice truth; not the official evaluator)")
    print(f" release: {Path(res['output']).name}   profile: {res['profile']}   "
          f"scoring.toml sha256: {res['scoring_toml_sha256'][:16]}")
    print("=" * W)
    print(f" {'category / part':<36}{'weight':>8}{'score':>9}{'points':>10}{'max':>9}")
    print("-" * W)
    for key, label in CATS:
        c = res["categories"][key]
        print(f" {label:<36}{c['weight']:>8.2f}{c['score']:>9.3f}{c['points']:>10.2f}{100 * c['weight']:>9.2f}")
        for part, val in c["parts"].items():
            sw = c["part_weights"].get(part)
            sws = f"{sw:.2f}" if sw is not None else ""
            print(f"   {part:<34}{sws:>8}{val:>9.3f}")
        for line in _detail_lines(key, c):
            for chunk in _wrap(line, W - 8):
                print(f"     . {chunk}")
    print("-" * W)
    print(f" {'subtotal':<36}{'':>8}{'':>9}{res['subtotal']:>10.2f}{100:>9.2f}")
    print(" penalties")
    for k, p in res["penalties"].items():
        print(f"   {k:<34}{p['count']:>8}{'':>9}{-p['points']:>10.2f}   {p['note']}"[:W + 60])
    print("-" * W)
    print(f" {'TOTAL (estimate, out of 100)':<36}{'':>8}{'':>9}{res['total']:>10.2f}")
    print("=" * W)
    print(f" Top {top} point losses (points, key: score: what to fix)")
    for i, item in enumerate(res["losses"][:top], 1):
        print(f" {i:>2}. -{item['points']:5.2f}  {item['key']} {item['message']}")
    if res["notes"]:
        print(" Notes:")
        for n in res["notes"]:
            print(f"   - {n}")
    print(f" (scored in {res['scoring_seconds']} s)")


# ----------------------------------------------------------------------------
# Calibration baselines
# ----------------------------------------------------------------------------

def _starter_decode(raw: bytes):
    if raw.startswith(BOM):
        try:
            return raw[3:].decode("utf-8")
        except UnicodeDecodeError:
            return None
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return raw.decode("utf-16")
        except UnicodeDecodeError:
            return None
    for enc in ("utf-8", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


def _letters(i: int) -> str:
    """0 -> a, 25 -> z, 26 -> ba ...: key names without digits (redteam reads digit runs)."""
    s = ""
    while True:
        s = chr(97 + i % 26) + s
        i //= 26
        if i == 0:
            return s


def _destroy(node, keys: bool):
    if isinstance(node, dict):
        return {(f"k{_letters(i)}" if keys else k): _destroy(v, keys) for i, (k, v) in enumerate(node.items())}
    if isinstance(node, list):
        return [_destroy(v, keys) for v in node]
    if isinstance(node, bool) or node is None:
        return node
    if isinstance(node, (int, float)):
        return 0
    return "X"


def _redact_bytes(raw: bytes, ext: str, keys: bool):
    if not raw.strip() or ext not in (".csv", ".tsv", ".json", ".txt"):
        return None
    text = _starter_decode(raw)
    if text is None:
        return None
    if ext in (".csv", ".tsv"):
        delim = "\t" if ext == ".tsv" else ","
        try:
            rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delim))
        except csv.Error:
            return None
        buf = io.StringIO()
        w = csv.writer(buf, delimiter=delim, lineterminator="\n")
        for r in rows:
            w.writerow(["X"] * len(r))
        return buf.getvalue().encode("utf-8")
    if ext == ".json":
        try:
            obj = json.loads(text)
        except (ValueError, RecursionError):
            return None
        return (json.dumps(_destroy(obj, keys), ensure_ascii=False) + "\n").encode("utf-8")
    return "\n".join("X" if ln.strip() else "" for ln in text.split("\n")).encode("utf-8")


def make_baseline(kind: str, inp: Path, out: Path, truth_path) -> int:
    t0 = time.monotonic()
    if out.exists() and any(out.iterdir()):
        print(f"refusing to write into a non-empty folder: {out}")
        return 2
    truth = None
    if truth_path and Path(truth_path).is_file():
        truth = json.loads(Path(truth_path).read_text(encoding="utf-8"))
    san = out / "sanitized"
    san.mkdir(parents=True, exist_ok=True)
    entries, out_of = [], {}
    for i, p in enumerate(walk_files(inp)):
        rel = p.relative_to(inp).as_posix()
        raw = p.read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        if kind == "passthrough":
            data, out_rel = raw, rel
        else:
            data = _redact_bytes(raw, p.suffix.lower(), kind == "redact-all")
            parent = rel.rsplit("/", 1)[0] + "/" if "/" in rel else ""
            out_rel = rel if kind == "redact" else f"{parent}file_{i:04d}{p.suffix.lower()}"
        if data is None:
            entries.append({"input_sha256": sha, "output": None, "status": "quarantined",
                            "reason": "unsupported_or_malformed"})
            continue
        dest = san / out_rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        entries.append({"input_sha256": sha, "output": "sanitized/" + out_rel, "status": "sanitized"})
        out_of[rel] = out_rel
    records = []
    if truth:
        for rel in sorted(truth["files"]):
            o = out_of.get(rel)
            if not o:
                continue
            for loc in truth["files"][rel]["units"]:
                if not loc.startswith("@"):
                    records.append({"file": "sanitized/" + o, "loc": loc, "patient": None})
    with open(out / "records.jsonl", "w", encoding="utf-8", newline="\n") as fh:
        for r in records:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    n_san = sum(1 for e in entries if e["status"] == "sanitized")
    report = {
        "schema": "raksha-report/1", "files": entries,
        "counts": {"files_total": len(entries), "files_sanitized": n_san, "files_quarantined": len(entries) - n_san,
                   "records_processed": len(records), "identifiers_detected": 0, "records_linked": 0,
                   "records_generalized": 0, "records_suppressed": 0, "records_quarantined": 0},
        "entities": {}, "timing": {"seconds": round(time.monotonic() - t0, 2)},
        "resources": {"peak_rss_mb": 40.0},
    }
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"baseline {kind}: files {len(entries)} sanitized {n_san} records {len(records)}")
    return 0


def main(argv=None) -> int:
    # Deep JSON in releases needs a higher recursion limit. It is raised only while scoring and
    # restored afterwards, so importing or calling this module (the tests do) does not change
    # the limit for the rest of the process.
    old = sys.getrecursionlimit()
    sys.setrecursionlimit(max(old, 10000))
    try:
        return _main(argv)
    finally:
        sys.setrecursionlimit(old)


def _main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser(description="Dev-only estimator of the official RAKSHA score.")
    ap.add_argument("--output", required=True, help="release folder to score (or to create with --make-baseline)")
    ap.add_argument("--input", default=str(DEFAULT_KIT / "dev" / "input"), help="raw input folder")
    ap.add_argument("--truth", default=str(DEFAULT_KIT / "dev" / "truth" / "truth.json"))
    ap.add_argument("--other", help="release made with a different RAKSHA_SECRET (A7)")
    ap.add_argument("--repeat", help="release made again with the same secret (determinism)")
    ap.add_argument("--profile", default="small", help="performance profile in scoring.toml (small, standard, ...)")
    ap.add_argument("--json", dest="json_out", help="write the full result to this JSON file")
    ap.add_argument("--stdout", help="captured stdout+stderr of the run, scanned as a side channel")
    ap.add_argument("--kit", help="toolkit folder (default: derived from --truth)")
    ap.add_argument("--config", help="scoring.toml (default <kit>/scoring.toml)")
    ap.add_argument("--redteam-json", help="reuse a saved tools/redteam.py --json result")
    ap.add_argument("--exit-code", type=int, default=0, help="the pipeline's exit code (default 0)")
    ap.add_argument("--wall-seconds", type=float, help="override report.json timing.seconds")
    ap.add_argument("--peak-mb", type=float, help="override report.json resources.peak_rss_mb")
    ap.add_argument("--top", type=int, default=10, help="how many point losses to list")
    ap.add_argument("--make-baseline", choices=["passthrough", "redact", "redact-all"],
                    help="build a calibration baseline release instead of scoring")
    args = ap.parse_args(argv)
    if args.make_baseline:
        return make_baseline(args.make_baseline, Path(args.input), Path(args.output), args.truth)
    if not Path(args.output).is_dir():
        print(f"no such release folder: {args.output}")
        return 2
    res = score_release(args)
    print_card(res, args.top)
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(res, indent=2, default=str) + "\n", encoding="utf-8")
        print(f" wrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
