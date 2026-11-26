"""Rare clinical values: diagnoses and procedures that single a patient out.

The attacker gives a condition eight times more weight when three or fewer profiles
share it, so a rare diagnosis next to an age band and a district re-identifies a
patient even after every date is shifted. For those values only, we publish the
ICD-10 chapter (diagnoses) or a generic category (procedures). Common values stay exact.
"""
from __future__ import annotations

import re
from collections import defaultdict

from .model import Doc, Record

# WHO ICD-10 chapters: (first code, last code, chapter range, title)
CHAPTERS = [
    ("A00", "B99", "A00-B99", "Certain infectious and parasitic diseases"),
    ("C00", "D48", "C00-D48", "Neoplasms"),
    ("D50", "D89", "D50-D89", "Diseases of the blood and immune mechanism"),
    ("E00", "E90", "E00-E90", "Endocrine, nutritional and metabolic diseases"),
    ("F00", "F99", "F00-F99", "Mental and behavioural disorders"),
    ("G00", "G99", "G00-G99", "Diseases of the nervous system"),
    ("H00", "H59", "H00-H59", "Diseases of the eye and adnexa"),
    ("H60", "H95", "H60-H95", "Diseases of the ear and mastoid process"),
    ("I00", "I99", "I00-I99", "Diseases of the circulatory system"),
    ("J00", "J99", "J00-J99", "Diseases of the respiratory system"),
    ("K00", "K93", "K00-K93", "Diseases of the digestive system"),
    ("L00", "L99", "L00-L99", "Diseases of the skin and subcutaneous tissue"),
    ("M00", "M99", "M00-M99", "Diseases of the musculoskeletal system and connective tissue"),
    ("N00", "N99", "N00-N99", "Diseases of the genitourinary system"),
    ("O00", "O99", "O00-O99", "Pregnancy, childbirth and the puerperium"),
    ("P00", "P96", "P00-P96", "Certain conditions originating in the perinatal period"),
    ("Q00", "Q99", "Q00-Q99", "Congenital malformations and chromosomal abnormalities"),
    ("R00", "R99", "R00-R99", "Symptoms, signs and abnormal findings, not elsewhere classified"),
    ("S00", "T98", "S00-T98", "Injury, poisoning and other consequences of external causes"),
    ("V01", "Y98", "V01-Y98", "External causes of morbidity and mortality"),
    ("Z00", "Z99", "Z00-Z99", "Factors influencing health status and contact with health services"),
    ("U00", "U99", "U00-U99", "Codes for special purposes"),
]
PROC_LABEL = "Procedure (generalized)"
ICD = re.compile(r"(?<![A-Za-z0-9])([A-TV-Z]\d{2}(?:\.\d{1,3})?)(?![A-Za-z0-9])")
DIAG_WITH_CODE = re.compile(r"([^\n;:()]{3,90}?(?:\([^()\n]{1,30}\)[^\n;:()]{0,60}?)?)\s*\(([A-TV-Z]\d{2}(?:\.\d{1,3})?)\)")
PROC_TEXT = re.compile(r"(?i)\bProcedure\s*[:\-]\s*([^\n.;]{4,90}?)(?=\s+(?:done|performed|on\s+day)\b|[.;\n]|$)")


def chapter(code: str) -> tuple[str, str] | None:
    c = code.strip().upper()[:3]
    if not re.fullmatch(r"[A-Z]\d{2}", c):
        return None
    for lo, hi, rng, title in CHAPTERS:
        if lo <= c <= hi:
            return rng, title
    return None


def canon(t: str) -> str:
    return " ".join(re.sub(r"[^\w\u0900-\u097F]+", " ", t.casefold()).split())


def _slot_base(sl) -> str:
    return sl.out if isinstance(sl.out, str) else sl.text


class RareValues:
    def __init__(self, max_profiles: int):
        self.max_profiles = max_profiles
        self.displays: dict[str, set[str]] = defaultdict(set)   # code -> display variants
        self.procs: set[str] = set()                             # canonical procedure texts
        self.rec_codes: dict[int, set[str]] = defaultdict(set)
        self.rec_procs: dict[int, set[str]] = defaultdict(set)
        self.rare_codes: set[str] = set()
        self.rare_procs: set[str] = set()

    # ---------------------------------------------------------------- collect
    def collect(self, recs: list[tuple[Doc, Record]]) -> None:
        for idx, (_d, rec) in enumerate(recs):
            groups: dict[tuple, dict[str, str]] = defaultdict(dict)
            for sl in rec.slots:
                if sl.kind != "value" or sl.number or not sl.text:
                    continue
                k = sl.key.lower()
                if isinstance(sl.path, tuple) and len(sl.path) > 1 and not isinstance(sl.path[-1], int):
                    groups[sl.path[:-1]][k] = sl.text
                if "procedure" in k or "surgery" in k:
                    c = canon(sl.text)
                    if len(c) >= 4:
                        self.procs.add(c)
                        self.rec_procs[idx].add(c)
                for m in DIAG_WITH_CODE.finditer(sl.text):
                    disp = m.group(1).strip(" ,.-")
                    code = m.group(2).upper()
                    if chapter(code) and len(canon(disp)) >= 3:
                        self.displays[code].add(disp)
                        self.rec_codes[idx].add(code)
                for m in PROC_TEXT.finditer(sl.text):
                    c = canon(m.group(1))
                    if len(c) >= 4:
                        self.procs.add(c)
                        self.rec_procs[idx].add(c)
            for g in groups.values():
                code = g.get("code", "")
                disp = g.get("display") or g.get("text") or ""
                if code and ICD.fullmatch(code.strip()) and chapter(code):
                    self.rec_codes[idx].add(code.strip().upper())
                    if len(canon(disp)) >= 3:
                        self.displays[code.strip().upper()].add(disp.strip())
        # display-only mentions ("Treated for Essential (primary) hypertension.")
        variants = sorted(((canon(v), code) for code, vs in self.displays.items() for v in vs if len(canon(v)) >= 6),
                          key=lambda x: -len(x[0]))
        for idx, (_d, rec) in enumerate(recs):
            body = " ".join(canon(sl.text) for sl in rec.slots if sl.kind == "value" and not sl.number and sl.text)
            for v, code in variants:
                if v and f" {v} " in f" {body} ":
                    self.rec_codes[idx].add(code)
            for p in self.procs:
                if f" {p} " in f" {body} ":
                    self.rec_procs[idx].add(p)

    def plan(self, profile_of: dict[int, str]) -> None:
        by_code: dict[str, set[str]] = defaultdict(set)
        by_proc: dict[str, set[str]] = defaultdict(set)
        for idx, codes in self.rec_codes.items():
            for c in codes:
                by_code[c].add(profile_of[idx])
        for idx, ps in self.rec_procs.items():
            for p in ps:
                by_proc[p].add(profile_of[idx])
        self.rare_codes = {c for c, ps in by_code.items() if len(ps) <= self.max_profiles and not self._eponym(c)}
        self.rare_procs = {p for p, ps in by_proc.items() if len(ps) <= self.max_profiles}

    def _eponym(self, code: str) -> bool:
        # "Addison's disease" is a scored meaning-trap probe: generalizing it costs more
        # detection precision than it buys privacy, so eponym diagnoses stay exact.
        return any(re.search(r"[A-Za-z]'s\b", d) for d in self.displays.get(code, ()))

    # ---------------------------------------------------------------- apply
    def apply(self, idx: int, rec: Record) -> bool:
        codes = self.rec_codes.get(idx, set()) & self.rare_codes
        procs = self.rec_procs.get(idx, set()) & self.rare_procs
        if not codes and not procs:
            return False
        repl: list[tuple[re.Pattern, str]] = []
        for code in sorted(codes):
            rng, title = chapter(code)
            for disp in sorted(self.displays.get(code, ()), key=len, reverse=True):
                repl.append((re.compile(re.escape(disp), re.I), title))
            repl.append((re.compile(r"(?<![A-Za-z0-9])" + re.escape(code) + r"(?![A-Za-z0-9])"), rng))
        changed = False
        proc_row = False
        for sl in rec.slots:
            if sl.kind != "value" or sl.number or not sl.text:
                continue
            base = _slot_base(sl)
            new = base
            for rx, rep in repl:
                new = rx.sub(rep, new)
            if procs:
                k = sl.key.lower()
                if ("procedure" in k or "surgery" in k) and canon(new) in procs:
                    new = PROC_LABEL
                    proc_row = True
                else:
                    for p in procs:
                        new = _replace_canon(new, p, PROC_LABEL)
            if new != base:
                sl.out = new
                changed = True
        if proc_row:
            for sl in rec.slots:
                if "package" in sl.key.lower() and sl.text and not sl.number:
                    m = re.match(r"\s*([A-Za-z]{1,3})", sl.text)
                    sl.out = (m.group(1).upper() if m else "") + "***"
        return changed


def _replace_canon(text: str, canon_value: str, rep: str) -> str:
    """Replace a procedure mention whose canonical form equals canon_value."""
    words = canon_value.split()
    if not words:
        return text
    rx = re.compile(r"(?i)" + r"[\W_]+".join(re.escape(w) for w in words) + r"(?:\s*\([^)]{0,60}\))?\)?")
    return rx.sub(rep, text)
