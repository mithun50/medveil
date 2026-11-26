"""Rewrite slots with typed placeholders, pseudonyms, shifted dates and bands, then
serialize each document in its original format."""
from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field

from .detect.dates import DateHit, find_dates, render
from .detect.engine import name_tokens
from .link import _ident
from .lexicon import district_of
from .model import Doc, Record, Slot, Span
from .privacy import band_label, shift_date
from .textnorm import b64_encode_text
from .translit import tokens_match

PLACEHOLDER = {
    "PHONE": "[PHONE]", "AADHAAR": "[AADHAAR]", "AADHAAR_MASKED": "[AADHAAR]", "ABHA": "[ABHA]",
    "ABHA_ADDR": "[ABHA-ADDRESS]", "EMAIL": "[EMAIL]", "PAN": "[PAN]", "INSURANCE": "[INSURANCE-ID]",
    "HOUSE": "[HOUSE]", "LOCALITY": "[LOCALITY]", "LANDMARK": "[LANDMARK]", "VILLAGE": "[VILLAGE]",
    "TEHSIL": "[TEHSIL]", "PIN": "[PIN]", "DOB": "[DOB]", "ADDRESS": "[ADDRESS]", "ENCODED": "[ENCODED-PII-REMOVED]",
}


@dataclass
class Ctx:
    psn: str | None
    rec_token: str
    shift: int
    band: tuple | None
    top: int
    district: str | None
    pat_tokens: list = field(default_factory=list)
    rel_tokens: list = field(default_factory=list)
    mrn_psn: dict = field(default_factory=dict)
    pin_digits: int = 3
    dob_mode: str = "suppress"
    date_order: str = "dmy"


def _role_of_mention(value: str, ctx: Ctx) -> str:
    toks = [t for t in _ident(tuple(name_tokens(value)))]
    if not toks:
        return "other"
    if any(tokens_match(t, p) for t in toks for p in ctx.pat_tokens):
        return "patient"
    if any(tokens_match(t, r) for t in toks for r in ctx.rel_tokens):
        return "relative"
    return "other"


def replacement(sp: Span, sl: Slot, ctx: Ctx, structured: bool) -> str:
    t = sp.etype
    if t == "NAME":
        role = sp.role
        if role == "mention":
            role = _role_of_mention(sl.text[sp.start:sp.end], ctx)
        if sl.ftype in ("FIRST_NAME", "LAST_NAME"):
            return "[NAME]"
        if role == "patient":
            return ctx.psn or "[PATIENT]"
        if role == "relative":
            return "[RELATIVE]"
        return "[PERSON]"
    if t == "MRN":
        if sl.kind in ("header", "key", "filename"):
            return ctx.mrn_psn.get(sp.value) or "[MRN]"
        return ctx.psn or ("REC-" + ctx.rec_token)
    if t == "DATE":
        h: DateHit = sp.value
        return render(h, shift_date(h.date, ctx.shift))
    if t == "DOB" and not structured and ctx.dob_mode == "shift":
        if isinstance(sp.value, DateHit):
            return render(sp.value, shift_date(sp.value.date, ctx.shift))
        return "[DOB]"
    if t == "AGE":
        label = band_label(ctx.band, ctx.top) if ctx.band and ctx.band[0] <= int(sp.value) <= ctx.band[1] else None
        if label is None:
            a = int(sp.value)
            label = f"{ctx.top}+" if a >= ctx.top else f"{(a // 10) * 10}-{(a // 10) * 10 + 9}"
        return label
    if structured:
        if t == "DOB":
            if ctx.dob_mode == "shift":
                # Only the first date is written, shifted: anything else in a DOB field (a
                # name, a phone typed into the wrong column, a second date) is dropped, as in
                # suppress mode, and the value stays one valid date (a FHIR birthDate).
                hits = find_dates(sl.text[sp.start:sp.end], ctx.date_order)
                if hits:
                    return render(hits[0], shift_date(hits[0].date, ctx.shift))
            return ""
        if t in ("VILLAGE", "TEHSIL"):
            return ctx.district or PLACEHOLDER[t]
        if t == "PIN":
            d = re.sub(r"\D", "", sl.text[sp.start:sp.end])
            return (d[: ctx.pin_digits] + "*" * (6 - ctx.pin_digits)) if len(d) == 6 else "[PIN]"
    return PLACEHOLDER.get(t, "[REDACTED]")


def apply(sl: Slot, ctx: Ctx) -> str | None:
    """Rewritten slot text, or None when nothing changes."""
    if not sl.spans:
        return None
    structured = sl.ftype not in (None, "TEXT", "ADDRESS") and sl.kind == "value"
    out = []
    pos = 0
    text = sl.text
    for sp in sorted(sl.spans, key=lambda s: s.start):
        if sp.start < pos:
            continue
        out.append(text[pos:sp.start])
        out.append(replacement(sp, sl, ctx, structured))
        pos = sp.end
    out.append(text[pos:])
    new = "".join(out)
    if sl.ftype == "ADDRESS":
        new = _tidy_address(new)
    return new


_PH = re.compile(r"\[(?:HOUSE|LOCALITY|LANDMARK|VILLAGE|TEHSIL|PIN|ADDRESS)\]")


def _tidy_address(s: str) -> str:
    # collapse runs of address placeholders so the address keeps its readable shape
    return re.sub(r"(\[(?:HOUSE|LOCALITY|LANDMARK)\])(?:\s*,\s*\[(?:HOUSE|LOCALITY|LANDMARK)\])+", "[ADDRESS]", s)


# --------------------------------------------------------------------------- per-format output
def rewrite_record(rec: Record, ctx: Ctx) -> bool:
    """Fill slot.out for every slot. Returns True if the PSN appears in the record."""
    found = False
    for sl in rec.slots:
        new = apply(sl, ctx)
        sl.out = new
        if new is not None and ctx.psn and ctx.psn in new:
            found = True
    return found


def place_psn(rec: Record, ctx: Ctx, doc: Doc) -> None:
    """Make sure a linked record carries its pseudonym somewhere inside it."""
    if not ctx.psn:
        return
    for sl in rec.slots:
        if sl.out is not None and ctx.psn in str(sl.out):
            return
    if doc.fmt == "text":
        sl = rec.slots[0]
        base = sl.out if sl.out is not None else sl.text
        sl.out = f"Patient: {ctx.psn}{doc.newline}{base}"
        return
    for pref in ("MRN", "NAME", "PHONE", "AADHAAR", "ABHA", "FIRST_NAME", "RELATIVE"):
        for sl in rec.slots:
            if sl.ftype == pref and sl.kind == "value" and not sl.number and sl.spans:
                sl.out = ctx.psn
                return
    for sl in rec.slots:
        if sl.kind == "value" and not sl.number and sl.spans and any(s.etype == "NAME" for s in sl.spans):
            sl.out = (sl.out or sl.text)
            if ctx.psn not in sl.out:
                sl.out = sl.out.replace("[PATIENT]", ctx.psn, 1) if "[PATIENT]" in sl.out else ctx.psn + " " + sl.out
            return


def final_value(sl: Slot):
    """Value to write back into the document for this slot."""
    if sl.out is None:
        return sl.orig
    if sl.number:
        if any(s.etype == "AGE" for s in sl.spans):
            return sl.out  # band string replaces the number (generalizable field)
        return 0
    if sl.b64:
        return b64_encode_text(sl.out)
    return sl.out


def serialize(doc: Doc) -> str:
    if doc.fmt in ("csv", "tsv"):
        rows = [list(r) for r in doc.data]
        for fs in doc.file_slots:
            if fs.kind == "header":
                j = fs.path[1]
                rows[0][j] = fs.out if fs.out is not None else fs.orig
        for rec in doc.records:
            for sl in rec.slots:
                i, j = sl.path
                rows[i + 1][j] = final_value(sl)
        buf = io.StringIO()
        w = csv.writer(buf, delimiter=doc.delimiter, lineterminator=doc.newline)
        for r in rows:
            w.writerow(r)
        return buf.getvalue()
    if doc.fmt == "text":
        sl = doc.records[0].slots[0]
        return sl.out if sl.out is not None else sl.orig
    # JSON / FHIR
    leaf: dict = {}
    keys: dict = {}
    drop: set = set()
    for rec in doc.records:
        for sl in rec.slots:
            if sl.kind == "key":
                if sl.out is not None:
                    keys[sl.path] = sl.out
            else:
                if doc.fmt == "fhir" and sl.ftype == "DOB" and isinstance(sl.out, str) and not sl.out.strip():
                    drop.add(sl.path)
                    continue
                leaf[sl.path] = final_value(sl)
    def build(node, path):
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                kp = path + (k,)
                if kp in drop:
                    continue
                nk = keys.get(kp, k)
                if nk in out:
                    n = 2
                    while f"{nk}-{n}" in out:
                        n += 1
                    nk = f"{nk}-{n}"
                out[nk] = build(v, kp)
            return out
        if isinstance(node, list):
            return [build(v, path + (i,)) for i, v in enumerate(node)]
        return leaf.get(path, node)

    obj = build(doc.data, ())
    indent = doc.json_style.get("indent")
    if indent is None:
        text = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    else:
        text = json.dumps(obj, ensure_ascii=False, indent=indent)
    return text.replace("\n", doc.newline) + doc.newline


def rename_file(doc: Doc, code: str) -> str:
    """New file name if the name holds personal data, else the same name."""
    fs = next(s for s in doc.file_slots if s.kind == "filename")
    if not fs.spans:
        return doc.rel
    text = fs.text
    parts, pos = [], 0
    for sp in sorted(fs.spans, key=lambda s: s.start):
        if sp.start < pos:
            continue
        parts.append(text[pos:sp.start])
        parts.append("\x00")
        pos = sp.end
    parts.append(text[pos:])
    s = "".join(parts)
    stem, dot, ext = s.rpartition(".") if "." in s else (s, "", "")
    if "\x00" in ext:
        stem, dot, ext = s, "", ""
    stem = re.sub(r"\x00(?:[_\-\s.]*\x00)+", "\x00", stem)
    stem = stem.replace("\x00", code, 1).replace("\x00", "")
    stem = re.sub(r"[_\-\s]{2,}", "_", stem).strip("_- ") or code
    new = stem + (dot + ext if dot else "")
    folder = doc.rel.rsplit("/", 1)[0] + "/" if "/" in doc.rel else ""
    return folder + new


def district_name(rec: Record) -> str | None:
    for d in sorted(rec.ev.districts):
        dd = district_of(d)
        return dd[0] if dd else d.title()
    return None
