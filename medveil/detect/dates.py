"""Date detection, parsing and format-preserving re-rendering.

Every match keeps a template so a shifted date is written back in exactly the
original style: separators, zero padding, 2- or 4-digit year, month names, and any
time or timezone suffix. Ambiguous numeric dates are read with the file's inferred
day/month order.
"""
from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass

MONTHS = ["january", "february", "march", "april", "may", "june", "july", "august", "september",
          "october", "november", "december"]
_MON_ALT = r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
HI_MONTHS = ["जनवरी", "फ़रवरी", "मार्च", "अप्रैल", "मई", "जून", "जुलाई", "अगस्त", "सितंबर", "अक्टूबर", "नवंबर", "दिसंबर"]
_HI_ALT = "|".join(HI_MONTHS + ["फरवरी", "सितम्बर", "अक्तूबर", "नवम्बर", "दिसम्बर"])
_HI_IDX = {m: i + 1 for i, m in enumerate(HI_MONTHS)}
_HI_IDX.update({"फरवरी": 2, "सितम्बर": 9, "अक्तूबर": 10, "नवम्बर": 11, "दिसम्बर": 12})

ISO = re.compile(r"(?<![\d\-/.])(\d{4})-(\d{2})-(\d{2})(?![\d])")
NUM = re.compile(r"(?<![\d/.\-])(\d{1,2})([/.\-])(\d{1,2})\2(\d{4}|\d{2})(?![\d/.\-]|:\d)")
YMD = re.compile(r"(?<![\d/.\-])(\d{4})([/.])(\d{1,2})\2(\d{1,2})(?![\d/.])")
DMONY = re.compile(r"(?<![\w])(\d{1,2})(st|nd|rd|th)?([\s\-]+)(" + _MON_ALT + r")(\.?)(?:([\s,\-]+)(\d{4}|'\d{2}|\d{2}(?!\d)))?(?![a-z])", re.I)
MONDY = re.compile(r"(?<![\w])(" + _MON_ALT + r")(\.?)(\s+)(\d{1,2})(st|nd|rd|th)?(,?\s+)(\d{4})(?!\d)", re.I)
HIDATE = re.compile(r"(?<!\d)(\d{1,2})\s+(" + _HI_ALT + r")(?:\s+(\d{4}))?")


@dataclass
class DateHit:
    start: int
    end: int
    date: dt.date
    kind: str
    parts: tuple
    ambiguous: bool = False
    has_year: bool = True


def _mon(tok: str) -> int:
    t = tok.lower().rstrip(".")
    for i, m in enumerate(MONTHS):
        if m.startswith(t[:3]):
            return i + 1
    raise ValueError(tok)


def _year2(y: int, ref_year: int) -> int:
    full = 2000 + y
    return full if full <= ref_year + 1 else 1900 + y


def _safe(y: int, m: int, d: int) -> dt.date | None:
    try:
        if 1890 <= y <= 2100:
            return dt.date(y, m, d)
    except ValueError:
        return None
    return None


def order_evidence(text: str) -> tuple[int, int]:
    """Count numeric dates that only parse day-first or only month-first."""
    dmy = mdy = 0
    for m in NUM.finditer(text):
        a, b = int(m.group(1)), int(m.group(3))
        if a > 12 and b <= 12:
            dmy += 1
        elif b > 12 and a <= 12:
            mdy += 1
    return dmy, mdy


def find_dates(text: str, order: str = "dmy", ref_year: int = 2026) -> list[DateHit]:
    hits: list[DateHit] = []
    taken: list[tuple[int, int]] = []

    def free(s, e):
        return not any(s < te and ts < e for ts, te in taken)

    for m in ISO.finditer(text):
        d = _safe(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        if d:
            hits.append(DateHit(m.start(), m.end(), d, "iso", ()))
            taken.append((m.start(), m.end()))
    for m in YMD.finditer(text):
        if not free(m.start(), m.end()):
            continue
        d = _safe(int(m.group(1)), int(m.group(3)), int(m.group(4)))
        if d:
            hits.append(DateHit(m.start(), m.end(), d, "ymd", (m.group(2), len(m.group(3)), len(m.group(4)))))
            taken.append((m.start(), m.end()))
    for m in NUM.finditer(text):
        if not free(m.start(), m.end()):
            continue
        a, sep, b, y = m.group(1), m.group(2), m.group(3), m.group(4)
        yi = int(y) if len(y) == 4 else _year2(int(y), ref_year)
        ai, bi = int(a), int(b)
        if order == "mdy":
            first = (bi, ai)  # (day, month)
            alt = (ai, bi)
        else:
            first = (ai, bi)
            alt = (bi, ai)
        d = _safe(yi, first[1], first[0])
        use_order = order
        if d is None:
            d = _safe(yi, alt[1], alt[0])
            use_order = "mdy" if order == "dmy" else "dmy"
        if d is None:
            continue
        amb = ai <= 12 and bi <= 12 and ai != bi
        hits.append(DateHit(m.start(), m.end(), d, "num", (use_order, sep, len(a), len(b), len(y)), ambiguous=amb))
        taken.append((m.start(), m.end()))
    for m in DMONY.finditer(text):
        if not free(m.start(), m.end()):
            continue
        try:
            mon = _mon(m.group(4))
        except ValueError:
            continue
        ytxt = m.group(7)
        has_year = bool(ytxt)
        if ytxt:
            yv = ytxt.lstrip("'")
            yi = int(yv) if len(yv) == 4 else _year2(int(yv), ref_year)
        else:
            yi = ref_year
        d = _safe(yi, mon, int(m.group(1)))
        if not d:
            continue
        parts = (len(m.group(1)), m.group(2) or "", m.group(3), m.group(4), m.group(5), m.group(6) or "", ytxt or "")
        hits.append(DateHit(m.start(), m.end(), d, "dmony", parts, has_year=has_year))
        taken.append((m.start(), m.end()))
    for m in MONDY.finditer(text):
        if not free(m.start(), m.end()):
            continue
        try:
            mon = _mon(m.group(1))
        except ValueError:
            continue
        d = _safe(int(m.group(7)), mon, int(m.group(4)))
        if not d:
            continue
        parts = (m.group(1), m.group(2), m.group(3), len(m.group(4)), m.group(5) or "", m.group(6))
        hits.append(DateHit(m.start(), m.end(), d, "mondy", parts))
        taken.append((m.start(), m.end()))
    for m in HIDATE.finditer(text):
        if not free(m.start(), m.end()):
            continue
        mon = _HI_IDX.get(m.group(2))
        yi = int(m.group(3)) if m.group(3) else ref_year
        d = _safe(yi, mon, int(m.group(1))) if mon else None
        if d:
            hits.append(DateHit(m.start(), m.end(), d, "hi", (len(m.group(1)), bool(m.group(3))), has_year=bool(m.group(3))))
            taken.append((m.start(), m.end()))
    hits.sort(key=lambda h: h.start)
    return hits


def _pad(n: int, width: int) -> str:
    return f"{n:0{width}d}" if width > 1 else str(n)


def _month_name(template: str, mon: int) -> str:
    full = MONTHS[mon - 1]
    if len(template.rstrip(".")) <= 3 or (len(template) == 4 and template.lower().startswith("sept")):
        name = full[:3] if not template.lower().startswith("sept") else ("sept" if mon == 9 else full[:3])
    else:
        name = full
    if template.isupper():
        return name.upper()
    if template[:1].isupper():
        return name.capitalize()
    return name


def render(hit: DateHit, d: dt.date) -> str:
    if hit.kind == "iso":
        return f"{d.year:04d}-{d.month:02d}-{d.day:02d}"
    if hit.kind == "ymd":
        sep, lm, ld = hit.parts
        return f"{d.year:04d}{sep}{_pad(d.month, lm)}{sep}{_pad(d.day, ld)}"
    if hit.kind == "num":
        order, sep, la, lb, ly = hit.parts
        y = f"{d.year:04d}" if ly == 4 else f"{d.year % 100:02d}"
        if order == "mdy":
            return f"{_pad(d.month, la)}{sep}{_pad(d.day, lb)}{sep}{y}"
        return f"{_pad(d.day, la)}{sep}{_pad(d.month, lb)}{sep}{y}"
    if hit.kind == "dmony":
        ld, suf, sp1, mon_t, dot, sp2, ytxt = hit.parts
        day = _pad(d.day, ld)
        if suf:
            suf = "th" if 11 <= d.day <= 13 else {1: "st", 2: "nd", 3: "rd"}.get(d.day % 10, "th")
        out = f"{day}{suf}{sp1}{_month_name(mon_t, d.month)}{dot}"
        if ytxt:
            y = f"{d.year:04d}" if len(ytxt.lstrip("'")) == 4 else ("'" if ytxt.startswith("'") else "") + f"{d.year % 100:02d}"
            out += f"{sp2}{y}"
        return out
    if hit.kind == "mondy":
        mon_t, dot, sp1, ld, suf, sp2 = hit.parts
        if suf:
            suf = "th" if 11 <= d.day <= 13 else {1: "st", 2: "nd", 3: "rd"}.get(d.day % 10, "th")
        return f"{_month_name(mon_t, d.month)}{dot}{sp1}{_pad(d.day, ld)}{suf}{sp2}{d.year:04d}"
    if hit.kind == "hi":
        ld, has_y = hit.parts
        out = f"{_pad(d.day, ld)} {HI_MONTHS[d.month - 1]}"
        return out + (f" {d.year:04d}" if has_y else "")
    raise ValueError(hit.kind)
