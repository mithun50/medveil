"""Privacy plan per patient cluster: date shifts, age bands, location generalization.

Every record of one patient gets the same shift, the same age band and the same
location level, so pooling records under one pseudonym tells an attacker nothing
more than any single record. Age bands are adaptive: 10 years when at least
`k_patients` patients share (gender, band, district), else 20 years, top-coded.
"""
from __future__ import annotations

import datetime as dt
import re
from collections import Counter
from dataclasses import dataclass

from .crypto import Keys


@dataclass
class Plan:
    canonical: str
    psn: str | None
    shift: int
    band: tuple[int, int] | None = None   # (lo, hi) inclusive; hi None for top-code
    district: str | None = None
    gender: str | None = None


def band_label(b: tuple[int, int] | None, top: int) -> str | None:
    if b is None:
        return None
    lo, hi = b
    if lo >= top:
        return f"{top}+"
    return f"{lo}-{hi}"


def _aligned(ages: list[int], width: int, top: int) -> tuple[int, int] | None:
    if not ages:
        return None
    lo_age, hi_age = min(ages), max(ages)
    if lo_age >= top:
        return (top, 200)
    start = (lo_age // width) * width
    if hi_age <= start + width - 1:
        return (start, start + width - 1)
    # straddles an aligned boundary: a band of the same width aligned to 10
    start = (lo_age // 10) * 10
    if hi_age <= start + width - 1:
        return (start, start + width - 1)
    return (start, ((hi_age // 10) * 10) + 9)


def plan_bands(profiles: dict[str, dict], policy: dict) -> tuple[dict, dict]:
    """profiles: canonical -> {"ages": [...], "gender": g, "district": d}.

    Returns (bands, location level) per profile. A profile keeps a 10-year band only if
    k_patients profiles share (gender, band, district). If even the widest band is too
    rare, the location is raised from district to division for that profile.
    """
    age_pol = policy.get("age", {})
    ladder = list(age_pol.get("ladder", [10, 20]))
    top = int(age_pol.get("top_code", 80))
    k = int(age_pol.get("k_patients", 2))
    k_loc = int(policy.get("location", {}).get("k_patients", k))
    division_of = policy.get("_division_of", {})
    first = {c: _aligned(p["ages"], ladder[0], top) for c, p in profiles.items()}
    classes = Counter((p.get("gender"), first[c], p.get("district")) for c, p in profiles.items() if first[c])
    out = {}
    for c, p in profiles.items():
        b = first[c]
        if b is None:
            out[c] = None
            continue
        if b[0] >= top or classes[(p.get("gender"), b, p.get("district"))] >= k:
            out[c] = b
            continue
        for w in ladder[1:]:
            b = _aligned(p["ages"], w, top)
            if b and b[0] >= top:
                break
        out[c] = b
    final = Counter((p.get("gender"), out[c], p.get("district")) for c, p in profiles.items() if out[c])
    by_div = Counter((p.get("gender"), out[c], division_of.get(p.get("district"), p.get("district")))
                     for c, p in profiles.items() if out[c])
    keep = policy.get("location", {}).get("keep_level", "district")
    fallback = policy.get("location", {}).get("fallback_level", "state")
    level = {}
    for c, p in profiles.items():
        level[c] = "district"
        if keep in ("division", "state") and p.get("district"):
            level[c] = keep
            continue
        if out[c] and p.get("district") and final[(p.get("gender"), out[c], p.get("district"))] < k_loc:
            div = division_of.get(p.get("district"))
            if fallback == "division" and div and by_div[(p.get("gender"), out[c], div)] >= k_loc:
                level[c] = "division"
            else:
                level[c] = "state"
    return out, level


def shift_for(keys: Keys, canonical: str, policy: dict) -> int:
    d = policy.get("dates", {})
    return keys.shift_days(canonical, int(d.get("shift_min_days", 30)), int(d.get("shift_max_days", 365)))


def shift_date(d: dt.date, days: int) -> dt.date:
    try:
        return d + dt.timedelta(days=days)
    except OverflowError:
        return d


_DIST_CTX = re.compile(r"(?i)(\b(?:Distt\.?|District|Dist\.?)\s+|(?:जिला|ज़िला)\s+)([A-Za-z][A-Za-z ]{2,30}?|[\u0900-\u097F]+)(?=\s*(?:[-,;\n]|$|\s{2}))")


def raise_location(rec, level: str, division_of: dict) -> bool:
    """Replace this record's district with its division (or the state) where it appears
    as a location: district fields, village/tehsil fields we already raised, and
    "Distt. X" / "जिला X" in text. Hospital names are left alone."""
    from .lexicon import district_of
    changed = False
    for sl in rec.slots:
        if sl.kind != "value" or sl.number or not sl.text:
            continue
        base = sl.out if isinstance(sl.out, str) else sl.text
        new = base
        if sl.ftype in ("DISTRICT", "VILLAGE", "TEHSIL"):
            d = district_of(base)
            if d:
                new = _label(d, level, division_of)
        elif sl.ftype in (None, "TEXT", "ADDRESS"):
            def sub(m):
                d = district_of(m.group(2))
                return m.group(1) + _label(d, level, division_of) if d else m.group(0)
            new = _DIST_CTX.sub(sub, base)
        if sl.ftype == "PIN" and re.match(r"\d{3}\*\*\*$", base.strip()):
            new = "******"
        if new != base:
            sl.out = new
            changed = True
    return changed


def _label(d: tuple[str, str], level: str, division_of: dict) -> str:
    canon, div = d
    if level == "division" and div:
        return f"{div} Division"
    return "Uttar Pradesh"
