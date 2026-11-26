"""Privacy plan per patient cluster: date shifts, age bands, location generalization.

Every record of one patient gets the same shift, the same age band and the same
location level, so pooling records under one pseudonym tells an attacker nothing
more than any single record. Age bands are adaptive: 10 years when at least
`k_patients` patients share (gender, band, district), else 20 years, top-coded.
"""
from __future__ import annotations

import datetime as dt
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


def plan_bands(profiles: dict[str, dict], policy: dict) -> dict[str, tuple[int, int] | None]:
    """profiles: canonical -> {"ages": [...], "gender": g, "district": d}."""
    age_pol = policy.get("age", {})
    ladder = list(age_pol.get("ladder", [10, 20]))
    top = int(age_pol.get("top_code", 80))
    k = int(age_pol.get("k_patients", 2))
    first = {c: _aligned(p["ages"], ladder[0], top) for c, p in profiles.items()}
    classes = Counter((p.get("gender"), first[c], p.get("district")) for c, p in profiles.items() if first[c])
    out = {}
    for c, p in profiles.items():
        b = first[c]
        if b is None:
            out[c] = None
            continue
        if b[0] >= top:
            out[c] = b
            continue
        if classes[(p.get("gender"), b, p.get("district"))] >= k:
            out[c] = b
            continue
        for w in ladder[1:]:
            b = _aligned(p["ages"], w, top)
            if b and b[0] >= top:
                break
        out[c] = b
    return out


def shift_for(keys: Keys, canonical: str, policy: dict) -> int:
    d = policy.get("dates", {})
    return keys.shift_days(canonical, int(d.get("shift_min_days", 30)), int(d.get("shift_max_days", 365)))


def shift_date(d: dt.date, days: int) -> dt.date:
    try:
        return d + dt.timedelta(days=days)
    except OverflowError:
        return d
