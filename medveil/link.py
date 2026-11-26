"""Identity resolution: evidence, a precision-first rule ladder, constrained union-find.

The ladder mirrors how the dataset defines "must be linked": a shared strong
identifier, or the same name plus a second clue (DOB, relative, or village with age
within one year) whose combination is unique. Every merge is checked against
cannot-link constraints on the pooled evidence of both clusters, so a single bad
edge cannot chain different people together.
"""
from __future__ import annotations

import datetime as dt
import re
from collections import defaultdict

from .detect.dates import DateHit, find_dates
from .detect.engine import ident_tokens, name_tokens
from .detect.patterns import genders_in
from .lexicon import GENDER_WORDS, district_of
from .model import Doc, Evidence, Record
from .translit import key, tokens_match

STRONG = ("mrn", "aadhaar", "abha", "pan", "insurance", "email", "abha_addr")
ONE_PER_PERSON = ("aadhaar", "abha", "pan")


# --------------------------------------------------------------------------- evidence
def _dob_dates(sl, sp, order: str) -> set[dt.date]:
    txt = sl.text[sp.start:sp.end]
    out = set()
    hits = find_dates(txt, order)
    if not hits:
        return out
    h = hits[0]
    out.add(h.date)
    if h.kind == "num" and h.ambiguous:
        o2 = "mdy" if h.parts[0] == "dmy" else "dmy"
        alt = find_dates(txt, o2)
        if alt:
            out.add(alt[0].date)
    return out


def extract_evidence(rec: Record, doc: Doc) -> None:
    ev = Evidence()
    first = last = None
    for sl in rec.slots:
        if sl.ftype == "GENDER" and sl.text.strip():
            g = GENDER_WORDS.get(sl.text.strip().lower())
            if g:
                ev.genders.add(g)
        if sl.ftype == "DISTRICT" and sl.text.strip():
            d = district_of(sl.text)
            ev.districts.add(d[0] if d else sl.text.strip().lower())
        if sl.ftype == "AGE_SEX":
            ev.genders |= genders_in(sl.text)
        if sl.ftype == "RELATION" or sl.ftype == "RELATIVE":
            m = re.match(r"\s*([SDW])\s?/\s?O\b", sl.text, re.I)
            if m:
                ev.genders.add("M" if m.group(1).upper() == "S" else "F")
        if sl.kind in ("text",) or sl.ftype in (None, "TEXT"):
            ev.genders |= genders_in(sl.text)
            for m in re.finditer(r"(?i)\b(?:Distt\.?|District)\s+([A-Z][a-z]+(?: [A-Z][a-z]+)?)", sl.text):
                d = district_of(m.group(1))
                if d:
                    ev.districts.add(d[0])
            for m in re.finditer(r"(?:जिला|ज़िला)\s+([\u0900-\u097F]+)", sl.text):
                d = district_of(m.group(1))
                if d:
                    ev.districts.add(d[0])
        for sp in sl.spans:
            t = sp.etype
            if t == "MRN" and sp.value:
                ev.ids.add(("mrn", sp.value))
            elif t in ("AADHAAR", "ABHA", "PAN", "INSURANCE", "EMAIL", "ABHA_ADDR") and sp.value:
                ev.ids.add((t.lower(), str(sp.value)))
                if t == "AADHAAR" and len(str(sp.value)) == 12:
                    ev.aadhaar_last4.add(str(sp.value)[-4:])
            elif t == "AADHAAR_MASKED" and sp.value:
                ev.aadhaar_last4.add(str(sp.value))
            elif t == "PHONE" and sp.value and len(str(sp.value)) == 10:
                ev.phones.add(str(sp.value))
            elif t == "NAME":
                toks = tuple(name_tokens(sl.text[sp.start:sp.end]))
                if not toks:
                    continue
                if sl.ftype == "FIRST_NAME":
                    first = toks
                elif sl.ftype == "LAST_NAME":
                    last = toks
                elif sp.role == "patient":
                    ev.names.append(toks)
                elif sp.role == "relative":
                    ev.relatives.append(toks)
                elif sp.role == "mention":
                    ev.mentions.append(toks)
            elif t == "DOB":
                ev.dobs |= _dob_dates(sl, sp, doc.date_order)
            elif t == "AGE" and sp.value is not None:
                ev.ages.append(int(sp.value))
            elif t == "VILLAGE":
                vk = tuple(key(w) for w in re.findall(r"[A-Za-z]+|[\u0900-\u097F]+", sl.text[sp.start:sp.end]) if key(w))
                if vk:
                    ev.villages.add(vk)
            elif t == "DATE" and isinstance(sp.value, DateHit):
                rec.dates.append(sp.value.date)
    if first or last:
        ev.names.append(tuple((first or ()) + (last or ())))
    rec.ev = ev


def ref_date(rec: Record, default: dt.date) -> dt.date:
    return min(rec.dates) if rec.dates else default


# --------------------------------------------------------------------------- name logic
def _ident(toks: tuple) -> list[str]:
    return ident_tokens(list(toks))


def full_match(a: tuple, b: tuple) -> bool:
    """Same person name, order-insensitive, transliteration tolerant."""
    if len(a) < 2 or len(b) < 2:
        return False
    ia, ib = sorted(_ident(a)), sorted(_ident(b))
    if not ia or not ib:
        return False
    if len(ia) != len(ib):
        # allow a missing generic part ("Sunita Devi Patel" vs "Sunita Patel")
        small, big = (ia, ib) if len(ia) < len(ib) else (ib, ia)
        if len(big) - len(small) > 1 or len(small) < 2:
            return False
        return all(any(tokens_match(x, y) for y in big) for x in small)
    used = set()
    for x in ia:
        hit = None
        for j, y in enumerate(ib):
            if j not in used and tokens_match(x, y):
                hit = j
                break
        if hit is None:
            return False
        used.add(hit)
    return True


def given_of(toks: tuple) -> str | None:
    ident = [t for t in toks if t in set(_ident(toks))]
    return ident[0] if ident else None


def name_compatible(a: tuple, b: tuple) -> bool:
    """Not contradictory: one name could be a fragment of the other."""
    ia, ib = _ident(a), _ident(b)
    if not ia or not ib:
        return True
    if len(ia) >= 2 and len(ib) >= 2:
        return full_match(a, b)
    small, big = (ia, ib) if len(ia) <= len(ib) else (ib, ia)
    return all(any(tokens_match(x, y) for y in big) for x in small)


def rel_match(a: tuple, b: tuple) -> bool:
    ia, ib = _ident(a), _ident(b)
    if not ia or not ib:
        return False
    if len(ia) >= 2 and len(ib) >= 2:
        return full_match(a, b)
    return tokens_match(ia[0], ib[0])


# --------------------------------------------------------------------------- clusters
class Cluster:
    __slots__ = ("members", "ids", "phones", "names", "mentions", "relatives", "dobs", "genders", "villages",
                 "byears", "districts", "last4")

    def __init__(self):
        self.members: list[int] = []
        self.ids: set = set()
        self.phones: set = set()
        self.names: list = []
        self.mentions: list = []
        self.relatives: list = []
        self.dobs: set = set()
        self.genders: set = set()
        self.villages: set = set()
        self.byears: list = []
        self.districts: set = set()
        self.last4: set = set()

    def absorb(self, other: "Cluster") -> None:
        self.members += other.members
        self.ids |= other.ids
        self.phones |= other.phones
        self.names += other.names
        self.mentions += other.mentions
        self.relatives += other.relatives
        self.dobs |= other.dobs
        self.genders |= other.genders
        self.villages |= other.villages
        self.byears += other.byears
        self.districts |= other.districts
        self.last4 |= other.last4

    def byear_range(self) -> tuple[int, int] | None:
        if not self.byears:
            return None
        lo = max(a for a, _ in self.byears)
        hi = min(b for _, b in self.byears)
        if lo > hi:
            lo = min(a for a, _ in self.byears)
            hi = max(b for _, b in self.byears)
        return lo, hi


def conflict(a: Cluster, b: Cluster) -> bool:
    if a.genders and b.genders and not (a.genders & b.genders):
        return True
    if a.dobs and b.dobs and not (a.dobs & b.dobs):
        return True
    for kind in ONE_PER_PERSON:
        va = {v for k, v in a.ids if k == kind}
        vb = {v for k, v in b.ids if k == kind}
        if va and vb and not (va & vb):
            return True
    if a.last4 and b.last4 and not (a.last4 & b.last4):
        return True
    fa = [n for n in a.names if len(_ident(n)) >= 1]
    fb = [n for n in b.names if len(_ident(n)) >= 1]
    if fa and fb and not any(name_compatible(x, y) for x in fa for y in fb):
        return True
    ra, rb = a.byear_range(), b.byear_range()
    if ra and rb and (ra[0] > rb[1] + 1 or rb[0] > ra[1] + 1):
        return True
    for x in a.dobs:
        if rb and not (rb[0] - 1 <= x.year <= rb[1] + 1):
            return True
    for x in b.dobs:
        if ra and not (ra[0] - 1 <= x.year <= ra[1] + 1):
            return True
    return False


def _multi_patient(ev: Evidence) -> bool:
    names = [n for n in ev.names if _ident(n)]
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            if not name_compatible(names[i], names[j]):
                return True
    mrns = [v for k, v in ev.ids if k == "mrn"]
    prefixes = defaultdict(set)
    for v in mrns:
        m = re.match(r"[A-Z]+", v)
        prefixes[m.group(0) if m else ""].add(v)
    if any(len(s) >= 2 for s in prefixes.values()) or len(mrns) > 3:
        return True
    for kind in ONE_PER_PERSON:
        if len({v for k, v in ev.ids if k == kind}) > 1:
            return True
    return False


def link(records: list[Record], default_ref: dt.date) -> dict[int, list[int]]:
    """Return clusters as {cluster_id: [record indices]} for records with person evidence."""
    n = len(records)
    clusters: dict[int, Cluster] = {}
    owner = list(range(n))
    eligible = []
    for i, r in enumerate(records):
        ev = r.ev
        # A phone alone (a caller, a visitor) does not make a record a patient record.
        has = ev.ids or ev.names or ev.mentions or ev.relatives
        if not has or _multi_patient(ev):
            continue
        c = Cluster()
        c.members = [i]
        c.ids = set(ev.ids)
        c.phones = set(ev.phones)
        c.names = list(ev.names)
        c.mentions = list(ev.mentions)
        c.relatives = list(ev.relatives)
        c.dobs = set(ev.dobs)
        c.genders = set(ev.genders)
        c.villages = set(ev.villages)
        c.districts = set(ev.districts)
        c.last4 = set(ev.aadhaar_last4)
        rd = ref_date(r, default_ref)
        for a in ev.ages:
            c.byears.append((rd.year - a - 1, rd.year - a))
        for d in ev.dobs:
            c.byears.append((d.year, d.year))
        clusters[i] = c
        eligible.append(i)

    def find(x):
        while owner[x] != x:
            owner[x] = owner[owner[x]]
            x = owner[x]
        return x

    def union(x, y) -> bool:
        rx, ry = find(x), find(y)
        if rx == ry:
            return True
        a, b = clusters[rx], clusters[ry]
        if conflict(a, b):
            return False
        if rx > ry:
            rx, ry = ry, rx
            a, b = b, a
        owner[ry] = rx
        a.absorb(b)
        del clusters[ry]
        return True

    # L1 strong identifiers, L2 phones. Shared values across name-incompatible people are skipped.
    for tier in ("ids", "phones"):
        index: dict = defaultdict(list)
        for i in eligible:
            vals = records[i].ev.ids if tier == "ids" else records[i].ev.phones
            for v in vals:
                index[v].append(i)
        for v in sorted(index, key=str):
            members = index[v]
            if len(members) < 2:
                continue
            base = members[0]
            for other in members[1:]:
                union(base, other)

    # L3 full name + clue, L4 given name + relative. The weaker side (a fragment) must
    # have exactly one candidate, so a fragment that fits two people is never linked.
    changed = True
    rounds = 0
    while changed and rounds < 6:
        changed = False
        rounds += 1
        roots = sorted(clusters)
        tok_index: dict[str, set[int]] = defaultdict(set)
        for r in roots:
            c = clusters[r]
            for nm in c.names + c.mentions:
                for t in _ident(nm):
                    tok_index[_block(t)].add(r)
        picks: dict[int, list[int]] = {}
        for r in roots:
            c = clusters[r]
            cands = set()
            for nm in c.names + c.mentions:
                for t in _ident(nm):
                    cands |= tok_index.get(_block(t), set())
            cands.discard(r)
            matches = [o for o in sorted(cands) if _clue_link(c, clusters[o])]
            # Prefer anchors (clusters with identifiers): two fragments of one person
            # must not block each other from joining their single anchor.
            anchors = [o for o in matches if clusters[o].ids or clusters[o].phones]
            picks[r] = anchors if anchors else matches
        for r in roots:
            if r not in clusters:
                continue
            p = picks.get(r, [])
            if len(p) != 1:
                continue
            o = p[0]
            if o not in clusters or find(r) == find(o):
                continue
            if _strength(clusters[r]) > _strength(clusters[o]) and picks.get(o) != [r]:
                continue  # the weaker side has other candidates: ambiguous, do not link
            if union(r, o):
                changed = True
    out: dict[int, list[int]] = {}
    for root, c in clusters.items():
        out[root] = sorted(c.members)
    return out


def _clue_link(a: Cluster, b: Cluster) -> bool:
    if conflict(a, b):
        return False
    full = any(full_match(x, y) for x in a.names for y in b.names)
    if full:
        if a.dobs & b.dobs:
            return True
        if any(rel_match(x, y) for x in a.relatives for y in b.relatives):
            return True
        if a.villages & b.villages or any(_village_match(x, y) for x in a.villages for y in b.villages):
            ra, rb = a.byear_range(), b.byear_range()
            if ra and rb and not (ra[0] > rb[1] + 1 or rb[0] > ra[1] + 1):
                return True
        return False
    # Fragment: given name (or a mention) plus the relative's name.
    ga = [given_of(x) for x in a.names + a.mentions]
    gb = [given_of(x) for x in b.names + b.mentions]
    ga = [g for g in ga if g]
    gb = [g for g in gb if g]
    if ga and gb and any(tokens_match(x, y) for x in ga for y in gb):
        small, big = (a, b) if (len(a.names) + len(a.ids)) <= (len(b.names) + len(b.ids)) else (b, a)
        if not small.relatives or not big.relatives:
            return False
        if any(rel_match(x, y) for x in small.relatives for y in big.relatives):
            # the fragment must not carry a full name that disagrees
            return True
    return False


def _village_match(a: tuple, b: tuple) -> bool:
    return len(a) == len(b) and all(tokens_match(x, y, 0.9) for x, y in zip(a, b))


def _block(t: str) -> str:
    """Blocking key tolerant to vowel spelling: first letter plus consonant skeleton."""
    from .translit import consonants
    return consonants(t)


def _strength(c: Cluster) -> int:
    return 3 * len(c.ids) + 2 * len(c.phones) + len(c.names)
