"""Detection engine: a learning pre-pass, then per-slot detection.

Pre-pass ("learn") collects knowledge that makes free-text detection context aware:
identifier shapes from ID columns and labels, full names from name columns, villages,
PINs and identifier digit cores. Detection then combines protected spans, patterns,
field semantics, context names, addresses and this knowledge.
"""
from __future__ import annotations

import re
from collections import defaultdict
from functools import lru_cache

from ..lexicon import GENERIC_NAME_TOKENS, HONORIFIC_PRE, NAME_PREFIX, SAFE_KEYS, district_of, is_given, is_stopword
from ..model import PII_TYPES, Doc, Slot, Span
from ..textnorm import encoded_payloads, normalize
from ..translit import key, tokens_match
from .dates import find_dates, order_evidence
from .names import find_address, find_names, is_lat_name_tok
from .patterns import (
    AADHAAR_MASKED, ID_LABEL, ID_LABEL_DEVA, digits, find_ages, find_ids, id_key, in_protected,
    phone10, protected_spans,
)

WORD = re.compile(r"[A-Za-z][A-Za-z'\-]*|[\u0900-\u0963\u0966-\u097F]+")
_DEVA = re.compile(r"[\u0900-\u097F]")
_PLAIN_KEY = re.compile(r"[a-z_][a-z0-9_]*(?:[A-Z][a-z0-9_]*)*")
_HAS_UP = re.compile(r"[A-Z]")
_HAS_DG = re.compile(r"\d")
_CHUNK_OVER = 32_768        # slots longer than this are detected chunk by chunk
_CHUNK_LEN = 4_096          # target chunk size; cuts only at a newline or whitespace
_CHUNK_MARGIN = 256         # each chunk is detected with this much context on both sides
_WS = re.compile(r"\s")
# lowercase text still gets name detection when a strong cue is present ("name: rohit mehra")
# Lowercase text only reaches find_names when one of these cues is present, so every label
# find_names accepts (names._LABELS, relation markers, honorifics) must be listed here.
_NAME_CUE = re.compile(r"(?i)\b(?:name|naam|patient|pt|attendant|guardian|relative|husband|father|wife|mother|"
                       r"spouse|nok|next of kin|informant|contact person|escort|bystander|beneficiary|rogi|"
                       r"mareez|mariz|[a-z]+ by|handed over to|report of|son of|daughter of|wife of|husband of|"
                       r"widow of|care of|baby of|[sdwcbfmh]\s?/\s?o|wd\s?/\s?o|ji|sahab|bhai|behenji|didi|amma|"
                       r"smt|shri|mr|mrs)\b|\b[a-z]+ (?:ka|ki|ke|ko|ne) ")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_DOB_CUE = re.compile(r"(?i)(?:\bD\.?\s?O\.?\s?B\.?|date\s+of\s+birth|birth\s*date|\bborn\b|जन्म(?:\s*तिथि)?|janm)\W{0,6}$")
_REL_PREFIX = re.compile(r"^\s*(?:(?:S|D|W|C|B|H|F|M|Wd)\s?/\s?O\.?|son of|daughter of|wife of|husband of|care of|"
                         r"पुत्र|पुत्री|पत्नी|पति)\s*[:\-]?\s*(?:श्री\s*)?", re.I)
_TITLE_PREFIX = re.compile(r"^\s*(?:(?:Mr|Mrs|Ms|Smt|Shri|Sri|Km|Miss|Late|Master|Baby)\.?\s+|श्री\s+|श्रीमती\s+)", re.I)

STRONG_PRIORITY = {"ENCODED": -1, "ABHA": 0, "AADHAAR": 1, "AADHAAR_MASKED": 1, "PHONE": 2, "EMAIL": 3, "ABHA_ADDR": 3, "PAN": 3,
                   "INSURANCE": 3, "MRN": 4, "DOB": 5, "NAME": 6, "HOUSE": 7, "LOCALITY": 7, "LANDMARK": 7,
                   "VILLAGE": 7, "TEHSIL": 7, "PIN": 7, "ADDRESS": 7, "DATE": 8, "AGE": 9}


def name_tokens(text: str) -> list[str]:
    """Identifying folded tokens of a name (titles stripped)."""
    out = []
    for w in WORD.findall(text):
        lw = w.lower().rstrip(".")
        if lw in HONORIFIC_PRE or w in ("श्री", "श्रीमती"):
            continue
        k = key(w)
        if k:
            out.append(k)
    return out


def ident_tokens(toks: list[str]) -> list[str]:
    return list(_ident_cached(tuple(toks)))


_GENERIC_KEYS = frozenset(key(g) for g in GENERIC_NAME_TOKENS)


@lru_cache(maxsize=200_000)
def _ident_cached(toks: tuple) -> tuple:
    return tuple(t for t in toks if t not in _GENERIC_KEYS and len(t) >= 2)


class Shapes:
    def __init__(self):
        self.vals: dict[str, str] = {}
        self.counts: dict[str, int] = defaultdict(int)
        self._pats: list[re.Pattern] = []
        self._known: re.Pattern | None = None
        self.cores: set[str] = set()

    @staticmethod
    def shape(raw: str) -> str | None:
        parts = re.findall(r"[A-Za-z]+|\d+|[^A-Za-z\d]+", raw.strip())
        if not parts:
            return None
        if not any(p[0].isalpha() for p in parts) or sum(len(p) for p in parts if p.isdigit()) < 3:
            return None
        rx = []
        for p in parts:
            if p.isdigit():
                rx.append(r"\d{%d}" % len(p))
            elif p.isalpha():
                if len(p) > 6:
                    return None
                rx.append(re.escape(p.upper()))
            else:
                rx.append(r"[\s/\-_.]?")
        return "".join(rx)

    def learn(self, raw: str) -> None:
        raw = raw.strip()
        k = id_key(raw)
        if len(k) < 4 or sum(c.isdigit() for c in k) < 3:
            return
        self.vals[k] = raw
        groups = [g for g in re.findall(r"\d+", raw) if len(g) >= 5]
        if groups:
            self.cores.add(max(groups, key=len))
        sh = self.shape(raw)
        if sh:
            self.counts[sh] += 1

    def finalize(self) -> None:
        self._pats = [re.compile(r"(?<![A-Za-z0-9])" + sh + r"(?![A-Za-z0-9])", re.I)
                      for sh, n in sorted(self.counts.items()) if n >= 2]
        alts = []
        for raw in sorted(set(self.vals.values()), key=lambda s: (-len(s), s)):
            parts = re.findall(r"[A-Za-z]+|\d+", raw)
            if len(parts) >= 2 or (parts and not parts[0].isdigit()):
                alts.append(r"[\s/\-_.]?".join(re.escape(p) for p in parts))
        self._known = re.compile(r"(?<![A-Za-z0-9])(?:" + "|".join(alts) + r")(?![A-Za-z0-9])", re.I) if alts else None

    def patterns(self) -> list[re.Pattern]:
        return self._pats + ([self._known] if self._known is not None else [])

    def known(self, k: str) -> bool:
        return k in self.vals


class Knowledge:
    def __init__(self):
        self.shapes = Shapes()
        self.full_names: dict[tuple, str] = {}     # sorted ident token keys -> role
        self.first_index: dict[str, list[tuple]] = defaultdict(list)
        self.villages: set[tuple] = set()
        self.village_first: dict[str, list[tuple]] = defaultdict(list)
        self.pins: set[str] = set()
        self.phones: set[str] = set()

    def add_name(self, text: str, role: str) -> None:
        toks = name_tokens(text)
        if len(toks) < 2 or len(toks) > 4 or not ident_tokens(toks):
            return
        tup = tuple(sorted(toks))
        if tup not in self.full_names:
            self.full_names[tup] = role
            for t in toks:
                self.first_index[t].append(tup)

    def add_village(self, text: str) -> None:
        toks = [key(w) for w in WORD.findall(text) if key(w)]
        if not toks or len(toks) > 4:
            return
        if district_of(text):
            return
        tup = tuple(toks)
        if len("".join(tup)) < 5:
            return
        self.villages.add(tup)
        self.village_first[tup[0]].append(tup)

    def finalize(self) -> None:
        self.shapes.finalize()
        for k in self.first_index:
            self.first_index[k] = sorted(set(self.first_index[k]))
        for k in self.village_first:
            self.village_first[k] = sorted(set(self.village_first[k]), key=lambda t: -len(t))


WHOLE_TYPES = {"NAME", "FIRST_NAME", "LAST_NAME", "RELATIVE", "PHONE", "AADHAAR", "ABHA", "PAN", "EMAIL",
               "INSURANCE", "MRN", "DOB", "VILLAGE", "TEHSIL", "PIN", "ABHA_ADDR"}
NO_DETECT = {"GENDER", "DISTRICT", "STATE", "RELATION"}


def learn_doc(doc: Doc, K: Knowledge) -> None:
    """Pre-pass over one parsed document."""
    for rec in doc.records:
        first = last = None
        for sl in rec.slots:
            t, ft = sl.text, sl.ftype
            if not t or t.lower() in ("null", "none", "na", "n/a", "-"):
                continue
            if ft == "MRN" and not _UUID.match(t) and sl.kind != "key":
                K.shapes.learn(t)
            elif ft == "NAME" and sl.kind != "key":
                K.add_name(_TITLE_PREFIX.sub("", t), "patient")
            elif ft == "RELATIVE" and sl.kind != "key":
                K.add_name(_REL_PREFIX.sub("", t), "relative")
            elif ft == "FIRST_NAME":
                first = t
            elif ft == "LAST_NAME":
                last = t
            elif ft == "VILLAGE" and sl.kind != "key":
                K.add_village(t)
            elif ft == "PIN":
                d = digits(t)
                if len(d) == 6:
                    K.pins.add(d)
            elif ft == "PHONE":
                p = phone10(t)
                if p:
                    K.phones.add(p)
            if ft in (None, "TEXT") or sl.kind in ("text",):
                for m in ID_LABEL.finditer(t):
                    K.shapes.learn(m.group(2))
                for m in ID_LABEL_DEVA.finditer(t):
                    K.shapes.learn(m.group(2))
        if first and last:
            K.add_name(f"{first} {last}", "patient")
    if doc.fmt in ("text",) or doc.fmt in ("csv", "tsv", "json", "fhir"):
        dm, md = 0, 0
        for rec in doc.records:
            for sl in rec.slots:
                if sl.ftype in ("DATE", "DOB", None, "TEXT"):
                    a, b = order_evidence(sl.text)
                    dm += a
                    md += b
        hint = doc.header_hint
        if "mm/dd" in hint or "mm dd" in hint:
            md += 5
        if "dd/mm" in hint:
            dm += 5
        doc.date_votes = (dm, md)


def _known_name_spans(text: str, K: Knowledge, prot) -> list[Span]:
    out = []
    words = list(WORD.finditer(text))
    keys = [key(m.group(0)) for m in words]
    i = 0
    while i < len(words):
        k = keys[i]
        cands = K.first_index.get(k)
        hit = None
        if cands:
            for tup in cands:
                n = len(tup)
                if i + n > len(words):
                    continue
                # contiguous words, single spaces or underscores, any order
                window = words[i:i + n]
                gaps_ok = all(re.fullmatch(r"[\s_.]{1,3}", text[window[x].end():window[x + 1].start()] or "x")
                              for x in range(n - 1))
                if not gaps_ok:
                    continue
                wk = sorted(keys[i:i + n])
                if all(tokens_match(a, b, 0.92) for a, b in zip(wk, tup)):
                    hit = (window[0].start(), window[-1].end(), K.full_names[tup])
                    break
        if hit and not in_protected(prot, hit[0], hit[1]):
            out.append(Span(hit[0], hit[1], "NAME", role="mention", conf=0.9, value=text[hit[0]:hit[1]], rule="known_name"))
        i += 1
    return out


def _known_village_spans(text: str, K: Knowledge, prot) -> list[Span]:
    out = []
    words = list(WORD.finditer(text))
    keys = [key(m.group(0)) for m in words]
    for i, k in enumerate(keys):
        for tup in K.village_first.get(k, ()):
            n = len(tup)
            if tuple(keys[i:i + n]) == tup:
                s, e = words[i].start(), words[i + n - 1].end()
                if not in_protected(prot, s, e):
                    out.append(Span(s, e, "VILLAGE", value=text[s:e], rule="known_village"))
                break
    return out


def _known_id_spans(text: str, K: Knowledge) -> list[Span]:
    out = []
    # digits with a separator between every digit ("2 0 2 6 0 0 4 6 1") hide a known ID core
    for m in re.finditer(r"(?<![\dA-Za-z])\d(?:[ .\-]\d){4,}(?![\dA-Za-z])", text):
        d = re.sub(r"\D", "", m.group(0))
        if any(c in d for c in K.shapes.cores) or d in K.phones:
            out.append(Span(m.start(), m.end(), "MRN", value=None, rule="spaced_id"))
    for m in re.finditer(r"(?<![\dA-Za-z])\d{5,}(?![\dA-Za-z])", text):
        d = m.group(0)
        before = text[m.start() - 1:m.start()] if m.start() else ""
        after = text[m.end():m.end() + 1]
        if d in K.shapes.cores and before not in ("/", "-") and after not in ("/", "-"):
            # redact the digit core, but never use it as linking evidence
            out.append(Span(m.start(), m.end(), "MRN", value=None, rule="id_core"))
        elif len(d) == 10 and d in K.phones:
            out.append(Span(m.start(), m.end(), "PHONE", value=d, rule="known_phone"))
        elif len(d) == 6 and d in K.pins:
            out.append(Span(m.start(), m.end(), "PIN", value=d, rule="known_pin"))
    return out


def resolve(spans: list[Span]) -> list[Span]:
    spans = sorted(spans, key=lambda s: (STRONG_PRIORITY.get(s.etype, 10), -(s.end - s.start), -s.conf, s.start))
    chosen: list[Span] = []
    for sp in spans:
        if sp.end <= sp.start:
            continue
        if any(sp.overlaps(c) for c in chosen):
            # a longer name may absorb an overlapping weaker name
            continue
        chosen.append(sp)
    chosen.sort(key=lambda s: s.start)
    return chosen


def detect_slot(sl: Slot, K: Knowledge, doc: Doc, file_level: bool = False, _depth: int = 0) -> None:
    text = sl.text
    if not text or not text.strip() or text.lower() in ("null", "none"):
        return
    if len(text) > _CHUNK_OVER and sl.ftype in (None, "TEXT", "ADDRESS") and not sl.number and _depth == 0:
        _detect_chunked(sl, K, doc, file_level)
        return
    # Plain programmatic JSON keys ("resourceType", "visit_date") cannot hold personal data,
    # unless one of their parts is a known given name ("zainab_siddiqui").
    if sl.kind == "key" and _PLAIN_KEY.fullmatch(text) and not any(
            is_given(p) for p in text.split("_") if len(p) >= 3 and not is_stopword(p)):
        return
    ft = sl.ftype
    spans: list[Span] = []
    view = text.replace("_", " ")
    if ft == "DOCTOR":
        sl.protected = [(0, len(text), "doctor")]
        return
    if sl.kind == "key" and not file_level:
        file_level = True
    if ft in WHOLE_TYPES and sl.kind not in ("key",):
        s0 = len(text) - len(text.lstrip())
        e0 = len(text.rstrip())
        if ft in ("NAME", "FIRST_NAME", "LAST_NAME"):
            if re.match(r"(?i)\s*(?:dr\.?|doctor)\s", text):
                sl.protected = [(0, len(text), "doctor")]
                return
            m = _TITLE_PREFIX.match(text)
            s1 = m.end() if m else s0
            if re.search(r"[A-Za-z\u0900-\u097F]", text):
                spans.append(Span(s1, e0, "NAME", role="patient", value=text[s1:e0], rule="field_" + ft.lower()))
        elif ft == "RELATIVE":
            m = _REL_PREFIX.match(text)
            s1 = m.end() if m else s0
            if re.search(r"[A-Za-z\u0900-\u097F]", text[s1:]):
                spans.append(Span(s1, e0, "NAME", role="relative", value=text[s1:e0], rule="field_relative"))
        elif ft == "MRN":
            if _UUID.match(text.strip()) or not re.search(r"\d", text):
                return
            spans.append(Span(s0, e0, "MRN", value=id_key(text), rule="field_mrn"))
        elif ft == "AADHAAR":
            if AADHAAR_MASKED.search(text):
                spans.append(Span(s0, e0, "AADHAAR_MASKED", value=digits(text)[-4:], rule="field_aadhaar"))
            elif len(digits(text)) >= 4:
                spans.append(Span(s0, e0, "AADHAAR", value=digits(text), rule="field_aadhaar"))
        elif ft == "PHONE":
            if len(digits(text)) >= 6:
                spans.append(Span(s0, e0, "PHONE", value=phone10(text) or digits(text), rule="field_phone"))
        elif ft == "DOB":
            spans.append(Span(s0, e0, "DOB", value=None, rule="field_dob"))
        elif ft == "PIN":
            if digits(text):
                spans.append(Span(s0, e0, "PIN", value=digits(text), rule="field_pin"))
        elif ft in ("VILLAGE", "TEHSIL"):
            if district_of(text):
                return
            spans.append(Span(s0, e0, ft, value=text.strip(), rule="field_" + ft.lower()))
        else:  # ABHA, PAN, EMAIL, INSURANCE, ABHA_ADDR
            if text.strip():
                spans.append(Span(s0, e0, ft, value=id_key(text) if ft != "EMAIL" else text.strip().lower(),
                                  rule="field_" + ft.lower()))
        sl.spans = spans
        return
    if ft in NO_DETECT:
        return
    if ft == "AGE":
        m = re.search(r"\d{1,3}", text)
        if m and sl.number:
            sl.spans = [Span(0, len(text), "AGE", value=int(float(text)), rule="field_age")]
        elif m:
            sl.spans = [Span(m.start(), m.end(), "AGE", value=int(m.group(0)), rule="field_age")]
        return
    if ft == "AGE_SEX":
        m = re.search(r"\d{1,3}", text)
        if m:
            sl.spans = [Span(m.start(), m.end(), "AGE", value=int(m.group(0)), rule="field_age_sex")]
        return
    if sl.number:
        # Numbers outside typed fields: only identifier-sized integers matter.
        d = text.split(".")[0]
        if len(d) == 12:
            sl.spans = [Span(0, len(text), "AADHAAR", value=d, rule="number_aadhaar")]
        elif len(d) == 14:
            sl.spans = [Span(0, len(text), "ABHA", value=d, rule="number_abha")]
        elif len(d) == 10 and d[0] in "6789":
            sl.spans = [Span(0, len(text), "PHONE", value=d, rule="number_phone")]
        return
    has_upper = _HAS_UP.search(view) is not None or _DEVA.search(view) is not None
    has_digit = _HAS_DG.search(view) is not None
    prot = protected_spans(view) if (has_upper or ft == "ADDRESS" or "/" in view) else []
    sl.protected = prot
    order = doc.date_order
    # Base64 or hex runs hiding personal data inside free text are replaced as a whole.
    if len(view) >= 16 and _depth < 3:
        for s, e, dec in encoded_payloads(view):
            sub = Slot(path=(), text=normalize(dec), ftype="TEXT", kind="value")
            detect_slot(sub, K, doc, file_level, _depth + 1)
            if any(sp.etype in PII_TYPES for sp in sub.spans):
                spans.append(Span(s, e, "ENCODED", value=None, rule="encoded_payload"))
    safe_clinical = (ft is None and sl.kind == "value" and sl.key.lower() in SAFE_KEYS and len(view) < 60)
    ids = find_ids(view, K.shapes) if has_digit or "@" in view else []
    spans.extend(ids)
    if has_digit:
        spans.extend(_known_id_spans(view, K))
    phones = [s for s in ids if s.etype == "PHONE"]
    if has_digit and (ft == "DATE" or ft is None or ft in ("TEXT", "ADDRESS")):
        for h in find_dates(view, order):
            before = view[max(0, h.start - 22):h.start]
            et = "DOB" if _DOB_CUE.search(before) else "DATE"
            spans.append(Span(h.start, h.end, et, value=h, rule="date"))
    if ft == "DATE" or safe_clinical:
        sl.spans = resolve(spans)
        return
    if has_digit:
        spans.extend(find_ages(view))
    if has_upper or _NAME_CUE.search(view):
        names = find_names(view, prot, phones)
        spans.extend(names)
        spans.extend(_known_name_spans(view, K, prot))
        spans.extend(_known_village_spans(view, K, prot))
    if has_upper or ft == "ADDRESS" or ("near" in view.lower() or "opp" in view.lower()):
        spans.extend(find_address(view, prot, whole=(ft == "ADDRESS")))
    if file_level and has_upper:
        spans.extend(_aggressive_names(view, prot, any(s.etype in ("MRN", "PHONE") for s in ids)))
    sl.spans = resolve(spans)


def _chunks(text: str):
    """Split at newlines; split long lines at the last whitespace before _CHUNK_LEN.
    A run without whitespace (a base64 blob) stays whole so it can still be decoded."""
    pos = 0
    n = len(text)
    while pos < n:
        end = min(n, pos + _CHUNK_LEN)
        if end < n:
            nl = text.rfind("\n", pos, end)
            if nl > pos:
                end = nl + 1
            else:
                ws = max(text.rfind(" ", pos, end), text.rfind("\t", pos, end))
                if ws > pos:
                    end = ws + 1
                else:
                    m = re.compile(r"\s").search(text, end)
                    end = m.end() if m else n
        yield pos, text[pos:end]
        pos = end


def _detect_chunked(sl: Slot, K: Knowledge, doc: Doc, file_level: bool) -> None:
    """Detection for very long text in chunks. Identical chunks (degenerate or repeated
    content) are detected once, which keeps hostile inputs like 'Dr. ' * 300000 linear.

    Each chunk is detected with context on both sides: up to 256 characters before it and
    256 after it, both cut at whitespace. So a spaced phone number cut by the boundary is
    matched whole, a name whose label ("Name:", "Dr.") ends the previous chunk keeps its
    cue, and a doctor's title still protects the name after it. A span belongs to the chunk
    it starts in; a span that starts inside one already taken is dropped."""
    text = sl.text
    n = len(text)
    cache: dict[tuple[str, str, str], tuple[list, list]] = {}
    spans: list[Span] = []
    prot: list = []
    taken_until = 0
    for off, chunk in _chunks(text):
        end = off + len(chunk)
        tail = lead = ""
        if end < n:
            m_end = min(n, end + _CHUNK_MARGIN)
            ws = _WS.search(text, m_end, min(n, m_end + _CHUNK_LEN))
            tail = text[end:(ws.start() if ws else m_end)]
        if off > 0:
            ws = _WS.search(text, max(0, off - _CHUNK_MARGIN), off)
            lead = text[ws.end():off] if ws else ""
        key = (lead, chunk, tail)
        hit = cache.get(key)
        if hit is None:
            sub = Slot(path=sl.path, text=lead + chunk + tail, ftype=sl.ftype, key=sl.key, kind=sl.kind)
            detect_slot(sub, K, doc, file_level, 1)
            hit = (sub.spans, sub.protected)
            if len(cache) < 4096:
                cache[key] = hit
        lo, hi = len(lead), len(lead) + len(chunk)
        base = off - lo
        for sp in hit[0]:
            if not lo <= sp.start < hi or sp.start + base < taken_until:
                continue
            spans.append(Span(sp.start + base, sp.end + base, sp.etype, sp.role, sp.value, sp.conf, sp.rule))
            taken_until = max(taken_until, sp.end + base)
        for s, e, k in hit[1]:
            if e > lo and s < hi:
                prot.append((max(s, lo) + base, e + base, k))
    sl.spans = spans
    sl.protected = prot


def _aggressive_names(text: str, prot, has_id: bool = False) -> list[Span]:
    """File names, headers and keys: a known given name, or any capitalised word sitting
    next to an identifier ("HSP/0077 Sunaina"), is personal data."""
    out = []
    for m in WORD.finditer(text):
        w = m.group(0)
        if w[0].isascii() and not is_lat_name_tok(w):
            continue
        if is_stopword(w) or w.lower() in NAME_PREFIX:
            continue
        if in_protected(prot, m.start(), m.end()):
            continue
        if is_given(w) or has_id:
            out.append(Span(m.start(), m.end(), "NAME", role="mention", conf=0.6, value=w, rule="file_given"))
    return out
