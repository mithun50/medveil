"""Residual leak gate.

After a document is rewritten, its serialized output is re-scanned for every piece
of personal data detected anywhere in that document or its patients' clusters:
name tokens in both scripts, digit identifiers across any separators, e-mails, IDs
and address strings. Hits outside protected clinical spans (doctor names, hospitals)
are redacted. The ledger lives in memory only and is never written.
"""
from __future__ import annotations

import re

from .detect.engine import ident_tokens, name_tokens
from .detect.patterns import digits, protected_spans
from .lexicon import is_stopword
from .textnorm import fold
from .translit import key

_WORDS = re.compile(r"[A-Za-z]+|[\u0900-\u0963\u0966-\u097F]+")
_DIGIT_RUN = re.compile(r"\d(?:[\s\-./()+]{0,2}\d)+")
_KEEP_KINDS = ("doctor", "org", "eponym", "asha", "drugdose")


class Ledger:
    def __init__(self):
        self.digit_items: set[str] = set()
        self.words: set[str] = set()
        self.texts: set[str] = set()

    def add_span(self, etype: str, surface: str, value) -> None:
        s = fold(surface).strip()
        if not s:
            return
        if etype in ("PHONE", "AADHAAR", "ABHA"):
            d = digits(s)
            if len(d) >= 10:
                self.digit_items.add(d[-10:] if etype == "PHONE" else d)
        elif etype == "MRN":
            groups = [g for g in re.findall(r"\d+", s) if len(g) >= 5]
            if groups:
                self.digit_items.add(max(groups, key=len))
            if len(s) >= 5:
                self.texts.add(s.casefold())
        elif etype in ("EMAIL", "PAN", "INSURANCE", "ABHA_ADDR"):
            if len(s) >= 5:
                self.texts.add(s.casefold())
        elif etype == "NAME":
            self.add_name(s)
        elif etype in ("HOUSE", "LOCALITY", "LANDMARK", "VILLAGE"):
            if len(s) >= 6:
                self.texts.add(s.casefold())

    def add_name(self, s: str) -> None:
        idents = set(ident_tokens(name_tokens(s)))
        for w in _WORDS.findall(fold(s)):
            lw = w.casefold()
            if len(w) >= 3 and not is_stopword(lw) and key(w) in idents:
                self.words.add(lw)


def _hits(text: str, ledger: Ledger) -> list[tuple[int, int]]:
    out = []
    cf = text.casefold()
    if ledger.words:
        for m in _WORDS.finditer(text):
            if m.group(0).casefold() in ledger.words:
                out.append((m.start(), m.end()))
    if ledger.digit_items:
        for m in _DIGIT_RUN.finditer(text):
            raw = m.group(0)
            d = digits(raw)
            for item in ledger.digit_items:
                if item in d:
                    # map the digit-only match back to the raw run
                    k = d.find(item)
                    pos = [i for i, c in enumerate(raw) if c.isdigit()]
                    s = m.start() + pos[k]
                    e = m.start() + pos[k + len(item) - 1] + 1
                    if not (text[s - 1:s].isdigit() if s else False):
                        out.append((s, e))
    for t in ledger.texts:
        i = cf.find(t)
        while i != -1:
            out.append((i, i + len(t)))
            i = cf.find(t, i + 1)
    return out


def scrub(text: str, ledger: Ledger) -> tuple[str, int]:
    """Redact residual ledger hits outside protected spans. Returns (text, hits)."""
    if not text or not (ledger.words or ledger.digit_items or ledger.texts):
        return text, 0
    folded = fold(text)
    if len(folded) == len(text):
        text = folded
    hits = _hits(text, ledger)
    if not hits:
        return text, 0
    prot = [(s, e) for s, e, k in protected_spans(text) if k in _KEEP_KINDS]
    keep = []
    for s, e in sorted(set(hits)):
        if any(ps <= s and e <= pe for ps, pe in prot):
            continue
        before = text[max(0, s - 4):s]
        if before.endswith("PSN-") or before.endswith("REC-") or text[max(0, s - 1):s] == "[":
            continue
        if keep and s < keep[-1][1]:
            keep[-1] = (keep[-1][0], max(keep[-1][1], e))
            continue
        keep.append((s, e))
    if not keep:
        return text, 0
    out, pos = [], 0
    for s, e in keep:
        out.append(text[pos:s])
        out.append("[REDACTED]")
        pos = e
    out.append(text[pos:])
    return "".join(out), len(keep)
