"""Context-driven person-name and address detection in Latin, Devanagari and Hinglish.

Names are found from context, not from a list of known patients:
labels ("Name:", "नाम:", "Attendant:"), relation markers (S/o, W/o, C/O, पुत्र),
honorifics ("ji", "sahab", "Smt."), Hindi postpositions ("Irfan ka BP", "कविता को"),
chat senders, closeness to a phone number, and gazetteer given+surname pairs.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..lexicon import (
    DEVA_POSTPOSITIONS, DEVA_RELATION, HINDI_COMMON, HINDI_POSTPOSITIONS, HONORIFIC_POST,
    HONORIFIC_POST_DEVA, HONORIFIC_PRE, HONORIFIC_PRE_DEVA, NAME_PREFIX, is_given, is_name_token,
    is_stopword, is_surname,
)
from ..model import Span
from .patterns import co_is_complaint, in_protected, overlaps_protected

TOKEN = re.compile(r"[A-Za-z][A-Za-z'\-]*\.?|[\u0900-\u0963\u0966-\u097F\u200c\u200d]+|\d+|[ \t]+|\r?\n|.", re.S)

LABEL_WORDS = frozenset("""
age sex gender uhid ipd ip opd mrn mob mobile phone ph contact address addr dob reg regn no date
ward bed consultant diagnosis village vill gram gaon tehsil teh distt district dist pin pincode
aadhaar aadhar abha relation attendant patient pt name hospital doctor dr mr mrs ms smt shri
yrs yr years year y m f male female visit discharge admission advice review rx tab cap inj
mohalla house makan near opp email report forwarded type the of and with for to from by on in
at is was sample test result unit range collected reported referred status amount bill package
policy claim id
""".split())


@dataclass
class Tok:
    text: str
    s: int
    e: int
    kind: str  # lat | deva | num | ws | nl | p


def tokenize(text: str) -> list[Tok]:
    out = []
    for m in TOKEN.finditer(text):
        t = m.group(0)
        if t[0].isalpha() and t[0].isascii():
            k = "lat"
        elif "\u0900" <= t[0] <= "\u097f":
            k = "deva"
        elif t[0].isdigit():
            k = "num"
        elif t in ("\n", "\r\n"):
            k = "nl"
        elif t.isspace():
            k = "ws"
        else:
            k = "p"
        out.append(Tok(t, m.start(), m.end(), k))
    return out


def _bare(t: str) -> str:
    return t.rstrip(".").strip("'")


def is_lat_name_tok(t: str) -> bool:
    b = _bare(t)
    if len(b) < 2 or not b[0].isupper():
        return False
    lb = b.lower()
    if lb in LABEL_WORDS or is_stopword(lb) or lb in HONORIFIC_POST or lb in HONORIFIC_PRE:
        return False
    if b.isupper() and len(b) <= 4 and not is_name_token(b):
        return False  # acronyms: BP, DM, HTN, ATT
    if not re.search(r"[aeiouyAEIOUY]", b):
        return False
    return True


def is_deva_name_tok(t: str) -> bool:
    if t in HINDI_COMMON or t in DEVA_POSTPOSITIONS or t in DEVA_RELATION or t in HONORIFIC_PRE_DEVA:
        return False
    if t in HONORIFIC_POST_DEVA:
        return False
    return len(t) >= 2


_NOT_A_NAME = frozenset("not na nil none unknown self same as above below given available applicable mentioned "
                        "stated known baby infant child n/a".split())


# letters with internal hyphens or apostrophes, as the tokenizer keeps them: "anne-marie", "o'brien"
_ANYCASE_TOK = re.compile(r"[A-Za-z]+(?:['\-][A-Za-z]+)*")


def is_lat_name_tok_anycase(t: str) -> bool:
    """After a strong cue (a label, a relation marker) a word is a name whatever its case:
    'name: rohit mehra' and 'Name: rOhIt' are as personal as 'Name: Rohit'."""
    b = _bare(t)
    lb = b.lower()
    if len(b) < 2 or not _ANYCASE_TOK.fullmatch(b):
        return False
    if lb in LABEL_WORDS or lb in _NOT_A_NAME or is_stopword(lb) or lb in HONORIFIC_POST or lb in HONORIFIC_PRE:
        return False
    if not re.search(r"[aeiouy]", lb):
        return False
    return True


class Toks:
    """Token list with helpers for walking over single spaces."""

    def __init__(self, text: str):
        self.text = text
        self.t = tokenize(text)

    def next_word(self, i: int, allow_colon=False) -> int | None:
        """Index of the next word token after i, crossing at most one space (or ': ' / '- ')."""
        j = i + 1
        n = len(self.t)
        seen_space = 0
        while j < n:
            tk = self.t[j]
            if tk.kind == "ws":
                if len(tk.text) > 1 and "\t" not in tk.text and seen_space == 0 and allow_colon:
                    seen_space += 1
                    j += 1
                    continue
                if len(tk.text) > 1 or "\t" in tk.text:
                    return None
                seen_space += 1
                if seen_space > 2:
                    return None
                j += 1
                continue
            if tk.kind == "p" and allow_colon and tk.text in ":-\u2013=#":
                j += 1
                continue
            if tk.kind in ("lat", "deva"):
                return j
            return None
        return None

    def take_name(self, j: int | None, script: str | None = None, max_tok: int = 4,
                  any_case: bool = False) -> tuple[int, int] | None:
        """From word index j take a run of name tokens. Returns (first, last) token indices."""
        if j is None:
            return None
        first = j
        tk = self.t[j]
        script = script or tk.kind
        # Allow a name prefix like "Md." or "Mohd." at the start.
        count = 0
        last = None
        k = j
        while k is not None and k < len(self.t) and count < max_tok:
            tk = self.t[k]
            if tk.kind != script:
                break
            word = tk.text
            if script == "lat":
                ok = is_lat_name_tok(word) or (_bare(word).lower() in NAME_PREFIX and count == 0) or \
                    (re.fullmatch(r"[A-Z]\.", word) is not None) or (any_case and is_lat_name_tok_anycase(word))
            else:
                ok = is_deva_name_tok(word)
            if not ok:
                break
            last = k
            count += 1
            if script == "lat" and word.endswith(".") and _bare(word).lower() not in NAME_PREFIX and not re.fullmatch(r"[A-Z]\.", word):
                break  # sentence end
            nxt = self.next_word(k)
            if nxt is None or nxt != k + 2:
                break
            k = nxt
        if last is None:
            return None
        # A run made only of a prefix ("Md.") is not a name.
        if all(_bare(self.t[x].text).lower() in NAME_PREFIX for x in range(first, last + 1) if self.t[x].kind == script):
            return None
        return first, last

    def take_name_back(self, end_idx: int, script: str, max_tok: int = 3, gazetteer_any_case: bool = False):
        """Name tokens ending right before token index end_idx (separated by one space)."""
        k = end_idx - 1
        if k < 0 or self.t[k].kind != "ws" or len(self.t[k].text) != 1:
            return None
        k -= 1
        last = k
        first = None
        count = 0
        while k >= 0 and count < max_tok:
            tk = self.t[k]
            if tk.kind != script:
                break
            ok = is_lat_name_tok(tk.text) if script == "lat" else is_deva_name_tok(tk.text)
            if not ok and script == "lat" and gazetteer_any_case:
                # "rohit ji": a lowercase word before an honorific counts if it is a known name
                ok = is_lat_name_tok_anycase(tk.text) and is_name_token(_bare(tk.text))
            if not ok:
                if script == "lat" and _bare(tk.text).lower() in NAME_PREFIX and first is not None:
                    first = k
                break
            if script == "lat" and tk.text.endswith(".") and _bare(tk.text).lower() not in NAME_PREFIX:
                if count > 0:
                    break
            first = k
            count += 1
            if k - 2 < 0 or self.t[k - 1].kind != "ws" or len(self.t[k - 1].text) != 1:
                break
            k -= 2
        if first is None:
            return None
        return first, last

    def span(self, a: int, b: int) -> tuple[int, int]:
        s, e = self.t[a].s, self.t[b].e
        txt = self.text[s:e]
        if txt.endswith(".") and _bare(self.t[b].text).lower() not in NAME_PREFIX and not re.fullmatch(r"[A-Z]\.", self.t[b].text):
            e -= 1
        return s, e


# Labels that introduce a name, with the role of that person.
_LABELS = [
    (re.compile(r"(?i)\b(?:patient(?:'s)?\s*name|pt\.?\s*name|name\s+of\s+(?:the\s+)?patient|patient|pt|naam|name|"
                r"beneficiary(?:\s+name)?|report\s+of|rogi(?:\s+ka\s+naam)?|mareez(?:\s+ka\s+naam)?|mariz)\s*[:\-=]\s*"), "patient"),
    (re.compile(r"(?i)\breport\s+of\s+"), "patient"),
    (re.compile(r"(?i)\b(?:attendant|guardian|relative|father(?:'s)?(?:\s+name)?|husband(?:'s)?(?:\s+name)?|"
                r"mother(?:'s)?(?:\s+name)?|wife(?:'s)?(?:\s+name)?|spouse|nok|next\s+of\s+kin|informant|"
                r"contact\s+person|escort|bystander)\s*[:\-=]\s*"), "relative"),
    (re.compile(r"(?i)\b(?:called\s+by|witnessed\s+by|raised\s+by|signed\s+by|brought\s+by|accompanied\s+by|"
                r"informed\s+by|visited\s+by|submitted\s+by|reported\s+by|consent\s+(?:given|signed)\s+by|"
                r"received\s+by|collected\s+by|handed\s+over\s+to)\s*[:\-=]?\s*"), "other"),
    (re.compile(r"(?:मरीज़?\s*का\s*नाम|रोगी\s*का\s*नाम|नाम|मरीज़?|रोगी|मरीज़ा)\s*[:：\-]\s*"), "patient"),
    (re.compile(r"(?:पिता\s*का\s*नाम|पति\s*का\s*नाम|माता\s*का\s*नाम|पत्नी\s*का\s*नाम|अभिभावक|परिचारक|"
                r"पिता/पति\s*का\s*नाम)\s*[:：\-]\s*"), "relative"),
]
_REL = re.compile(r"(?i)(?<![A-Za-z/])(S|D|W|C|B|F|M|Wd|H)\s?/\s?O\b\.?\s*[:\-]?\s*|"
                  r"\b(?:son|daughter|wife|husband|widow|care|baby)\s+of\s+")
_DEVA_REL = re.compile(r"(?:पुत्र|पुत्री|पत्नी|पति|सुपुत्र|सुपुत्री|पिता)\s*(?:श्री\s*)?")
_POSSESSIVE_REL = re.compile(r"\b((?:[A-Z][a-z]+\s){0,2}[A-Z][a-z]+)['\u2019]s\s+(?:attendant|wife|husband|son|daughter|"
                             r"mother|father|brother|sister|guardian|relative|relatives|family|caretaker|bystander|"
                             r"in-laws?|mother-in-law|father-in-law|nephew|niece|grandson|granddaughter|escort)\b")
_CHAT = re.compile(r"^\[[^\]\n]{4,40}\]\s*([^:\n]{2,40}):", re.M)
_REL_BEFORE = re.compile(r"(?i)(?:father|husband|mother|wife|guardian|spouse|relative|attendant|son|daughter)(?:'s)?\s*$|"
                         r"(?:पिता|पति|माता|पत्नी|पिता/पति|अभिभावक)\s*का\s*$")
_NAME_BEFORE_REL = re.compile(r"(?:^|[\n.:;|]\s*|\s)((?:[A-Za-z][A-Za-z]+\.? ){0,2}[A-Za-z][A-Za-z]+),?\s*$")
_GENERIC_SUFFIX = {"devi", "kumari", "bano", "begum", "khatoon", "khatun", "kaur", "bibi", "begam"}
# Kinship words that are part of how a relative is named ("Kamal Bhaiya", "Akram Mama").
_KINSHIP = {"bhaiya", "bhaiyya", "mama", "mami", "chacha", "chachi", "mausi", "mausa", "kaka", "kaki", "bhabhi",
            "bhabi", "nana", "nani", "dada", "dadi", "tau", "tai", "uncle", "aunty", "auntie", "jija", "bua", "fufa"}
_ADJ_GAP = re.compile(r"^[\s,;:]*(?:\([^)\n]{0,40}\))?[\s,;:]*(?:(?:mob(?:ile)?|ph(?:one)?|contact|tel|cell|no|call)\.?\s*(?:no\.?)?)?[\s.:\-#]*$", re.I)


# Hinglish role and kinship words ("Pita/Pati ka Naam", "Sambandhi ka Naam", "Mareez ka
# BP"): before ka/ki/ke they name a role, not a person.
_ROLE_WORDS = frozenset("""
pita pati mata maa papa patni beta beti bete bahu saas sasur bhai bhaiya behen bahan didi devar jeth
bhabhi chacha chachi mama mami nana nani dada dadi bua fufa mausa mausi sambandhi rishtedar parijan
abhibhavak sanrakshak rogi mareez mariz marij patient doctor daktar nurse ghar gaon gram mohalla
aspatal hospital ward bachcha bachche bacche shishu
""".split())
# a label word after ka/ki/ke: "<X> ka Naam / Pata / Umar / Number" is a field label
_LABEL_AFTER = frozenset("naam nam pata umar umra number no mobile phone janm tithi ling aadhaar".split())


def _role_before_postposition(T: "Toks", r: tuple[int, int], i: int) -> bool:
    words = [T.t[k].text for k in range(r[0], r[1] + 1) if T.t[k].kind == "lat"]
    if any(_bare(w).lower() in _ROLE_WORDS or "/" in w for w in words):
        return True
    # "<X> ka Naam" is a field label unless X is a known name ("Ramesh ka number" is Ramesh)
    j = T.next_word(i)
    return (j is not None and _bare(T.t[j].text).lower() in _LABEL_AFTER
            and not any(is_name_token(_bare(w)) for w in words))


def _is_known_word(b: str) -> bool:
    """A gazetteer name, or a hyphen/apostrophe compound whose parts of 2+ letters all are
    ("mary-ann", "ram-prasad")."""
    if is_name_token(b):
        return True
    parts = [x for x in re.split(r"['\-]", b) if len(x) >= 2]
    return len(parts) > 1 and all(is_name_token(x) for x in parts)


def _known_run(T: Toks, r: tuple[int, int] | None) -> tuple[int, int] | None:
    """The leading tokens of run r that are known given names or surnames, or None."""
    if r is None:
        return None
    last = None
    for k in range(r[0], r[1] + 1):
        tk = T.t[k]
        if tk.kind == "ws":
            continue
        if tk.kind != "lat" or not _is_known_word(_bare(tk.text)):
            break
        last = k
    return (r[0], last) if last is not None else None


def find_names(text: str, prot: list, phone_spans: list[Span]) -> list[Span]:
    if not text or not re.search(r"[A-Za-z\u0900-\u097F]", text):
        return []
    T = Toks(text)
    toks = T.t
    pos2idx = {tk.s: i for i, tk in enumerate(toks)}
    cands: list[Span] = []

    def idx_at(pos: int) -> int | None:
        while pos < len(text) and text[pos] in " \t":
            pos += 1
        return pos2idx.get(pos)

    def add(a, b, role, conf, rule):
        s, e = T.span(a, b)
        if e <= s:
            return
        if overlaps_protected(prot, s, e, kinds=("doctor", "org", "eponym", "asha", "drugdose", "history", "complaint")):
            return
        # "Kamal Bhaiya": the kinship word after a name is part of the relative's name
        km = re.match(r" ([A-Za-z]+)\b", text[e:e + 12])
        if km and km.group(1).lower() in _KINSHIP:
            e += km.end()
        cands.append(Span(s, e, "NAME", role=role, conf=conf, value=text[s:e], rule=rule))

    # 1. labels (a bare "Name:" or "नाम:" right after a relative word belongs to the relative)
    for rx, role in _LABELS:
        for m in rx.finditer(text):
            if role == "patient" and _REL_BEFORE.search(text[max(0, m.start() - 24):m.start()]):
                continue
            j = idx_at(m.end())
            if j is None or toks[j].kind not in ("lat", "deva"):
                continue
            # Any letter case only after an explicit separator ("name: rohit mehra"); "report of"
            # or "reported by" without one is often followed by clinical words. A bare "Patient:"
            # is often followed by a complaint, so there lowercase words count only while they
            # are known given names or surnames ("Patient: rohit mehra", not "Patient: fever").
            bare = re.sub(r"[\s:\-=]+$", "", m.group(0)).strip().lower().rstrip(".")
            sep = re.search(r"[:\-=]\s*$", m.group(0)) is not None
            if bare in ("patient", "pt"):
                # the longer of the capitalised run and the known-name run ("Rohit mehra")
                cands_r = [x for x in (T.take_name(j), _known_run(T, T.take_name(j, any_case=True))) if x]
                r = max(cands_r, key=lambda x: x[1]) if cands_r else None
            else:
                r = T.take_name(j, any_case=sep)
            if r:
                add(r[0], r[1], role, 0.95, "label")
    # 2. relation markers
    for m in _REL.finditer(text):
        g = (m.group(1) or "").upper()
        if g in ("S", "D", "W", "B", "WD"):
            # "Asha, W/o Kamal": the name before the marker is the patient (any letter case)
            bm = _NAME_BEFORE_REL.search(text[max(0, m.start() - 60):m.start()])
            if bm:
                a = idx_at(max(0, m.start() - 60) + bm.start(1))
                if a is not None:
                    r = T.take_name(a, "lat", 4, any_case=True)
                    if r and T.t[r[1]].e <= m.start():
                        add(r[0], r[1], "patient", 0.85, "before_relation")
        if g == "C" and co_is_complaint(text, m.end()):
            continue
        if g == "H":
            # "H/O" is "history of" in clinical text; only a known name makes it a relation.
            j = idx_at(m.end())
            if j is None or not is_given(toks[j].text):
                continue
        j = idx_at(m.end())
        if j is None:
            continue
        r = T.take_name(j, any_case=True)
        if r:
            add(r[0], r[1], "relative", 0.95, "relation")
    for m in _DEVA_REL.finditer(text):
        j = idx_at(m.end())
        if j is not None and toks[j].kind == "deva":
            r = T.take_name(j, "deva", 3)
            if r:
                add(r[0], r[1], "relative", 0.9, "relation_deva")
    # 3. honorifics after a name, Hinglish and Hindi postpositions, titles before a name
    for i, tk in enumerate(toks):
        low = _bare(tk.text).lower()
        if tk.kind == "lat" and low in HONORIFIC_POST:
            r = T.take_name_back(i, "lat", gazetteer_any_case=True)
            if r:
                add(r[0], r[1], "mention", 0.85, "honorific")
        elif tk.kind == "deva" and tk.text in HONORIFIC_POST_DEVA:
            r = T.take_name_back(i, "deva")
            if r:
                add(r[0], r[1], "mention", 0.8, "honorific_deva")
        elif tk.kind == "lat" and tk.text in HINDI_POSTPOSITIONS:
            r = T.take_name_back(i, "lat", 2, gazetteer_any_case=True)
            if r and (i + 2 < len(toks)) and not _role_before_postposition(T, r, i):
                add(r[0], r[1], "mention", 0.75, "postposition")
        elif tk.kind == "deva" and tk.text in DEVA_POSTPOSITIONS:
            r = T.take_name_back(i, "deva", 3)
            if r:
                s0 = toks[r[0]].s
                before = text[max(0, s0 - 3):s0]
                at_start = s0 == 0 or before.strip() == "" or before.strip()[-1:] in ("।", ".", "\n")
                if at_start or all(is_given(toks[x].text) or is_surname(toks[x].text) for x in range(r[0], r[1] + 1, 2)):
                    add(r[0], r[1], "mention", 0.75, "postposition_deva")
        elif tk.kind == "lat" and low in HONORIFIC_PRE:
            j = T.next_word(i)
            if j is not None:
                r = T.take_name(j, "lat", 3)
                if r:
                    add(r[0], r[1], "mention", 0.85, "title")
        elif tk.kind == "deva" and tk.text in HONORIFIC_PRE_DEVA:
            j = T.next_word(i)
            if j is not None and toks[j].kind == "deva":
                r = T.take_name(j, "deva", 3)
                if r:
                    add(r[0], r[1], "mention", 0.85, "title_deva")
    # 4. chat sender
    for m in _CHAT.finditer(text):
        j = idx_at(m.start(1))
        if j is not None:
            r = T.take_name(j, None, 3, any_case=True)
            if r:
                add(r[0], r[1], "other", 0.85, "chat_sender")
    # 4b. a possessive before a relation noun: "Agnes's attendant", "Rohit's wife"
    for m in _POSSESSIVE_REL.finditer(text):
        words = m.group(1).split()
        while words and not is_lat_name_tok(words[0]):
            words.pop(0)      # "Sample received from" is not part of the name
        if not words or not all(is_lat_name_tok(w) for w in words):
            continue
        s = m.end(1) - len(" ".join(words))
        if overlaps_protected(prot, s, m.end(1), kinds=("doctor", "org", "eponym", "asha")):
            continue
        cands.append(Span(s, m.end(1), "NAME", role="mention", conf=0.8, value=text[s:m.end(1)],
                          rule="possessive_relation"))
    # 5. a capitalised name right before a phone number
    for ps in phone_spans:
        window_start = max(0, ps.start - 60)
        seg = text[window_start:ps.start]
        for m in re.finditer(r"((?:[A-Z][a-z]+|[A-Z]{2,})(?: (?:[A-Z][a-z]+|[A-Z]{2,})){1,2})", seg):
            gap = seg[m.end():]
            if not _ADJ_GAP.match(gap):
                continue
            a = idx_at(window_start + m.start(1))
            if a is None:
                continue
            r = T.take_name(a, "lat", 3)
            if r and (r[1] - r[0]) >= 2:
                add(r[0], r[1], "other", 0.85, "phone_adjacent")
    # 6. gazetteer given + surname pairs anywhere, and "<Name> Devi/Bano/Kaur"
    for i, tk in enumerate(toks):
        if tk.kind == "lat" and is_lat_name_tok(tk.text):
            j = T.next_word(i)
            nxt = toks[j] if j == i + 2 else None
            if nxt is not None and nxt.kind == "lat" and _bare(nxt.text).lower() in _GENERIC_SUFFIX:
                add(i, j, "mention", 0.75, "name_suffix")
                continue
        if tk.kind == "lat" and is_lat_name_tok(tk.text) and is_given(_bare(tk.text)):
            j = T.next_word(i)
            if j == i + 2 and toks[j].kind == "lat" and is_lat_name_tok(toks[j].text) and is_surname(_bare(toks[j].text)):
                r = T.take_name(i, "lat", 3)
                if r:
                    add(r[0], r[1], "mention", 0.7, "gazetteer")
        elif tk.kind == "deva" and is_deva_name_tok(tk.text) and is_given(tk.text):
            j = T.next_word(i)
            if j == i + 2 and toks[j].kind == "deva" and is_surname(toks[j].text):
                add(i, j, "mention", 0.7, "gazetteer_deva")
    return cands


# --------------------------------------------------------------------------- addresses
_TW = r"(?:[A-Z][a-zA-Z]+|[A-Z]{2,})"
HOUSE = re.compile(r"\b(?:H\.?\s?No\.?|House\s?No\.?|House|Makan\s?No\.?|Makan|Plot\s?No\.?|Flat\s?No\.?|Door\s?No\.?|"
                   r"Qtr\.?\s?No\.?|Ghar\s?No\.?|Mkn\.?\s?No\.?)\s*[:\-]?\s*\d{1,5}[A-Za-z]?(?:\s?/\s?\d{1,4})?\b", re.I)
HOUSE_DEVA = re.compile(r"मकान\s*(?:नं\.?|नंबर|संख्या|न\.)\s*\d{1,5}")
MOHALLA = re.compile(r"\b(?:Mohalla|Mohalle|Mohala|Mohallah|Muhalla|Mohl\.?)\s+" + _TW + r"(?:\s+" + _TW + r"){0,2}")
MOHALLA_DEVA = re.compile(r"मोहल्ला\s+[^,।\n\d]{2,30}?(?=,|।|\n|$)")
LOCALITY_SUFFIX = re.compile(r"\b" + _TW + r"(?:\s+" + _TW + r")?\s+(?:Colony|Basti|Tola|Mohalla|Purwa|Patti|Bazar|Bazaar|Chowk|Gali|Nagar)\b")
WARD_ADDR = re.compile(r"\bWard\s*(?:No\.?\s*)?\d{1,3}\b(?!\s*\()", re.I)
WARD_DEVA = re.compile(r"वार्ड\s*(?:नं\.?|संख्या)?\s*\d{1,3}")
LANDMARK = re.compile(r"\b(?:near|nr\.?|opp\.?|opposite|behind|beside|next\s+to|in\s+front\s+of|close\s+to)\s+"
                      r"(?:[A-Za-z]+\.?)(?:\s+[A-Za-z]+){0,3}?(?=\s*(?:,|;|\n|$|-\s|\.\s))", re.I)
LANDMARK_NOUN = re.compile(r"(?i)\b(?:mandir|masjid|gurudwara|church|school|vidyalaya|tanki|bhawan|bhavan|chowk|bazar|"
                           r"market|thana|post office|petrol pump|park|station|temple|mosque|talab|pokhar|kuan|tower|"
                           r"dharamshala|panchayat|kotwali|chauraha|pul|bridge|godown|mill)\b")
LANDMARK_DEVA = re.compile(r"(?:(?<=,)|(?<=^)|(?<=\s))[^,।\n:]{2,30}?\s+के\s+(?:पास|पीछे|सामने|निकट|बगल\s+में)")
VILLAGE = re.compile(r"\b(?:Vill\.?|Village|Gram|Gaon|Grm\.?|Vil\.?|Gaanv|P\.O\.|Mauza|Mauja|Mouza|Majra|Kasba|Qasba|Hamlet)"
                     r"\s*[:\-]?\s*(" + _TW + r"(?:\s+" + _TW + r"){0,2})")
VILLAGE_DEVA = re.compile(r"(?:ग्राम|गांव|गाँव|ग्रा\.|ग्राम\s*पंचायत|मौजा|मौज़ा|मजरा|कस्बा|क़स्बा)\s*[:\-]?\s*((?:[\u0900-\u097F]+)(?:\s+[\u0900-\u097F]+){0,2}?)(?=\s*(?:,|।|\n|$|\s{2}|\s+(?:तहसील|जिला|जनपद|ब्लॉक|आयु|पोस्ट)))")
TEHSIL = re.compile(r"\b(?:Tehsil|Teh\.?|Tahsil|Taluka|Taluk|Block|Mandal|Pargana|Vikas\s?Khand)\s*[:\-]?\s*("
                    + _TW + r"(?:\s+" + _TW + r")?)")
TEHSIL_DEVA = re.compile(r"(?:तहसील|ब्लॉक|विकास\s*खंड|विकासखंड|परगना|तालुका)\s*[:\-]?\s*([\u0900-\u097F]+)")
PIN_LABEL = re.compile(r"(?i)\b(?:PIN|Pin\s?Code|Pincode|Postal\s?Code|Zip)\s*[:\-]?\s*(\d{6})\b|पिन\s*(?:कोड)?\s*[:\-]?\s*(\d{6})")
PIN_TAIL = re.compile(r"(?:Distt\.?|District|Dist\.?|Janpad|जिला|ज़िला|जनपद)\s+[^\n,;]{2,30}?\s*[-\u2013,]\s*(\d{6})(?!\d)")
PIN_BARE = re.compile(r"(?<![\d\-/.])[1-8]\d{5}(?![\d\-/.])")
ADDR_LINE = re.compile(r"(?im)^.*\b(?:address|addr|residence|resident of|r/o)\b.*$|^.*(?:पता|निवासी).*$")
ADDR_MARKERS = re.compile(r"(?i)\b(?:H\.?\s?No|House|Makan|Mohalla|Tehsil|Block|Distt|Janpad|Vill\.?|Gram|Mauza|near|opp\.)\b|"
                          r"मकान|मोहल्ला|तहसील|ब्लॉक|जिला|जनपद|ग्राम|मौजा")


def address_ranges(text: str, whole: bool) -> list[tuple[int, int]]:
    if whole:
        return [(0, len(text))]
    out = []
    for m in ADDR_LINE.finditer(text):
        out.append((m.start(), m.end()))
    for line in re.finditer(r"[^\n]+", text):
        if len(ADDR_MARKERS.findall(line.group(0))) >= 2:
            out.append((line.start(), line.end()))
    return out


def _in(ranges, s, e) -> bool:
    return any(a <= s and e <= b for a, b in ranges)


def find_address(text: str, prot: list, whole: bool = False) -> list[Span]:
    spans: list[Span] = []
    ranges = address_ranges(text, whole)

    def add(s, e, t, rule, val=None):
        if e > s:
            spans.append(Span(s, e, t, value=val if val is not None else text[s:e], rule=rule))

    for rx in (HOUSE, HOUSE_DEVA):
        for m in rx.finditer(text):
            if rx is HOUSE and not (_in(ranges, m.start(), m.end()) or re.match(r"(?i)(h\.?\s?no|makan|house\s?no)", m.group(0))):
                continue
            add(m.start(), m.end(), "HOUSE", "house")
    for rx in (MOHALLA, MOHALLA_DEVA):
        for m in rx.finditer(text):
            add(m.start(), m.end(), "LOCALITY", "mohalla")
    for m in LOCALITY_SUFFIX.finditer(text):
        if _in(ranges, m.start(), m.end()):
            add(m.start(), m.end(), "LOCALITY", "locality")
    for rx in (WARD_ADDR, WARD_DEVA):
        for m in rx.finditer(text):
            if _in(ranges, m.start(), m.end()) and not in_protected(prot, m.start(), m.end()):
                add(m.start(), m.end(), "LOCALITY", "ward_addr")
    for m in LANDMARK.finditer(text):
        if _in(ranges, m.start(), m.end()) or LANDMARK_NOUN.search(m.group(0)):
            add(m.start(), m.end(), "LANDMARK", "landmark")
    for m in LANDMARK_DEVA.finditer(text):
        s = m.start()
        while s < m.end() and text[s] in " ,":
            s += 1
        add(s, m.end(), "LANDMARK", "landmark_deva")
    for rx in (VILLAGE, VILLAGE_DEVA):
        for m in rx.finditer(text):
            if rx is VILLAGE and m.group(0).lower().startswith(("post", "p.o")) and not _in(ranges, m.start(), m.end()):
                continue
            add(m.start(1), m.end(1), "VILLAGE", "village")
    for rx in (TEHSIL, TEHSIL_DEVA):
        for m in rx.finditer(text):
            add(m.start(1), m.end(1), "TEHSIL", "tehsil")
    for m in PIN_LABEL.finditer(text):
        g = 1 if m.group(1) else 2
        add(m.start(g), m.end(g), "PIN", "pin_label")
    for m in PIN_TAIL.finditer(text):
        add(m.start(1), m.end(1), "PIN", "pin_tail")
    for m in PIN_BARE.finditer(text):
        if _in(ranges, m.start(), m.end()) and not in_protected(prot, m.start(), m.end()):
            add(m.start(), m.end(), "PIN", "pin_addr")
    return spans
