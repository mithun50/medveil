"""Pattern detectors: protected clinical spans, identifiers, phones, ages.

The protect layer runs first. It marks spans that must survive exactly (doctors,
doses, frequencies, vitals, labs, ICD codes, eponyms, K/C/O, H/O, C/O complaints,
hospital wards, ASHA workers). Name detectors may not redact inside them.
"""
from __future__ import annotations

import re

from ..lexicon import COMPLAINT_WORDS, DRUGS, is_name_token
from ..model import Span

# --------------------------------------------------------------------------- protect
_DRUG_ALT = "|".join(sorted((re.escape(d) for d in DRUGS if len(d) > 2), key=len, reverse=True))
PROTECT_RX: list[tuple[str, re.Pattern]] = [
    ("doctor", re.compile(r"\b(?:Dr|DR|Dr\.|Doctor)\.?\s+(?:[A-Z][a-zA-Z'\-]+\.?\s?){1,4}(?:\([^)\n]{1,60}\))?")),
    ("doctor", re.compile(r"(?:डॉ\.?|डा\.|डॉक्टर)\s*(?:[\u0900-\u097F]+\s?){1,3}")),
    ("eponym", re.compile(r"\b[A-Za-z]+'s\s+(?:disease|palsy|syndrome|sign|phenomenon|anaemia|anemia|ulcer|"
                          r"fracture|test|tumou?r|lymphoma|sarcoma|chorea|encephalopathy|thyroiditis|"
                          r"contracture|cyst|reaction|law|triad)\b", re.I)),
    ("eponym", re.compile(r"\b(?:Parkinson|Alzheimer|Addison|Cushing|Crohn|Wilson|Bell|Graves|Hodgkin|Down|"
                          r"Hashimoto|Huntington|Guillain|Barre|Kawasaki|Raynaud|Sjogren|Marfan|Meniere|Tourette|"
                          r"Paget|Pott|Whipple|Wernicke|Korsakoff|Kaposi|Hirschsprung|Duchenne|Turner|Klinefelter|"
                          r"Fanconi|Gilbert|Behcet|Buerger|Dupuytren)(?:'s)?\b", re.I)),
    ("history", re.compile(r"\b(?:K/C/O|K\.C\.O\.?|KCO|H/O|h/o|k/c/o|C/O\s+H/O)\b[^.;\n()]{0,80}", re.I)),
    ("ward", re.compile(r"\bWard\s*(?:No\.?\s*)?\d{1,3}\s*\([A-Za-z &]{3,30}\)(?:\s*[,/]\s*Bed\s*(?:No\.?\s*)?\d{1,3})?", re.I)),
    ("ward", re.compile(r"\bWard\s*/\s*Bed\s*:[^\n]*", re.I)),
    ("ward", re.compile(r"\bWard\s*:\s*\d{1,3}\s*\([A-Za-z &]{3,30}\)", re.I)),
    ("ward", re.compile(r"\b(?:Bed|bed)\s*(?:No\.?\s*)?\d{1,3}\b")),
    ("asha", re.compile(r"\bASHA\s+(?:workers?|worker|didi|sahyogini|facilitator)\b|\bASHA\b(?=\s+(?:worker|workers))")),
    ("dose", re.compile(r"\b\d+(?:\.\d+)?\s*(?:mg|mcg|µg|ug|g|gm|gms|ml|mL|IU|iu|units?|U|%|mmol/L|mg/dL|g/dL|/uL|"
                        r"/µL|/cumm|mIU/L|µIU/mL|ng/mL|pg/mL|mEq/L|cells|lakh|puffs?|drops?|tabs?|sachets?|kg|cm|"
                        r"mmHg|bpm|/min|F|°F|°C|C)\b(?:\s*\+\s*\d+(?:\.\d+)?\s*(?:mg|mcg|g|ml))?")),
    ("dose", re.compile(r"\b\d+/\d+\s*(?:mg|mcg)\b")),
    ("freq", re.compile(r"(?<![\d\-])[0-4](?:\s?-\s?[0-4]){2,3}(?![\d\-])")),
    ("freq", re.compile(r"\b(?:BD|TDS|OD|HS|SOS|QID|TID|BID|STAT|PRN|QHS|AC|PC|BBF|OW)\b")),
    ("freq", re.compile(r"\bx\s*\d+\s*(?:days?|d|wks?|weeks?|months?|mths?|yrs?|years?|hrs?|hours?)\b", re.I)),
    ("vital", re.compile(r"\b(?:BP|B\.P\.)\s*[:\-]?\s*\d{2,3}\s*/\s*\d{2,3}(?:\s*mmHg)?", re.I)),
    ("vital", re.compile(r"\b(?:Pulse|PR|HR|RR|SpO2|SPO2|Temp|Temperature|RBS|FBS|PPBS|Hb|GRBS|Wt|Weight)\b\s*[:\-]?\s*\d+(?:\.\d+)?", re.I)),
    ("icd", re.compile(r"\b[A-TV-Z]\d{2}(?:\.\d{1,3})?\b")),
    ("loinc", re.compile(r"\b\d{3,5}-\d\b")),
    ("org", re.compile(r"\b(?:[A-Z][A-Za-z]+\s){1,4}(?:Hospital|HOSPITAL|Pathology|PATHOLOGY|Diagnostics|DIAGNOSTICS|"
                       r"Clinic|CLINIC|Sadan|SADAN|Nursing Home|Medical College|Labs?|Laboratory|Centre|Center|"
                       r"Charitable|CHARITABLE|Multispeciality|MULTISPECIALITY)\b")),
    ("org", re.compile(r"\b[A-Z]{3,}(?:\s+[A-Z]{3,}){1,4}\s+(?:HOSPITAL|SADAN|CLINIC|PATHOLOGY|DIAGNOSTICS)\b")),
]
# Cheap prefilters: a pattern only runs when its trigger is present in the text.
_TRIGGER = {
    "doctor": lambda t, lo, dg, up: "dr" in lo or "doctor" in lo or "डॉ" in t or "डा." in t,
    "history": lambda t, lo, dg, up: "/o" in lo or "kco" in lo or "k.c.o" in lo,
    "ward": lambda t, lo, dg, up: "ward" in lo or "bed" in lo,
    "asha": lambda t, lo, dg, up: "ASHA" in t,
    "dose": lambda t, lo, dg, up: dg,
    "freq": lambda t, lo, dg, up: dg or up,
    "vital": lambda t, lo, dg, up: dg,
    "icd": lambda t, lo, dg, up: dg and up,
    "loinc": lambda t, lo, dg, up: dg and "-" in t,
    "org": lambda t, lo, dg, up: up and any(w in lo for w in ("hospital", "patholog", "diagnost", "clinic", "sadan",
                                                              "nursing", "college", "lab", "centre", "center",
                                                              "charitable", "multispecial")),
    "eponym": lambda t, lo, dg, up: up or "'s" in lo,
}
_HAS_DIGIT = re.compile(r"\d")
_HAS_UPPER = re.compile(r"[A-Z]")
_DRUG_WORDS = frozenset(d for d in DRUGS if len(d) > 2)
_WORD_NUM = re.compile(r"([A-Za-z][A-Za-z\-]+)(\s+\d{2,4}(?![\d\-/]))?")

_CO = re.compile(r"\bC\s?/\s?O\b\.?\s*[:\-]?\s*", re.I)
_WORD = re.compile(r"[A-Za-z][A-Za-z'\-]*|[\u0900-\u097F]+")


def co_is_complaint(text: str, pos: int) -> bool:
    """True if the words after a C/O at `pos` describe a complaint, not a person."""
    m = _WORD.search(text, pos, min(len(text), pos + 60))
    if not m:
        return True  # "C/O:" followed by nothing useful
    w = m.group(0)
    lw = w.lower()
    if lw in COMPLAINT_WORDS or lw in ("no", "known", "h", "k", "pain", "fever"):
        return True
    if re.match(r"[\u0900-\u097F]", w):
        from ..lexicon import HINDI_COMMON
        return w in HINDI_COMMON
    # "C/O rAmEsH": odd casing or a known name after C/O is a person, not a complaint
    if any(c.isupper() for c in w[1:]) or is_name_token(w):
        return False
    return w[0].islower()


def protected_spans(text: str) -> list[tuple[int, int, str]]:
    out = []
    lo = text.lower()
    dg = _HAS_DIGIT.search(text) is not None
    up = _HAS_UPPER.search(text) is not None
    for kind, rx in PROTECT_RX:
        trig = _TRIGGER.get(kind)
        if trig is not None and not trig(text, lo, dg, up):
            continue
        for m in rx.finditer(text):
            if m.end() > m.start():
                out.append((m.start(), m.end(), kind))
    for m in _WORD_NUM.finditer(text):
        if m.group(1).lower() in _DRUG_WORDS:
            out.append((m.start(), m.end(), "drugdose"))
    if "/" not in lo:
        return out
    for m in _CO.finditer(text):
        before = text[max(0, m.start() - 2):m.start()]
        if "/" in before or before.endswith("K") or before.endswith("H"):
            continue
        if co_is_complaint(text, m.end()):
            end = len(text)
            for stop in (";", "\n", ". "):
                k = text.find(stop, m.end())
                if k != -1:
                    end = min(end, k)
            out.append((m.start(), min(end, m.end() + 80), "complaint"))
    return out


def in_protected(prot, s: int, e: int) -> bool:
    return any(ps <= s and e <= pe for ps, pe, _ in prot)


def overlaps_protected(prot, s: int, e: int, kinds=None) -> bool:
    return any(ps < e and s < pe and (kinds is None or k in kinds) for ps, pe, k in prot)


# --------------------------------------------------------------------------- identifiers
EMAIL = re.compile(r"(?<![\w.+\-])[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+")
ABHA_ADDR = re.compile(r"(?<![\w.])[A-Za-z0-9._]{3,}@(?:abdm|sbx|ndhm|abha)\b", re.I)
ABHA = re.compile(r"(?<![\w\-/+])(?:\d{2}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}|\d(?:[ .\-]\d){13})(?![\w\-/])")
AADHAAR = re.compile(r"(?<![\w\-/+])(?:\d{4}[\s\-]?\d{4}[\s\-]?\d{4}|\d(?:[ .\-]\d){11})(?![\w\-/])")
AADHAAR_MASKED = re.compile(r"(?<![\w])(?:[Xx*•]{4}[\s\-]?[Xx*•]{4}[\s\-]?\d{4}|[Xx*]{8}\d{4})(?![\w])")
PAN = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]{3}[PCHFATBLJGpchfatbljg][A-Za-z]\d{4}[A-Za-z](?![A-Za-z0-9])")
INSURANCE = re.compile(r"(?<![A-Za-z0-9])(?:PMJAY|PM-JAY|ABPMJAY|AB-PMJAY)[\s\-/]?[A-Z]{0,3}[\s\-/]?\d{6,14}(?![A-Za-z0-9])"
                       r"|(?<![A-Za-z0-9])POL[\s/\-]\d{1,4}[\s/\-]\d{5,12}(?![A-Za-z0-9])", re.I)
PHONE = re.compile(r"(?<![\w/.\-])(?:\(?(?:\+|00)?91\)?[\s\-.]*)?0?[6-9](?:[\s\-.]?\d){9}(?![\w])")
LANDLINE = re.compile(r"(?<![\w/.\-])0\d{2,4}[\s\-]\d{6,8}(?![\w])")
ID_LABEL = re.compile(
    r"(?i)\b(UHID|MRN|MR\.?\s?No|MRD\s?No|Reg(?:istration|d)?\.?\s?No|Reg(?:istration)?\s?Number|IPD\s?No|IP\s?No|"
    r"CR\s?No|Hospital\s?No|Patient\s?ID|Pt\.?\s?ID|Adm(?:ission)?\.?\s?No|BHT\s?No|Case\s?No|OPD\s?Reg\.?\s?No)\.?"
    r"\s*[:#\-]?\s*([A-Za-z0-9][A-Za-z0-9/\-_.]{2,30}[A-Za-z0-9])")
ID_LABEL_DEVA = re.compile(r"(पंजीकरण\s*सं\.?|पंजीकरण\s*संख्या|पंजीकरण\s*क्रमांक|आईपीडी\s*सं\.?|यूएचआईडी|भर्ती\s*(?:सं\.?|संख्या|क्रमांक|नं\.?)|"
                           r"रजिस्ट्रेशन\s*(?:सं\.?|नं\.?|नंबर)|मरीज़?\s*(?:सं\.?|संख्या|क्रमांक|आईडी)|रोगी\s*(?:सं\.?|संख्या|क्रमांक))"
                           r"\s*[:]?\s*([A-Za-z0-9][A-Za-z0-9/\-_.]{2,30}[A-Za-z0-9])")
# Any other "<label> No./Number/ID/क्रमांक: <alphanumeric with digits>" is treated as an identifier.
GENERIC_ID_LABEL = re.compile(r"(?i)\b(?:[A-Za-z]{2,12}\.?\s){0,2}(?:No|Number|ID|Code|#)\.?\s*[:#\-]\s*([A-Za-z]{0,6}[/\-_.]?\d[A-Za-z0-9/\-_.]{3,28}[A-Za-z0-9])"
                              r"|(?:[\u0900-\u097F]+\s){0,2}(?:क्रमांक|संख्या|सं\.|नंबर|आईडी)\s*[:]\s*([A-Za-z0-9][A-Za-z0-9/\-_.]{3,30})")
_GENERIC_ID_SKIP = re.compile(r"(?i)\b(?:bill|invoice|receipt|sample|visit|order|test|lab|report|trip|ticket|package|"
                              r"batch|lot|ward|bed|room|version|icd|loinc|phone|mobile|contact|mob|ph|tel|aadhaar|aadhar|"
                              r"pan|abha|pin|zip|policy|claim|serial|sr|s|page)\b[^:\n]{0,14}$")
INS_LABEL = re.compile(r"(?i)\b(?:Policy\s?No|PMJAY\s?ID|Card\s?No|Member\s?ID|Insurance\s?ID|Ayushman\s?(?:Card|ID))\.?\s*[:#\-]?\s*([A-Za-z0-9][A-Za-z0-9/\-]{4,30})")
GENERIC_ID = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]{2,6}[/\-]?\d{2,4}[/\-]\d{4,8}(?![A-Za-z0-9])|(?<![A-Za-z0-9])[A-Za-z]{2,5}\d{6,9}(?![A-Za-z0-9])")


def digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def id_key(s: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", s.upper())


def phone10(s: str) -> str | None:
    d = digits(s)
    if len(d) == 12 and d.startswith("91"):
        d = d[2:]
    elif len(d) == 13 and d.startswith("091"):
        d = d[3:]
    elif len(d) == 14 and d.startswith("0091"):
        d = d[4:]
    elif len(d) == 11 and d.startswith("0"):
        d = d[1:]
    if len(d) == 10 and d[0] in "6789":
        return d
    return None


_UNIT_AFTER = re.compile(r"^\s*(?:mg|mcg|ml|g|gm|/uL|/cumm|cells|mmol|IU|units|%|kg|rs|inr|₹)\b", re.I)


def find_ids(text: str, shapes=None) -> list[Span]:
    spans: list[Span] = []

    def add(s, e, t, v, rule):
        spans.append(Span(s, e, t, value=v, rule=rule))

    for m in EMAIL.finditer(text):
        add(m.start(), m.end(), "EMAIL", m.group(0).lower(), "email")
    for m in ABHA_ADDR.finditer(text):
        add(m.start(), m.end(), "ABHA_ADDR", m.group(0).lower(), "abha_addr")
    for m in INSURANCE.finditer(text):
        add(m.start(), m.end(), "INSURANCE", id_key(m.group(0)), "insurance")
    for m in INS_LABEL.finditer(text):
        v = m.group(1)
        if sum(c.isdigit() for c in v) >= 4:
            add(m.start(1), m.end(1), "INSURANCE", id_key(v), "ins_label")
    for m in ABHA.finditer(text):
        d = digits(m.group(0))
        if len(d) == 14:
            add(m.start(), m.end(), "ABHA", d, "abha")
    for m in AADHAAR.finditer(text):
        if _UNIT_AFTER.match(text[m.end():m.end() + 8]):
            continue
        d = digits(m.group(0))
        # "919334843599" right after a phone cue is a +91 mobile, not an Aadhaar
        if d.startswith("91") and d[2] in "6789" and re.search(r"(?i)(?:mob(?:ile)?|phone|ph|contact|call|tel|cell|whatsapp|मोबाइल|फ़ोन)(?:\s*(?:no|number|#))?\.?\W{0,12}$",
                                                              text[max(0, m.start() - 20):m.start()]):
            continue
        add(m.start(), m.end(), "AADHAAR", d, "aadhaar")
    for m in AADHAAR_MASKED.finditer(text):
        add(m.start(), m.end(), "AADHAAR_MASKED", digits(m.group(0))[-4:], "aadhaar_masked")
    for m in PAN.finditer(text):
        add(m.start(), m.end(), "PAN", m.group(0).upper(), "pan")
    for m in PHONE.finditer(text):
        p = phone10(m.group(0))
        if p and not _UNIT_AFTER.match(text[m.end():m.end() + 8]):
            add(m.start(), m.end(), "PHONE", p, "phone")
    for m in LANDLINE.finditer(text):
        ctx = text[max(0, m.start() - 20):m.start()].lower()
        if any(w in ctx for w in ("ph", "tel", "mob", "contact", "call", "landline")):
            add(m.start(), m.end(), "PHONE", digits(m.group(0)), "landline")
    for m in ID_LABEL.finditer(text):
        v = m.group(2)
        if sum(c.isdigit() for c in v) >= 3:
            add(m.start(2), m.end(2), "MRN", id_key(v), "id_label")
    for m in ID_LABEL_DEVA.finditer(text):
        v = m.group(2)
        if sum(c.isdigit() for c in v) >= 3:
            add(m.start(2), m.end(2), "MRN", id_key(v), "id_label_deva")
    for m in GENERIC_ID_LABEL.finditer(text):
        g = 1 if m.group(1) else 2
        v = m.group(g)
        label = text[m.start():m.start(g)]
        if _GENERIC_ID_SKIP.search(label.split(":")[0].rstrip(" #-")) or sum(c.isdigit() for c in v) < 4:
            continue
        add(m.start(g), m.end(g), "MRN", id_key(v), "generic_id_label")
    if shapes is not None:
        for rx in shapes.patterns():
            for m in rx.finditer(text):
                add(m.start(), m.end(), "MRN", id_key(m.group(0)), "shape")
        for m in GENERIC_ID.finditer(text):
            if shapes.known(id_key(m.group(0))):
                add(m.start(), m.end(), "MRN", id_key(m.group(0)), "known_id")
    return spans


# --------------------------------------------------------------------------- ages
AGE_PATTERNS = [
    re.compile(r"(?i)\b(?:Age(?:\s*/\s*Sex|\s*/\s*Gender)?|Aayu|Umar)\s*[:\-]?\s*(\d{1,3})(?![\d.])"),
    re.compile(r"(?i)(?<![\d.\-/x])(\d{1,3})\s*(?:Y|Yr|Yrs|Year|Years|y/o|yo)\.?\s*(?:/|\s)\s*(?:M|F|Male|Female|O)\b"),
    re.compile(r"(?i)(?<![\d.\-/x])(\d{1,3})\s*(?:Yrs?|Years?)\s+old\b"),
    re.compile(r"(?<![\d.\-/x:])(\d{1,3})\s*/\s*(?:M|F|Male|Female)\b"),
    re.compile(r"(?i)(?<![\d.\-/x])(\d{1,3})\s*(?:Y|Yrs?|Years?)\.?\s*,\s*(?:male|female|M|F)\b"),
    re.compile(r"(?:आयु|उम्र|उमर)\s*[:\-]?\s*(\d{1,3})(?!\d)"),
    re.compile(r"(?<![\d.\-/x])(\d{1,3})\s*(?:वर्ष|साल)\s*(?:/|,)?\s*(?:पुरुष|महिला|स्त्री)"),
]
_DURATION_BEFORE = re.compile(r"(?i)(?:\bx|for|since|from|last|past|ago|back|after|within)\s*$")
_DURATION_AFTER = re.compile(r"(?i)^\s*(?:yrs?|years?)?\s*(?:back|ago|since|duration)")


def find_ages(text: str) -> list[Span]:
    out = []
    seen = set()
    for rx in AGE_PATTERNS:
        for m in rx.finditer(text):
            s, e = m.start(1), m.end(1)
            if (s, e) in seen:
                continue
            if _DURATION_BEFORE.search(text[max(0, s - 8):s]) or _DURATION_AFTER.match(text[e:e + 14]):
                continue
            age = int(m.group(1))
            if 0 <= age <= 120:
                seen.add((s, e))
                out.append(Span(s, e, "AGE", value=age, rule="age"))
    return out


GENDER_IN_TEXT = [
    (re.compile(r"(?i)\b\d{1,3}\s*(?:Y|Yrs?|Years?)?\s*/\s*(M|F)\b"), None),
    (re.compile(r"(?i)\bSex\s*[:\-]?\s*(Male|Female|M|F)\b"), None),
    (re.compile(r"(महिला|स्त्री)"), "F"),
    (re.compile(r"(पुरुष)"), "M"),
]


def genders_in(text: str) -> set[str]:
    out = set()
    for rx, fixed in GENDER_IN_TEXT:
        for m in rx.finditer(text):
            g = fixed or m.group(1)[0].upper()
            out.add(g)
    return out
