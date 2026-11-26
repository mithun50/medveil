"""Semantic types for CSV headers and JSON keys.

Two signals: a multilingual header lexicon and, for headers we do not recognise,
profiling of the column's values. A column type is only a prior. Every cell still
goes through the free-text detectors, so shifted columns and ragged rows are safe.
"""
from __future__ import annotations

import re
from functools import lru_cache

from ..lexicon import DEVA_HEADER, HEADER_RULES, district_of, is_name_token, is_stopword

_RULES = [(re.compile(p), t) for p, t in HEADER_RULES]
_CAMEL = re.compile(r"(?<=[a-z])(?=[A-Z])")


def norm_header(h: str) -> str:
    h = _CAMEL.sub(" ", h.strip())
    h = h.lower().replace("'s", " s").replace("#", " no ")
    h = re.sub(r"[_\-/().:,]+", " ", h)
    return " ".join(h.split())


# "<qualifier> name" is a person's name only for these qualifiers. "test_name",
# "procedure_name", "hospital_name" or "drug name" label things, not people: typing them
# NAME would redact the clinical value and, worse, make the record look like it holds two
# people, so it would never be linked. Such columns fall back to value profiling.
_PERSON_QUALIFIERS = frozenset("""
patient patients pt pts full first last given middle family sur surname beneficiary member insured
claimant customer client applicant person holder card rogi mariz mareez marij poora pura sampoorn
of the s
""".split())
_NAME_WORDS = frozenset("name names naam nam".split())


def _non_person_name(n: str) -> bool:
    words = n.split()
    if not any(w in _NAME_WORDS for w in words):
        return False
    others = [w for w in words if w not in _NAME_WORDS and w not in ("no", "ka", "ki", "ke")]
    return bool(others) and not any(w in _PERSON_QUALIFIERS for w in others)


@lru_cache(maxsize=4096)
def classify_header(h: str) -> str | None:
    raw = h.strip()
    if not raw:
        return None
    if re.search(r"[\u0900-\u097F]", raw):
        r = " ".join(raw.replace(":", " ").split())
        for k, t in sorted(DEVA_HEADER.items(), key=lambda kv: -len(kv[0])):
            if k in r:
                return t
    n = norm_header(raw)
    for rx, t in _RULES:
        if rx.search(n):
            if t == "NAME" and _non_person_name(n):
                return None
            return t
    return None


# Parent keys that change what a nested "name" or "display" means.
_PARENT_OTHER = {"facility", "hospital", "lab", "organization", "organisation", "panel", "panels", "drug",
                 "test", "department", "ward", "category", "medication", "code", "coding", "type", "class",
                 "serviceprovider", "custodian", "managingorganization", "location", "item", "product",
                 "insurer", "payer", "scheme", "package", "procedure", "diagnosis", "condition", "valuecodeableconcept"}
_PARENT_RELATIVE = {"guardian", "father", "husband", "relative", "attendant", "contact", "nok", "mother", "spouse",
                    "kin", "next_of_kin", "relatedperson", "parent", "wife", "son", "daughter", "emergency_contact"}
_PARENT_DOCTOR = {"doctor", "practitioner", "referred_by", "consultant", "physician", "prescriber", "surgeon",
                  "attending", "treating_doctor", "ref_doctor"}
# FHIR roles that point at practitioners; only meaningful inside FHIR resources.
_PARENT_DOCTOR_FHIR = {"author", "performer", "requester", "asserter", "recorder", "attester", "participant", "individual"}
_PARENT_OTHER_PERSON = {"raised_by", "informant", "caller", "witness", "reporter", "visitor", "submitted_by",
                        "created_by", "reported_by", "contact_person", "called_by", "requester", "requested_by",
                        "complainant", "applicant", "customer", "user", "member", "owner", "beneficiary"}
_DATE_KEY = re.compile(r"(date|datetime|_on$|_at$|^on$|issued|^start$|^end$|timestamp|lastupdated|authoredon|"
                       r"collected|reported|registered|recorded|admitted|discharged|^time$|period)", re.I)


def _parents(path: tuple) -> list[str]:
    return [p.lower() for p in path[:-1] if isinstance(p, str)]


def classify_key(key: str, path: tuple, ctx) -> str | None:
    k = str(key)
    kl = k.lower()
    parents = _parents(path) if path else []
    parent = parents[-1] if parents else ""
    rtypes = [x.lower() for x in ctx] if ctx else []
    rtype = rtypes[-1] if rtypes else ""
    # FHIR-specific structure
    if rtype or (path and any(p == "resource" for p in path if isinstance(p, str))):
        if kl in ("given", "family", "text", "prefix", "suffix") and "name" in parents:
            if rtype in ("practitioner", "practitionerrole"):
                return "DOCTOR"
            if rtype in ("organization", "location"):
                return None
            if "contact" in parents or rtype == "relatedperson":
                return "RELATIVE"
            return "FIRST_NAME" if kl == "given" else ("LAST_NAME" if kl == "family" else "NAME")
        if kl == "value" and "telecom" in parents:
            return "PHONE"
        if kl == "value" and "identifier" in parents:
            return "MRN"
        if kl == "display":
            if parent in ("subject", "patient", "beneficiary"):
                return "NAME"
            if parent in _PARENT_DOCTOR or parent in _PARENT_DOCTOR_FHIR:
                return "DOCTOR"
            return None
        if kl == "line" or (kl in ("text",) and parent == "address"):
            return "ADDRESS"
        if parent == "address" or "address" in parents:
            if kl == "city":
                return "VILLAGE"
            if kl == "district":
                return "DISTRICT"
            if kl == "postalcode":
                return "PIN"
            if kl in ("state", "country"):
                return None
        if kl == "birthdate":
            return "DOB"
        if kl == "div":
            return "TEXT"
        if kl == "data" and "attachment" in parents:
            return "TEXT"
        if kl in ("source",) and parent == "meta":
            return "TEXT"
        if kl == "gender":
            return "GENDER"
        if kl in ("reference", "fullurl", "id", "system", "code", "status", "url", "profile", "use",
                  "resourcetype", "unit", "contenttype", "language"):
            return None
        if _DATE_KEY.search(kl):
            return "DATE"
    # Generic JSON
    if kl in ("name", "full_name", "fullname", "local"):
        pset = set(parents)
        if pset & _PARENT_DOCTOR:
            return "DOCTOR"
        if pset & _PARENT_OTHER_PERSON:
            return "NAME"
        if parent in _PARENT_OTHER:
            return None
        if pset & _PARENT_RELATIVE:
            return "RELATIVE"
        if parent in ("name", "patient", "subject", "person", "beneficiary", "") or "patient" in pset:
            return "NAME"
        if any(p in ("visits", "patients", "records", "results", "tickets", "entries", "data", "items") for p in pset):
            return "NAME"
        return None
    if parent == "name" and kl in ("first", "given", "fname", "first_name"):
        return "FIRST_NAME"
    if parent == "name" and kl in ("last", "family", "surname", "lname", "last_name"):
        return "LAST_NAME"
    if kl in ("relation", "relationship"):
        return "RELATION"
    if kl in ("source_path", "path", "file", "filename", "file_name", "source_file", "export_path"):
        return "TEXT"
    t = classify_header(k)
    if t == "NAME" and parent in _PARENT_OTHER:
        return None
    if t is None and _DATE_KEY.search(kl):
        return "DATE"
    if t in ("NAME",) and set(parents) & _PARENT_RELATIVE:
        return "RELATIVE"
    return t


_PHONE = re.compile(r"^\s*(?:\+?91[\s\-]?|0)?[6-9]\d{2,4}[\s\-]?\d{2,4}[\s\-]?\d{2,5}\s*$")
_AADHAAR = re.compile(r"^\s*\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\s*$")
_ABHA = re.compile(r"^\s*\d{2}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\s*$")
_EMAIL = re.compile(r"^\s*[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+\s*$")
_PAN = re.compile(r"^\s*[A-Za-z]{5}\d{4}[A-Za-z]\s*$")
_NAMEISH = re.compile(r"^\s*(?:[A-Z][a-zA-Z.'\-]*|[\u0900-\u097F]+)(?:\s+(?:[A-Z][a-zA-Z.'\-]*|[\u0900-\u097F]+)){0,3}\s*$")


# Indian settlement-name morphology (Latin and Devanagari): Rampur, Mohanganj, Bhimnagar,
# Shivgarh, Rasoolabad, Durgamau, Jalalpur Khurd, Rasoolkheda, Bhawanidih, Ramgaon.
_PLACE_END = re.compile(r"(?i)\w{2}(?:pur|pura|puri|purwa|ganj|nagar|garh|gadh|abad|mau|kheda|khera|"
                        r"dih|gaon|patti|sarai|ghat|kot|bagh)$|^(?:khurd|kalan)$")
_PLACE_END_DEVA = re.compile(r"(?:पुर|पुरा|गंज|नगर|"
                             r"गढ़|गढ|आबाद|मऊ|खेड़ा|"
                             r"खेडा|खुर्द|कलां|डीह|"
                             r"गांव|गाँव|पट्टी|सराय)$")


def _place_like(v: str) -> bool:
    toks = re.findall(r"[A-Za-z]+|[\u0900-\u097F]+", v)
    if not toks or len(toks) > 4:
        return False
    # a surname such as "Kapur" or "Nagar" is a person's name, not a settlement
    return any((_PLACE_END.search(t) or _PLACE_END_DEVA.search(t)) and not is_name_token(t) for t in toks)


def profile_column(values: list[str]) -> str | None:
    vals = [v for v in (x.strip() for x in values) if v]
    if len(vals) < 2:
        return None
    n = len(vals)

    def share(rx) -> float:
        return sum(1 for v in vals if rx.match(v)) / n

    if share(_ABHA) >= 0.6:
        return "ABHA"
    if share(_AADHAAR) >= 0.6:
        return "AADHAAR"
    if sum(1 for v in vals if _PHONE.match(v) and len(re.sub(r"\D", "", v)) in (10, 11, 12)) / n >= 0.6:
        return "PHONE"
    if share(_EMAIL) >= 0.6:
        return "EMAIL"
    if share(_PAN) >= 0.6:
        return "PAN"
    nameish = [v for v in vals if _NAMEISH.match(v)]
    if len(nameish) / n >= 0.7:
        hits = 0
        for v in nameish:
            toks = v.replace(".", " ").split()
            if any(is_name_token(t) for t in toks) and not any(is_stopword(t) for t in toks):
                hits += 1
        if hits / n >= 0.5:
            return "NAME"
    # Place columns under an unknown header ("Mauza", "Basti"): known districts, or
    # settlement names by their morphology, and no digits (addresses carry house numbers).
    if not any(re.search(r"\d", v) for v in vals):
        if sum(1 for v in vals if district_of(v)) / n >= 0.6:
            return "DISTRICT"
        if sum(1 for v in vals if _place_like(v)) / n >= 0.6:
            return "VILLAGE"
    return None
