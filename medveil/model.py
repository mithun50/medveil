"""Core data model shared by every stage."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Entity types that are personal data and must not survive.
PII_TYPES = {
    "NAME", "PHONE", "AADHAAR", "AADHAAR_MASKED", "ABHA", "ABHA_ADDR", "EMAIL", "PAN",
    "INSURANCE", "MRN", "HOUSE", "LOCALITY", "LANDMARK", "VILLAGE", "TEHSIL", "PIN", "DOB",
    "ADDRESS", "ENCODED",
}
# Spans that are transformed, not removed.
TRANSFORM_TYPES = {"DATE", "AGE", "DIAG"}


@dataclass(slots=True)
class Span:
    start: int
    end: int
    etype: str
    role: str = ""          # patient | relative | other | mention (names); id kind for IDs
    value: Any = None       # parsed value: date, age, normalized id, name text
    conf: float = 1.0
    rule: str = ""

    def overlaps(self, other: "Span") -> bool:
        return self.start < other.end and other.start < self.end


@dataclass(slots=True)
class Slot:
    """One rewritable string inside a document."""
    path: tuple            # CSV: (row, col); JSON: key path; text: ()
    text: str              # normalized text that we rewrite
    ftype: str | None = None   # semantic type of the field, if structured
    key: str = ""          # header or key name
    kind: str = "value"    # value | header | key | filename | text
    number: bool = False   # original JSON value was a number
    b64: bool = False      # slot text was base64-decoded from the original value
    orig: Any = None       # original value, written back unchanged when nothing is found
    spans: list[Span] = field(default_factory=list)
    protected: list[tuple[int, int]] = field(default_factory=list)
    out: Any = None        # rewritten value


@dataclass(slots=True)
class Evidence:
    ids: set = field(default_factory=set)          # ("uhid", "SNJ26064127") ...
    phones: set = field(default_factory=set)
    names: list = field(default_factory=list)      # list of token-key tuples (patient full names)
    mentions: list = field(default_factory=list)   # weak name mentions (token-key tuples)
    relatives: list = field(default_factory=list)  # list of token-key tuples
    dobs: set = field(default_factory=set)         # date objects (all valid readings)
    ages: list = field(default_factory=list)       # (age, ref_date or None)
    genders: set = field(default_factory=set)
    villages: set = field(default_factory=set)
    districts: set = field(default_factory=set)
    aadhaar_last4: set = field(default_factory=set)


@dataclass(slots=True)
class Record:
    loc: str
    slots: list[Slot] = field(default_factory=list)
    ev: Evidence = field(default_factory=Evidence)
    cluster: int | None = None
    psn: str | None = None
    dates: list = field(default_factory=list)       # date objects seen in this record
    generalized: bool = False


@dataclass(slots=True)
class Doc:
    rel: str
    sha256: str
    fmt: str = ""            # csv | tsv | json | fhir | text
    encoding: str = ""
    delimiter: str = ""
    newline: str = "\n"
    data: Any = None         # parsed rows (CSV) or object (JSON) or text
    json_style: dict = field(default_factory=dict)
    records: list[Record] = field(default_factory=list)
    file_slots: list[Slot] = field(default_factory=list)   # filename, header, keys, metadata
    status: str = "pending"
    reason: str = ""
    out_rel: str = ""
    date_order: str = "dmy"
    date_votes: tuple = (0, 0)
    tokens: set = field(default_factory=set)
    header_hint: str = ""
    record_of_path: dict = field(default_factory=dict)


class Quarantine(Exception):
    """Raised with a reason code when a file cannot be processed safely."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason
