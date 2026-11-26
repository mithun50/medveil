"""Adversarial tweaks the official scorer undoes before matching, and hostile inputs.

The scorer normalizes output (NFKC, homoglyphs, zero-width, Indic digits, Latin
diacritics, casefold) and decodes base64, hex, \\uXXXX, HTML entities and %-encoding,
so a tweaked identifier we fail to remove still counts as a leak. Every case below
was a miss before the hardening in this change. Sentences are written by us.
"""
import base64
import json
import time

import pytest

from medveil.detect.engine import Knowledge, detect_slot
from medveil.ingest import sniff_and_parse
from medveil.model import Doc, Quarantine, Slot
from medveil.policy import DEFAULTS
from medveil.textnorm import fold, normalize

K = Knowledge()
K.finalize()


def found(text, etype=None):
    sl = Slot(path=(), text=normalize(text), ftype="TEXT", kind="value")
    detect_slot(sl, K, Doc(rel="x.txt", sha256="0"))
    return [(s.etype, sl.text[s.start:s.end]) for s in sl.spans if etype is None or s.etype == etype]


@pytest.mark.parametrize("text", [
    "Patient Name: R\u00f3hit M\u00e9hra",                 # Latin diacritics
    "name: rohit mehra",                                     # all lowercase after a label
    "Patient Name: rOhIt mEhRa",                             # alternating case
    "rohit ji ka BP 140/90",                                 # lowercase before an honorific
    "Patient Name: R\u043ehit Mehra",                        # Cyrillic homoglyph
    "Patient Name: Ro\u200bhit Me\u2060hra",                 # zero-width characters
    "Patient Name: Ro\u202ehit Mehra",                       # bidi override
])
def test_tweaked_names_are_found(text):
    assert found(text, "NAME") or found(text, "ENCODED")


@pytest.mark.parametrize("text", [
    "Mobile: 98765\u201343210", "Mob +91\u201498765\u201443210", "Mob 9 8 7 6 5 4 3 2 1 0",
    "Mob 98765\u00a043210", "Mobile: \u0669\u0668\u0667\u0666\u0665\u0664\u0663\u0662\u0661\u0660",
    "Mobile: \uff19\uff18\uff17\uff16\uff15\uff14\uff13\uff12\uff11\uff10",
])
def test_tweaked_phones_are_found(text):
    assert found(text, "PHONE")


@pytest.mark.parametrize("text", ["Aadhaar 3 9 7 2 0 5 8 3 9 6 2 8", "Aadhaar 3972\u20130583\u20139628"])
def test_tweaked_aadhaar_is_found(text):
    assert found(text, "AADHAAR")


def test_encoded_payloads_are_removed():
    line = "Patient Name: Rohit Mehra, Mobile 9876543210"
    for payload in (base64.b64encode(line.encode()).decode(), line.encode().hex(),
                    base64.b64encode(base64.b64encode(b"Name: Rohit Mehra")).decode()):
        assert found("Attachment: " + payload, "ENCODED"), payload
    assert found("ref Name%3A%20Rohit%20Mehra%20mob%209876543210", "PHONE")


def test_dash_variants_in_dates():
    assert found("DOB: 12\u201304\u20131977", "DOB")


def test_care_of_with_odd_casing_is_a_person():
    out = found("Address (attendant): C/O rAmEsH yAdAv, Ward 8")
    assert ("LOCALITY", "Ward 8") in out
    assert any(t == "NAME" for t, _ in out)


def test_fold_keeps_devanagari_marks():
    assert fold("मोहम्मद") == "मोहम्मद"
    assert fold("R\u00f3hit") == "Rohit"


@pytest.mark.parametrize("raw,reason", [
    (b'{"a": NaN}', "malformed_json"), (b'{"a": 1e400}', "malformed_json"), (b'{"a": Infinity}', "malformed_json"),
    (b"\x7fELF\x02\x01\x01" + b"\x00" * 50, "unsupported_binary"), (b"MZ\x90\x00" + b"\x00" * 50, "unsupported_binary"),
    (b"PK\x03\x04" + b"\x00" * 50, "unsupported_binary"), (b"\x1f\x8b\x08" + b"\x00" * 50, "unsupported_binary"),
    (b"<?xml version='1.0'?><!DOCTYPE x [<!ENTITY a 'b'>]><x>&a;</x>", "unsupported_markup"),
    (b"[" * 5000 + b"]" * 5000, "too_deep"),
])
def test_hostile_files_are_quarantined(raw, reason):
    doc = Doc(rel="hostile/f.json", sha256="0")
    with pytest.raises(Quarantine) as q:
        sniff_and_parse(doc, raw, DEFAULTS)
    assert q.value.reason == reason


@pytest.mark.parametrize("text", ["A" * 300_000, "Dr. " * 80_000, "C/O " * 80_000, "1-" * 150_000,
                                  "QUFB" * 80_000, "Name: " * 50_000, "(" * 300_000])
def test_pathological_text_is_fast(text):
    sl = Slot(path=(), text=normalize(text), ftype="TEXT", kind="text")
    t0 = time.perf_counter()
    detect_slot(sl, K, Doc(rel="x.txt", sha256="0"))
    assert time.perf_counter() - t0 < 6.0


def test_json_output_never_contains_nan():
    doc = Doc(rel="a.json", sha256="0")
    sniff_and_parse(doc, b'{"value": 1.5, "n": 12}', DEFAULTS)
    assert json.dumps(doc.data) == '{"value": 1.5, "n": 12}'
