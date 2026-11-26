"""Adversarial tweaks the official scorer undoes before matching, and hostile inputs.

The scorer normalizes output (NFKC, homoglyphs, zero-width, Indic digits, Latin
diacritics, casefold) and decodes base64, hex, \\uXXXX, HTML entities and %-encoding,
so a tweaked identifier we fail to remove still counts as a leak. Every case below
was a miss before the hardening in this change. Sentences are written by us.
"""
import base64
import hashlib
import json
import os
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
    assert found(text, "NAME")


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
    # Mach-O 32-bit and 64-bit in both byte orders, universal binary in both orders. Printable
    # padding: without NUL bytes only the magic number tells these apart from cp1252 text.
    (b"\xfe\xed\xfa\xce" + b"A" * 50, "unsupported_binary"), (b"\xce\xfa\xed\xfe" + b"A" * 50, "unsupported_binary"),
    (b"\xfe\xed\xfa\xcf" + b"A" * 50, "unsupported_binary"), (b"\xbe\xba\xfe\xca" + b"A" * 50, "unsupported_binary"),
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

# ---------------------------------------------------------------- review findings, PR #3

def test_pii_cut_by_a_chunk_boundary_is_found_whole():
    # Text over 32 KB is detected in ~4 KB chunks cut at whitespace. This layout puts the cut
    # between the two halves of a space-separated phone number.
    text = "x " * 2045 + "98765 43210\n" + "x " * 15000
    assert len(text) > 32_768
    assert ("PHONE", "98765 43210") in found(text, "PHONE")


def test_pii_at_a_chunk_boundary_is_not_counted_twice():
    text = "x " * 2041 + "Patient Name: Rohit Mehra\n" + "x " * 15000
    names = found(text, "NAME")
    assert names == [("NAME", "Rohit Mehra")]


@pytest.mark.parametrize("text", [
    "Attachment: OTg3NjU0MzIxMA==",                 # base64 of a phone, 16 characters
    "ref 39383736353433323130",                     # hex of the ASCII digits 9876543210
])
def test_short_or_digit_only_encodings_are_removed(text):
    assert found(text, "ENCODED")


def test_single_percent_escape_is_decoded():
    assert ("NAME", "Rohit Mehra") in found("Patient Name: Roh%69t Mehra", "NAME")


def test_percent_decoding_is_linear():
    text = "%41%42 " + "G" * 200_000
    t0 = time.perf_counter()
    normalize(text)
    assert time.perf_counter() - t0 < 1.0


def test_plain_hex_and_numbers_are_not_payloads():
    # ordinary IDs, lab values and long words stay untouched
    for text in ("Sample ID 3130313031303130", "Hb 11.2 g/dL, TLC 7600", "hepatosplenomegaly noted"):
        assert not found(text, "ENCODED"), text


def test_lowercase_known_name_after_bare_patient_label():
    assert ("NAME", "rohit mehra") in found("Patient: rohit mehra, 45 yrs", "NAME")


@pytest.mark.parametrize("text", ["Patient: fever and cough since 3 days", "Patient: c/o pain abdomen"])
def test_complaint_after_bare_patient_label_is_kept(text):
    assert not found(text, "NAME")


def test_lowercase_names_with_hyphen_or_apostrophe():
    assert ("NAME", "anne-marie o'brien") in found("Name: anne-marie o'brien", "NAME")


@pytest.mark.parametrize("text", ["Report of sonography whole abdomen", "Report of lipid profile"])
def test_labels_without_separator_need_capitalised_names(text):
    assert not found(text, "NAME")


@pytest.mark.parametrize("text", ["C/O gala kharab since 2 days", "C/O kaan dard", "c/o kamar mein dard"])
def test_hinglish_complaints_after_care_of_are_kept(text):
    assert not found(text, "NAME")


def test_care_of_lowercase_known_name_is_still_a_person():
    assert any(t == "NAME" for t, _ in found("Address: C/O ramesh yadav, Rampur"))


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs POSIX FIFOs")
def test_fifo_at_a_regular_path_is_not_read(tmp_path):
    from medveil.cli import _read_regular
    fifo = tmp_path / "notes.txt"
    os.mkfifo(fifo)
    raw, reason, _ = _read_regular(fifo, 1 << 20)   # must return at once, not block
    assert (raw, reason) == (b"", "special_file")


def test_regular_file_read_and_size_limit(tmp_path):
    from medveil.cli import _read_regular
    f = tmp_path / "a.txt"
    f.write_bytes(b"hello world")
    assert _read_regular(f, 1 << 20)[:2] == (b"hello world", "")
    raw, reason, h = _read_regular(f, 4)
    assert (raw, reason) == (b"", "too_large") and h.hexdigest() == hashlib.sha256(b"hello world").hexdigest()
