"""Unseen labels, headers and formats (found with fresh tools/chaos_gen.py seeds 21-40).

Every case below failed before the change that added it: each one leaked personal data,
destroyed a clinical value or blocked linking on a held-out data set.
"""
import pytest

from medveil.detect.engine import Knowledge, detect_slot
from medveil.detect.fields import classify_header, classify_key, profile_column
from medveil.ingest import build_slots, sniff_and_parse
from medveil.model import Doc, Record, Slot
from medveil.policy import DEFAULTS
from medveil.privacy import raise_location
from medveil.textnorm import normalize

K = Knowledge()
K.finalize()


def found(text, kind="value", ftype="TEXT"):
    sl = Slot(path=(), text=normalize(text), ftype=ftype, kind=kind, key="")
    detect_slot(sl, K, Doc(rel="x.txt", sha256="0"), kind == "header")
    return [(s.etype, sl.text[s.start:s.end]) for s in sl.spans]


# --------------------------------------------------------------- headers
@pytest.mark.parametrize("header", ["test_name", "procedure_name", "hospital_name", "drug name", "package_name",
                                    "ward name", "lab_name"])
def test_a_things_name_is_not_a_patient_name(header):
    # "test_name" typed NAME replaced "Haemoglobin" with [PATIENT] and made every lab row
    # look like two people, so no lab row was linked (seed 25: recall 0.32).
    assert classify_header(header) != "NAME"


@pytest.mark.parametrize("header", ["Patient Name", "pt_name", "name_of_patient", "Name", "Naam", "Full Name",
                                    "Poora Naam", "Rogi ka Naam", "Mariz ka Naam", "beneficiary name"])
def test_person_name_headers_stay_names(header):
    assert classify_header(header) == "NAME"


@pytest.mark.parametrize("header,kind", [
    ("Mauza", "VILLAGE"), ("Majra", "VILLAGE"), ("Kasba", "VILLAGE"), ("\u092e\u094c\u091c\u093e", "VILLAGE"),
    ("Block", "TEHSIL"), ("Vikas Khand", "TEHSIL"), ("Mandal", "TEHSIL"),
    ("Janpad", "DISTRICT"), ("Zilla", "DISTRICT"), ("\u091c\u0928\u092a\u0926", "DISTRICT"),
    ("M/F", "GENDER"), ("Linga", "GENDER"), ("Rel.", "RELATION"), ("PHR ID", "ABHA"),
    ("pol_no", "INSURANCE"), ("doa", "DATE"), ("dod", "DATE"),
])
def test_revenue_and_abbreviated_headers(header, kind):
    assert classify_header(header) == kind


def test_unknown_header_over_settlement_names_is_a_village_column():
    assert profile_column(["Bhimnagar", "Mohanganj", "\u0930\u0938\u0942\u0932\u0928\u0917\u0930 \u0916\u0941\u0930\u094d\u0926",
                           "Jalalpur", "Shivgarh"]) == "VILLAGE"
    assert profile_column(["Sultanpur", "Lucknow", "Bahraich", "Unnao", "Rae Bareli"]) == "DISTRICT"


@pytest.mark.parametrize("values", [["Haemoglobin", "HbA1c", "Serum Creatinine", "TSH"],
                                    ["Paracetamol", "Amlodipine", "Metformin"]])
def test_clinical_columns_are_not_places(values):
    assert profile_column(values) is None


def test_surnames_that_look_like_places_stay_names():
    assert profile_column(["Pawan Kapur", "Sonali Puri", "Anjali Nagar"]) == "NAME"


@pytest.mark.parametrize("header", ["Pita/Pati ka Naam", "Sambandhi ka Naam", "Abhibhavak ka Naam"])
def test_role_words_in_hinglish_headers_are_not_names(header):
    # "Pati ka Naam" lost "Pati" as a name: the header changed (schema) and a token was lost
    assert found(header, kind="header", ftype=None) == []


def test_a_known_name_before_ka_is_still_a_name():
    assert ("NAME", "Ramesh") in found("Ramesh ka number 9876543210")


# --------------------------------------------------------------- free-text labels
@pytest.mark.parametrize("text,village", [
    ("\u092e\u094c\u091c\u093e: \u092d\u0940\u092e\u0928\u0917\u0930", "\u092d\u0940\u092e\u0928\u0917\u0930"),
    ("Mauza: Bhimnagar, Janpad Sultanpur", "Bhimnagar"),
])
def test_mauza_label_marks_a_village(text, village):
    assert ("VILLAGE", village) in found(text)


@pytest.mark.parametrize("text,mrn", [
    ("\u0906\u0908.\u092a\u0940. \u0928\u0902.: DHH/ADM/00591", "DHH/ADM/00591"),
    ("\u0930\u091c\u093f. \u0928\u0902.: DHH.084999", "DHH.084999"),
    ("I.P. No.: HDI-IP-00591", "HDI-IP-00591"),
])
def test_dotted_id_labels(text, mrn):
    assert ("MRN", mrn) in found(text)


def test_possessive_before_a_relation_noun_is_a_name():
    assert ("NAME", "Agnes") in found("Sample received from Agnes's attendant.")
    assert found("Patient's attendant informed the nurse.") == []


def test_a_documents_own_id_is_removed_from_its_file_name():
    # a one-off ID format is never learned as a shape, so the file name kept it
    from medveil.detect.engine import own_ids_in_filename
    doc = Doc(rel="discharge/dhhardoi_ds_HDI-IP-00591.txt", sha256="0")
    sniff_and_parse(doc, "I.P. No.: HDI-IP-00591\nDiagnosis: Malaria (B54)\n".encode(), DEFAULTS)
    build_slots(doc, classify_header, classify_key)
    for rec in doc.records:
        for sl in rec.slots:
            detect_slot(sl, K, doc)
    for fs in doc.file_slots:
        detect_slot(fs, K, doc, file_level=True)
    own_ids_in_filename(doc)
    fs = next(s for s in doc.file_slots if s.kind == "filename")
    assert [fs.text[s.start:s.end] for s in fs.spans if s.etype == "MRN"] == ["HDI-IP-00591"]


# --------------------------------------------------------------- district raising
@pytest.mark.parametrize("text", ["\u091c\u093f\u0932\u093e \u0938\u0941\u0932\u094d\u0924\u093e\u0928\u092a\u0941\u0930, 228001",
                                  "\u091c\u0928\u092a\u0926 \u0938\u0941\u0932\u094d\u0924\u093e\u0928\u092a\u0941\u0930, 228001",
                                  "Janpad Sultanpur, 228001"])
def test_district_in_text_is_raised_in_both_scripts(text):
    # A PowerShell rewrite once turned the Devanagari district label in this regex into
    # mojibake, so Hindi "जिला X" was silently never raised to the state.
    rec = Record(loc="doc")
    rec.slots.append(Slot(path=(), text=text, ftype="TEXT", kind="text"))
    assert raise_location(rec, "state", {})
    assert "Uttar Pradesh" in rec.slots[0].out
