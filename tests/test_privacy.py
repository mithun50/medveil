import datetime as dt

from medveil.crypto import LETTERS, Keys
from medveil.privacy import _aligned, plan_bands, shift_date
from medveil.rare import RareValues, chapter
from medveil.model import Doc, Record, Slot, Span

POLICY = {"age": {"ladder": [10, 20], "top_code": 80, "k_patients": 2},
          "location": {"k_patients": 2, "fallback_level": "state"}, "_division_of": {}}


def test_bands_always_contain_every_true_age():
    for ages in ([48], [49, 50], [38, 41], [79, 81], [5], [97], [59, 60, 61]):
        b = _aligned(ages, 10, 80)
        assert all(b[0] <= a <= b[1] for a in ages), (ages, b)
        b = _aligned(ages, 20, 80)
        assert all(b[0] <= a <= b[1] for a in ages), (ages, b)


def test_rare_class_gets_wider_band_and_state_level():
    profiles = {"a": {"ages": [44], "gender": "F", "district": "Unnao"},
                "b": {"ages": [46], "gender": "F", "district": "Unnao"},
                "c": {"ages": [43], "gender": "M", "district": "Hardoi"}}
    bands, level = plan_bands(profiles, POLICY)
    assert bands["a"] == (40, 49) and bands["b"] == (40, 49)
    assert bands["c"] == (40, 59)
    assert level["a"] == "district" and level["c"] == "state"


def test_top_code():
    bands, _ = plan_bands({"x": {"ages": [92, 93], "gender": "M", "district": "Unnao"}}, POLICY)
    assert bands["x"][0] == 80


def test_shift_is_keyed_nonzero_and_bounded():
    k1, k2 = Keys(b"secret-one"), Keys(b"secret-two")
    shifts = [k1.shift_days(f"p{i}", 30, 365) for i in range(200)]
    assert all(30 <= abs(s) <= 365 for s in shifts)
    assert len(set(shifts)) > 100
    assert [k2.shift_days(f"p{i}", 30, 365) for i in range(200)] != shifts


def test_interval_preserved_under_one_shift():
    adm, dis = dt.date(2026, 2, 7), dt.date(2026, 2, 19)
    s = Keys(b"s").shift_days("patient", 30, 365)
    assert (shift_date(dis, s) - shift_date(adm, s)).days == 12


def test_pseudonyms_deterministic_letters_only_and_keyed():
    a, b = Keys(b"one"), Keys(b"two")
    p = a.pseudonym("mrn:HSP001")
    assert p == a.pseudonym("mrn:HSP001") and p != b.pseudonym("mrn:HSP001")
    assert p.startswith("PSN-") and all(c in LETTERS for c in p[4:])


def test_icd_chapter():
    assert chapter("B55.0")[0] == "A00-B99"
    assert chapter("I10")[0] == "I00-I99"
    assert chapter("E11.9")[0] == "E00-E90"


def _rec(text):
    r = Record(loc="doc")
    r.slots.append(Slot(path=(), text=text, kind="value"))
    return r


def test_rare_diagnosis_is_generalized_common_one_kept():
    recs = [(Doc(rel="a", sha256="0"), _rec("Diagnosis: Visceral leishmaniasis (kala-azar) (B55.0); Typhoid fever (A01.0)"))]
    for i in range(4):
        recs.append((Doc(rel=f"b{i}", sha256="0"), _rec("Diagnosis: Typhoid fever (A01.0)")))
    rv = RareValues(2)
    rv.collect(recs)
    rv.plan({i: f"p{i}" for i in range(len(recs))})
    assert rv.apply(0, recs[0][1])
    out = recs[0][1].slots[0].out
    assert out == ("Diagnosis: Certain infectious and parasitic diseases (A00-B99); Typhoid fever (A01.0)")


def test_eponym_diagnosis_kept_even_if_rare():
    recs = [(Doc(rel="a", sha256="0"), _rec("Diagnosis: Wilson's disease (E83.0)"))]
    rv = RareValues(2)
    rv.collect(recs)
    assert "E83.0" in rv.rec_codes[0], "the diagnosis must be collected for this test to mean anything"
    rv.plan({0: "p0"})
    assert "E83.0" not in rv.rare_codes
    assert not rv.apply(0, recs[0][1])


# ---------------------------------------------------------------- review findings, PR #3

def _collect(texts):
    recs = [(Doc(rel=f"r{i}", sha256="0"), _rec(x)) for i, x in enumerate(texts)]
    rv = RareValues(2)
    rv.collect(recs)
    return rv, recs


def test_uppercase_procedure_label_is_collected():
    rv, _ = _collect(["PROCEDURE: ventricular assist device implantation."])
    assert "ventricular assist device implantation" in rv.procs


def test_rare_diagnosis_mention_far_into_a_long_note_is_found():
    rv, _ = _collect(["Diagnosis: Visceral leishmaniasis (B55.0)",
                      "x " * 120_000 + "Treated for visceral leishmaniasis, improving."])
    assert "B55.0" in rv.rec_codes[1]


def test_long_diagnosis_display_is_generalized_whole():
    # Within DIAG_WITH_CODE's limits (90 + parenthesis of up to 30 + 60) but longer than
    # the 160-character window the display search used to look at.
    head = "Chronic visceral leishmaniasis with marked splenomegaly and pancytopenia in a migrant man "
    display = head + "(post kala-azar dermal form)" + " with secondary bacterial infection of all the skin lesions"
    assert len(head) <= 90 and len(display) > 160
    rv, recs = _collect(["Diagnosis: " + display + " (B55.0)"])
    rv.plan({0: "p0"})
    assert rv.apply(0, recs[0][1])
    out = recs[0][1].slots[0].out
    assert out == "Diagnosis: Certain infectious and parasitic diseases (A00-B99)", out


def _dob_ctx(mode):
    from medveil.rewrite import Ctx
    return Ctx(psn="PSN-ABCDEFGH", rec_token="t", shift=40, band=None, top=80, district=None, dob_mode=mode)


def test_structured_dob_in_shift_mode_keeps_only_the_dates():
    from medveil.rewrite import replacement
    text = "12/03/1980, Ramesh Kumar, 9876543210"
    sl = Slot(path=(0, 1), text=text, ftype="DOB", kind="value")
    out = replacement(Span(0, len(text), "DOB"), sl, _dob_ctx("shift"), structured=True)
    assert out == "21/04/1980", out
    assert replacement(Span(0, len(text), "DOB"), sl, _dob_ctx("suppress"), structured=True) == ""


def test_fhir_birthdate_with_spaces_is_dropped_not_left_blank():
    import json
    from medveil.detect.fields import classify_header, classify_key
    from medveil.ingest import build_slots, sniff_and_parse
    from medveil.policy import DEFAULTS
    from medveil.rewrite import serialize
    bundle = {"resourceType": "Bundle", "type": "collection", "entry": [{"resource": {
        "resourceType": "Patient", "id": "p1", "gender": "male", "birthDate": " 1980-03-12 "}}]}
    doc = Doc(rel="fhir/b.json", sha256="0")
    sniff_and_parse(doc, json.dumps(bundle).encode(), DEFAULTS)
    build_slots(doc, classify_header, classify_key)
    dob = [sl for r in doc.records for sl in r.slots if sl.ftype == "DOB"]
    assert dob, "birthDate must be typed as DOB for this test to mean anything"
    for sl in dob:
        sl.out = "  "            # what rewriting leaves when the date itself is suppressed
    assert "birthDate" not in serialize(doc)


def test_unknown_dob_mode_falls_back_to_suppress(tmp_path):
    from medveil.policy import load
    p = tmp_path / "policy.yaml"
    p.write_text("dob:\n  mode: year\n", encoding="utf-8")
    assert load(p)["dob"]["mode"] == "suppress"
    p.write_text("dob:\n  mode: shift\n", encoding="utf-8")
    assert load(p)["dob"]["mode"] == "shift"
