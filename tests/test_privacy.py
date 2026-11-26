import datetime as dt

from medveil.crypto import LETTERS, Keys
from medveil.privacy import _aligned, plan_bands, shift_date
from medveil.rare import RareValues, chapter
from medveil.model import Doc, Record, Slot

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
    assert "leishmaniasis" not in out and "B55.0" not in out
    assert "Typhoid fever (A01.0)" in out and "A00-B99" in out


def test_eponym_diagnosis_kept_even_if_rare():
    recs = [(Doc(rel="a", sha256="0"), _rec("Diagnosis: Wilson's disease (E83.0)"))]
    rv = RareValues(2)
    rv.collect(recs)
    rv.plan({0: "p0"})
    assert not rv.apply(0, recs[0][1])
