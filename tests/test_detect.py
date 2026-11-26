"""Detection traps. Every sentence here is written by us; none comes from the practice data."""
from medveil.detect.engine import Knowledge, detect_slot
from medveil.model import Doc, Slot
from medveil.textnorm import normalize

K = Knowledge()
K.finalize()


def spans(text, ftype=None, kind="value"):
    sl = Slot(path=(), text=normalize(text), ftype=ftype, kind=kind)
    detect_slot(sl, K, Doc(rel="x.txt", sha256="0"))
    return [(sp.etype, sl.text[sp.start:sp.end], sp.role) for sp in sl.spans]


def types(text, **kw):
    return {t for t, _, _ in spans(text, **kw)}


def surfaces(text, etype="NAME", **kw):
    return [s for t, s, _ in spans(text, **kw) if t == etype]


# ---- meaning traps -----------------------------------------------------------
def test_doctor_kept_relative_removed():
    out = spans("Attendant: Ramesh Saxena. Dr. Ramesh Verma reviewed the patient.")
    names = [s for t, s, _ in out if t == "NAME"]
    assert "Ramesh Saxena" in names
    assert not any("Verma" in n for n in names)


def test_care_of_relative_vs_complaint():
    assert surfaces("C/O Rohit Mehra, H.No. 12") == ["Rohit Mehra"]
    assert surfaces("C/O fever for 3 days, generalised weakness") == []
    assert surfaces("C/O: pain abdomen x 7 days") == []


def test_history_markers_kept():
    assert surfaces("K/C/O addison's disease. H/O TB 5 yrs back, completed ATT") == []


def test_doses_are_not_phones_or_ids():
    t = types("Dolo 650 BD x 5 days, Tab Metformin 500 mg 1-0-1, Ramipril 5 mg 0-0-1")
    assert not t & {"PHONE", "AADHAAR", "MRN", "PIN", "NAME"}


def test_lab_values_are_not_pins():
    assert "PIN" not in types("Platelet Count 175000 /uL, WBC 11000 /uL")


def test_eponyms_are_not_people():
    assert surfaces("Diagnosed with Parkinson's disease and Bell's palsy") == []


def test_hospital_ward_vs_address_ward():
    assert "LOCALITY" not in types("Ward/Bed: Ward 4 (Medicine) / Bed 29")
    assert "LOCALITY" in types("Address: H.No. 21, Ward 7, Mohalla Naya Tola, Distt. Unnao")


def test_asha_worker_is_not_a_name():
    assert surfaces("Referred by ASHA worker for follow up") == []


# ---- three scripts -------------------------------------------------------------
def test_devanagari_label_and_postposition():
    assert "राकेश सक्सेना" in surfaces("नाम: राकेश सक्सेना   आयु: 44 वर्ष")
    assert surfaces("पिता का नाम: दिनेश सक्सेना")[0] == "दिनेश सक्सेना"
    assert [r for t, s, r in spans("पिता का नाम: दिनेश सक्सेना") if t == "NAME"] == ["relative"]


def test_hinglish_honorifics_and_postpositions():
    assert "Rohit" in surfaces("Rohit sahab ka BP 150/90")
    assert "Pooja" in surfaces("Pooja ji ko dawai di")
    assert "Imtiyaz" in surfaces("Imtiyaz ka sugar high hai")


def test_name_before_relation_marker():
    out = spans("Meera, W/o Rajan, discharged in stable condition.")
    roles = {s: r for t, s, r in out if t == "NAME"}
    assert roles.get("Meera") == "patient" and roles.get("Rajan") == "relative"


def test_unknown_name_next_to_phone_is_caught():
    # not in any gazetteer: only context finds it (how canaries are planted)
    assert "Xorlan Quibbet" in surfaces("called by Xorlan Quibbet 94054-71434")
    assert "Xorlan Quibbet" in surfaces("18:40 - Xorlan Quibbet (attendant, bed 3), mob 6910522119")


def test_homoglyph_disguised_name():
    # Cyrillic "і" and a zero-width joiner inside the name
    assert surfaces("Patient Name: Sun\u0456ta Me\u200dhra")


# ---- identifiers ---------------------------------------------------------------
def test_phone_formats():
    for p in ("+91 72864 90658", "060062-72163", "75600-10034", "+91-7419406242", "८५९९२५३५२५", "(+91) 72864-90658"):
        assert "PHONE" in types(f"Mobile: {p}"), p


def test_ids():
    t = types("Aadhaar 3972 0583 9628, masked XXXX XXXX 5866, ABHA 91-7938-3729-8403, PAN ABCPD1234K, "
              "mail a.b@example.com, PMJAY-UP-8758791961, UHID: HSP/26/001234")
    assert {"AADHAAR", "AADHAAR_MASKED", "ABHA", "PAN", "EMAIL", "INSURANCE", "MRN"} <= t


def test_structured_fields():
    assert types("S/O KISHAN SAXENA", ftype="RELATIVE") == {"NAME"}
    assert surfaces("S/O KISHAN SAXENA", ftype="RELATIVE") == ["KISHAN SAXENA"]
    assert types("Dr. Kavya Iyer", ftype="NAME") == set()


def test_clean_clinical_text_untouched():
    text = ("1. Any patient presenting with C/O fever for 2-7 days should be tested for NS1 antigen.\n"
            "2. Paracetamol 650 mg every 6 hours; avoid NSAIDs.\n"
            "3. Differential diagnosis includes typhoid, malaria and, rarely, Addison's disease crisis.")
    assert types(text) <= {"DATE"}
