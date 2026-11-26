"""Tests for the dev-only score estimator tools/scorecard.py."""
import base64
import hashlib
import importlib.util
import json
import math
import sys
from datetime import date
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("scorecard", ROOT / "tools" / "scorecard.py")
sc = importlib.util.module_from_spec(_spec)
sys.modules["scorecard"] = sc
_spec.loader.exec_module(sc)


def test_norm_folds_disguises():
    assert sc.norm("R\u0430mesh") == "ramesh"            # Cyrillic a
    assert sc.norm("Ra\u200bmesh") == "ramesh"           # zero-width space
    assert sc.norm("\u0966\u096f") == "09"               # Devanagari digits
    assert sc.norm("12\u201334") == "12-34"              # en dash
    assert sc.norm("Ram\u00e9sh  KUMAR") == "ramesh kumar"
    deva = "\u0915\u092e\u0932\u093e"                     # Devanagari keeps its vowel signs
    assert sc.norm(deva) == deva


def test_hay_decodes_hidden_payloads_without_double_counting():
    b64 = base64.b64encode("Mahesh Chauhan 9876543210".encode()).decode()
    h = sc.Hay("attachment " + b64)
    assert h.count("w", "mahesh") == 1
    assert h.count("d", "9876543210") == 1
    assert sc.Hay("\\u092e\\u0939\\u0947\\u0936").count("w", sc.norm("\u092e\u0939\u0947\u0936")) == 1
    assert sc.Hay("R&#97;mesh").count("w", "ramesh") == 1
    assert sc.Hay("Ram%65sh").count("w", "ramesh") == 1
    assert sc.Hay("Ramesh &amp; Co").count("w", "ramesh") == 1
    assert sc.Hay("Rameshwar").count("w", "ramesh") == 0


def test_digit_keys_across_separators_and_prefixes():
    assert sc.Hay("+91 72864-90658").count("d", "7286490658") == 1
    assert sc.Hay("060062-72163").count("d", "6006272163") == 1          # trunk 0 glued on
    assert sc.Hay("\u096f\u096e\u096d\u096c\u096b\u096a\u0969\u0968\u0967\u0966").count("d", "9876543210") == 1
    assert sc.Hay("SNJ/26/064127").count("d", "064127") == 1
    assert sc.Hay("1064127").count("d", "064127") == 0
    assert sc.Hay('{"aadhaar": 397205839628}').count("d", "397205839628") == 1
    assert sc.Hay("229073").count("x", "229073") == 1
    assert sc.Hay("2290731").count("x", "229073") == 0


@pytest.mark.parametrize("text", ["12/04/1977", "1977-04-12", "12 Apr 1977", "April 12, 1977", "19770412",
                                  "04/12/1977"])
def test_dob_matches_any_format(text):
    assert sc.Hay("DOB: " + text).count("b", "1977-04-12") == 1


def test_dob_other_date_does_not_match():
    assert sc.Hay("DOB: 13/04/1977").count("b", "1977-04-12") == 0


def test_preserve_probe_spans_allow_the_doctor():
    h = sc.Hay("Dr. Ramesh Verma saw the patient. Relative: Ramesh Yadav")
    spans = h.probe_spans({sc.norm("Dr. Ramesh Verma")})
    assert h.count("w", "ramesh") == 2
    assert h.count_inside("w", "ramesh", spans) == 1


def test_age_dob_and_location_scores():
    assert sc.age_score("45-49", 47) == (0.9, False)
    assert sc.age_score("40-49/F", 47) == (0.8, False)
    assert sc.age_score("40-59", 47) == (0.6, False)
    assert sc.age_score("[45,50)", 49) == (0.9, False)
    assert sc.age_score("80+", 85) == (0.3, False)
    assert sc.age_score("50-54", 47) == (0.0, True)
    assert sc.age_score("47 Yrs/F", 47) == (1.0, False)
    assert sc.dob_score("12/04/1977", "1977-04-12", "dmy")[0] == 1.0
    assert sc.dob_score("20/04/1977", "1977-04-12", "dmy")[0] == 0.9
    assert sc.dob_score("1977", "1977-04-12", "dmy")[0] == 0.8
    assert sc.dob_score("1980", "1977-04-12", "dmy")[0] == 0.0


def test_parse_date_value_orders_and_yearless():
    assert sc.parse_date_value("01/13/2026", "mdy", None) == date(2026, 1, 13)
    assert sc.parse_date_value("05/11/2025", "dmy", None) == date(2025, 11, 5)
    assert sc.parse_date_value("30/05/26, 9:32 pm", "dmy", None) == date(2026, 5, 30)
    assert sc.parse_date_value("5 September", "dmy", date(2026, 9, 5)) == date(2026, 9, 5)
    assert sc.parse_date_value("11 December", "dmy", date(2026, 1, 10)) == date(2025, 12, 11)
    assert sc.parse_date_value("2026-08-30T09:30:00+05:30", "dmy", None) == date(2026, 8, 30)


def test_fbeta_and_loglin():
    assert sc.fbeta(1.0, 1.0, 2.0) == 1.0
    assert sc.fbeta(0.0, 1.0, 2.0) == 0.0
    assert sc.loglin(10, 15, 300) == 1.0
    assert sc.loglin(300, 15, 300) == 0.0
    assert math.isclose(sc.loglin(math.sqrt(15 * 300), 15, 300), 0.5)


# ----------------------------------------------------------------------------
# Synthetic end-to-end release (no toolkit needed)
# ----------------------------------------------------------------------------

TOML = """
[weights]
detection = 0.20
identity_resolution = 0.15
privacy = 0.25
utility = 0.20
integrity = 0.10
performance = 0.10
[detection]
beta = 2.0
type_mix = 0.5
[detection.type_weights]
PHONE = 1.0
PATIENT_NAME = 1.0
[utility.weights]
clinical_probes = 0.35
temporal = 0.20
generalization = 0.10
statistics = 0.15
token_retention = 0.10
record_retention = 0.10
[integrity.weights]
format_validity = 0.15
schema_preservation = 0.20
fhir_validity = 0.15
pseudonym_consistency = 0.10
channel_hygiene = 0.15
quarantine_handling = 0.15
report_quality = 0.10
[privacy]
utility_coupling_threshold = 0.40
[performance.profiles.small]
time_good_s = 15
time_limit_s = 300
memory_good_mb = 512
memory_limit_mb = 4096
[penalties]
per_leaked_identifier = 1.0
leaked_identifier_cap = 25
per_unprocessed_export = 5
unprocessed_cap = 20
per_canary_leak = 3
canary_cap = 15
false_success = 10
input_tampering = 5
"""

REG_IN = ("Name,Mobile,Doctor,Diagnosis\n"
          "Mahesh Chauhan,9876543210,Dr. Mahesh Verma,J18.9\n"
          "Sunita Patel,9123456789,Dr. Asha Rao,E11.9\n")
NOTE_IN = "Patient: Mahesh Chauhan\nDate: 10-05-2026\nC/O fever x 3 days\n"


def _name(surface, toks):
    return {"type": "PATIENT_NAME", "surface": surface, "person": "P", "role": "patient", "script": "latin",
            "channel": "content", "match": "name", "tokens": toks, "full": True, "critical": True}


def _phone(surface, key):
    return {"type": "PHONE", "surface": surface, "person": "P", "role": "patient", "script": "latin",
            "channel": "content", "match": "digits", "key": key, "critical": True}


def _unit(loc, pt, ents, preserve, dates=()):
    return {"loc": loc, "patient": pt, "cid": f"{pt}#0", "link": "required", "tags": [], "entities": ents,
            "preserve": preserve, "dates": list(dates), "fields": [], "exclude": []}


def _file(path, fmt, raw, units):
    return {"path": path, "format": fmt, "encoding": "utf-8", "delimiter": "," if fmt == "csv" else None,
            "expect": "sanitize", "category": "registration", "clean": False, "date_hint": "dmy",
            "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw), "generalizable": [],
            "units": {u["loc"]: u for u in units}}


def _build(tmp_path: Path, reg_out: str, note_out: str, note_psn: str):
    inp = tmp_path / "input"
    inp.mkdir()
    (inp / "reg.csv").write_bytes(REG_IN.encode())
    (inp / "note.txt").write_bytes(NOTE_IN.encode())
    truth = {
        "files": {
            "reg.csv": _file("reg.csv", "csv", REG_IN.encode(), [
                _unit("row:0", "PT1",
                      [_name("Mahesh Chauhan", ["mahesh", "chauhan"]), _phone("9876543210", "9876543210")],
                      [{"text": "Dr. Mahesh Verma", "kind": "doctor", "weight": 0.5, "trap": "doctor",
                        "path": "col:Doctor"},
                       {"text": "J18.9", "kind": "diagnosis_code", "weight": 1.0, "path": "col:Diagnosis"}]),
                _unit("row:1", "PT2", [_name("Sunita Patel", ["sunita", "patel"]), _phone("9123456789", "9123456789")],
                      [{"text": "E11.9", "kind": "diagnosis_code", "weight": 1.0, "path": "col:Diagnosis"}]),
            ]),
            "note.txt": _file("note.txt", "text", NOTE_IN.encode(), [
                _unit("doc", "PT1", [_name("Mahesh Chauhan", ["mahesh", "chauhan"])],
                      [{"text": "C/O fever x 3 days", "kind": "complaint", "weight": 1.0, "trap": "c/o-complaint"}],
                      [{"true": "2026-05-10", "event": "rx", "patient": "PT1", "hint": "dmy", "anchor": "Date:"}]),
            ]),
        },
        "patients": {}, "traps": {}, "canaries": [],
    }
    (tmp_path / "truth.json").write_text(json.dumps(truth), encoding="utf-8")
    out = tmp_path / "out"
    (out / "sanitized").mkdir(parents=True)
    (out / "sanitized" / "reg.csv").write_text(reg_out, encoding="utf-8")
    (out / "sanitized" / "note.txt").write_text(note_out, encoding="utf-8")
    recs = [{"file": "sanitized/reg.csv", "loc": "row:0", "patient": "PSN-AAAA"},
            {"file": "sanitized/reg.csv", "loc": "row:1", "patient": "PSN-BBBB"},
            {"file": "sanitized/note.txt", "loc": "doc", "patient": note_psn}]
    (out / "records.jsonl").write_text("".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")
    files = [{"input_sha256": truth["files"][n]["sha256"], "output": f"sanitized/{n}", "status": "sanitized"}
             for n in ("note.txt", "reg.csv")]
    report = {"schema": "raksha-report/1", "files": files,
              "counts": {k: 0 for k in sc.REPORT_COUNTS} | {"files_total": 2, "files_sanitized": 2,
                                                             "files_quarantined": 0},
              "entities": {}, "timing": {"seconds": 1.0}, "resources": {"peak_rss_mb": 50.0}}
    (out / "report.json").write_text(json.dumps(report), encoding="utf-8")
    (tmp_path / "scoring.toml").write_text(TOML, encoding="utf-8")
    rt = {"overall_risk": 0.1, "ours": {"pseudonyms": 2},
          "components": [{"name": "A1 direct exposure", "raw": 1.0, "ours": 0.0, "ratio": 0.0, "weight": 0.2},
                         {"name": "A2/A3 record linkage", "raw": 0.9, "ours": 0.18, "ratio": 0.2, "weight": 0.2}]}
    (tmp_path / "rt.json").write_text(json.dumps(rt), encoding="utf-8")
    return out


def _score(tmp_path: Path, out: Path) -> dict:
    res_path = tmp_path / "res.json"
    rc = sc.main(["--output", str(out), "--input", str(tmp_path / "input"), "--truth", str(tmp_path / "truth.json"),
                  "--kit", str(tmp_path), "--config", str(tmp_path / "scoring.toml"),
                  "--redteam-json", str(tmp_path / "rt.json"), "--repeat", str(out), "--json", str(res_path)])
    assert rc == 0
    return json.loads(res_path.read_text(encoding="utf-8"))


def test_clean_release_scores_full_detection_and_identity(tmp_path):
    out = _build(tmp_path,
                 "Name,Mobile,Doctor,Diagnosis\nPSN-AAAA,[PHONE],Dr. Mahesh Verma,J18.9\n"
                 "PSN-BBBB,[PHONE],Dr. Asha Rao,E11.9\n",
                 "Patient: PSN-AAAA\nDate: 15-05-2026\nC/O fever x 3 days\n", "PSN-AAAA")
    res = _score(tmp_path, out)
    det, ident = res["categories"]["detection"], res["categories"]["identity_resolution"]
    assert det["parts"]["recall"] == 1.0          # the doctor's "Mahesh" is allowed, not a leak
    assert det["parts"]["contextual_precision"] == 1.0
    assert ident["details"]["pairwise_precision"] == 1.0 and ident["details"]["pairwise_recall"] == 1.0
    assert res["penalties"]["leaked_identifiers"]["count"] == 0
    assert res["categories"]["utility"]["parts"]["clinical_probes"] == 1.0
    assert res["categories"]["integrity"]["parts"]["pseudonym_consistency"] == 1.0
    assert math.isclose(res["total"], res["subtotal"])


def test_leaks_and_claims_outside_the_record_are_caught(tmp_path):
    out = _build(tmp_path,
                 "Name,Mobile,Doctor,Diagnosis\nPSN-AAAA,[PHONE],Dr. Mahesh Verma,J18.9\n"
                 "PSN-BBBB,91234 56789,Dr. Asha Rao,E11.9\n",
                 "Patient: [NAME]\nDate: 15-05-2026\nC/O fever x 3 days\n", "PSN-AAAA")
    res = _score(tmp_path, out)
    det, ident = res["categories"]["detection"], res["categories"]["identity_resolution"]
    assert det["details"]["recall_by_type"]["PHONE"] == 0.5
    assert res["penalties"]["leaked_identifiers"]["count"] == 1
    # the note's claim names a pseudonym that is not in the note: treated as null
    assert ident["details"]["unit_claims_dropped_not_in_record"] == 1
    assert ident["details"]["pairwise_recall"] == 0.0
    assert res["categories"]["integrity"]["parts"]["pseudonym_consistency"] == pytest.approx(2 / 3)
    for loss in res["losses"]:
        assert "Sunita" not in loss["message"] and "9123" not in loss["message"]


# ----------------------------------------------------------------------------
# Calibration against the published anchors (needs the toolkit next to the repo)
# ----------------------------------------------------------------------------

def test_passthrough_calibration(kit, tmp_path):
    out = tmp_path / "pt"
    truth = kit / "dev" / "truth" / "truth.json"
    assert sc.main(["--make-baseline", "passthrough", "--input", str(kit / "dev" / "input"), "--output", str(out),
                    "--truth", str(truth)]) == 0
    res_path = tmp_path / "pt.json"
    assert sc.main(["--output", str(out), "--input", str(kit / "dev" / "input"), "--truth", str(truth),
                    "--kit", str(kit), "--other", str(out), "--repeat", str(out), "--json", str(res_path)]) == 0
    res = json.loads(res_path.read_text(encoding="utf-8"))
    assert res["categories"]["detection"]["parts"]["recall"] == 0.0
    assert res["categories"]["utility"]["score"] == pytest.approx(1.0, abs=1e-3)
    assert -21.5 < res["total"] < -17.5          # SCORING.md anchor: -19.48
