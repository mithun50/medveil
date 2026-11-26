"""Tests for tools/adversarial_gen.py.

The core invariant: every disguise the generator can apply is undone by the scorer-style
normaliser in verify mode. If that ever breaks, the "raw copy leaks near 100%" sanity
check is meaningless, so these tests pin it down. The kit-gated test also checks the
generator's correctness properties (preserve probes survive verbatim, truth keeps the
clean surface, hostile metadata is written).
"""
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

_spec = importlib.util.spec_from_file_location("adversarial_gen", TOOLS / "adversarial_gen.py")
adv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(adv)

KIT = ROOT.parent / "Secret-Wards-ToolKit"

NAME_SAMPLES = ["Mahesh Chauhan", "Fatima Bano", "Asha", "anita.sharma8186@example.com", "DCSPS3454E"]
DIGIT_SAMPLES = ["9876543210", "397205839628", "91-7938-3729-8403", "SNJ/26/064127", "IPD-2026-00461"]


def _alnum(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s)


@pytest.mark.parametrize("surface", NAME_SAMPLES)
@pytest.mark.parametrize("kind", adv.NAME_TWEAKS)
def test_name_tweaks_are_undone_by_the_normaliser(kind, surface):
    tweaked = adv.tweak_name(surface, kind, "\u200b")
    if tweaked is None:
        pytest.skip("tweak does not change this surface")
    assert tweaked != surface
    folded = adv.normalise_blob(tweaked)
    for tok in re.findall(r"[a-z0-9]+", surface.casefold()):
        assert tok in folded, "token %r lost after %s -> %r" % (tok, kind, folded)


@pytest.mark.parametrize("surface", DIGIT_SAMPLES)
@pytest.mark.parametrize("kind", adv.DIGIT_TWEAKS)
def test_digit_tweaks_are_undone_by_the_normaliser(kind, surface):
    tweaked = adv.tweak_digits(surface, kind)
    if tweaked is None:
        pytest.skip("tweak does not apply to this surface")
    assert tweaked != surface
    key = _alnum(re.sub(r"\D", "", surface))
    recovered = _alnum(adv.normalise_blob(tweaked))
    assert key in recovered, "digits %r lost after %s -> %r" % (key, kind, recovered)


@pytest.mark.parametrize("kind", adv.WRAP_KINDS)
def test_payload_wrapping_is_decoded_back(kind):
    line = "Patient Name: Rohit Mehra Mobile 9876543210"
    blob = adv.wrap_line(line, kind)
    assert "Rohit" not in blob and "9876543210" not in blob  # really hidden on the surface
    folded = adv.normalise_blob(blob)
    assert "rohit" in folded and "mehra" in folded
    assert "9876543210" in _alnum(folded)


def test_cp1252_fallback_picks_an_encodable_tweak():
    # Cyrillic / fullwidth cannot encode in cp1252; choose_tweak must fall back.
    for surface in ("Mahesh Chauhan", "Naresh"):
        kind, new = adv.choose_tweak(surface, "PATIENT_NAME", "cp1252", seed=3, fkey="f")
        assert new is not None
        new.encode("cp1252")  # must not raise
        folded = adv.normalise_blob(new)
        for tok in re.findall(r"[a-z]+", surface.casefold()):
            assert tok in folded


def test_homoglyph_table_inverts_the_cyrillic_tweak():
    # Every Cyrillic letter the generator substitutes must fold back to its Latin letter.
    for latin, cyr in adv._CYR.items():
        assert adv.fold(cyr) == latin.casefold()


def test_tweak_file_survives_json_too_deep_to_parse():
    # Regression: the kit ships a 1,500-deep JSON file. On Python 3.10 and 3.11 json.loads
    # raises RecursionError (not ValueError) on it, which crashed generation in CI. 100,000
    # levels raise RecursionError on every supported version, whatever the recursion limit.
    deep = "[" * 100_000 + "]" * 100_000
    text = '{"name": "Mahesh Chauhan", "x": %s}\n' % deep
    f = {"format": "json", "encoding": "utf-8", "sha256": "deep",
         "units": {"/": {"entities": [{"channel": "content", "type": "PATIENT_NAME",
                                      "surface": "Mahesh Chauhan"}], "preserve": []}}}
    changed_any = False
    for seed in range(20):  # some seeds select the surface for tweaking, some do not
        data, _, changed = adv.tweak_file("deep.json", f, text.encode("utf-8"), seed, None, adv.Counter())
        changed_any |= changed
        assert data.endswith(b"}\n")
    assert changed_any, "no seed tweaked the name, so the JSON check was never reached"


@pytest.mark.skipif(not ((KIT / "dev" / "input").is_dir() and (KIT / "dev" / "truth" / "truth.json").is_file()),
                    reason="toolkit not next to the repo")
def test_generation_keeps_truth_consistent(tmp_path):
    rc = adv.generate(KIT.resolve(), tmp_path.resolve(), 3)
    assert rc == 0
    dest = tmp_path / "3"
    truth = json.loads((dest / "truth" / "truth.json").read_text(encoding="utf-8"))
    assert truth["adversarial"]["tweaked_entities"] > 0
    assert truth["adversarial"]["by_tweak"]
    assert truth["hostile"], "hostile metadata missing"

    src_in = dest / "input"
    # Entities keep the ORIGINAL clean surface (the kit's); tweaked ones carry a tweak kind.
    kit_files = json.loads((KIT / "dev" / "truth" / "truth.json").read_text(encoding="utf-8"))["files"]
    seen_tweak = False
    for rel, f in truth["files"].items():
        if f.get("category") == "hostile":
            continue
        orig = kit_files.get(rel)
        for uk, u in f["units"].items():
            orig_ents = orig["units"][uk]["entities"] if orig else None
            if orig_ents is not None:
                assert len(orig_ents) == len(u["entities"]), (rel, uk)
            for i, e in enumerate(u["entities"]):
                if orig_ents is not None:
                    assert e["surface"] == orig_ents[i]["surface"], (rel, uk, e["surface"])
                if e.get("tweak"):
                    seen_tweak = True
                    assert e["tweak"] in set(adv.NAME_TWEAKS) | set(adv.DIGIT_TWEAKS) | set(adv.WRAP_KINDS)
    assert seen_tweak

    # Every preserve probe must still survive where the scorer looks: the decoded
    # haystack (raw text + decoded \uXXXX JSON string values + decoded base64 blobs).
    for rel, f in truth["files"].items():
        if f.get("category") in ("hostile",) or f.get("format") in ("pdf", "binary"):
            continue
        if f.get("format") == "symlink":
            continue
        p = src_in / rel
        assert p.is_file(), "input file missing: %s" % rel
        if f.get("category") == "malformed":
            continue   # deliberately undecodable kit files (corrupt bytes); they carry no probes
        enc = f.get("encoding") or "utf-8"
        text = p.read_bytes().decode(enc)   # a decode error fails the test instead of skipping
        hay = text + "\n" + "\n".join(dec for _, _, dec in adv.cg.b64_blobs(text))
        if f.get("format") in ("json", "fhir"):
            hay += "\n" + adv.cg.decoded_json_text(text)
        for u in f["units"].values():
            for pr in u.get("preserve") or []:
                t = pr.get("text")
                if not t:
                    continue
                assert t in hay, "preserve probe lost in %s: %r" % (rel, t)

    # Hostile files exist on disk and are recorded in both maps.
    for rel in truth["hostile"]:
        if truth["files"][rel].get("format") == "symlink":
            continue
        assert (src_in / rel).exists(), "missing hostile file %s" % rel


# ---------------------------------------------------------------- review findings, PR #3

def test_u_escape_wrapper_round_trips_non_bmp():
    line = "Name: Rohit \U0001F600 Mehra"
    blob = adv.wrap_line(line, "wrap_uXXXX")
    assert json.loads('"' + blob[len("esc: "):] + '"') == line


def test_take_phone_fallback_never_repeats():
    used = set()
    got = [adv.take_phone(iter(["9876543210"]), used) for _ in range(4)]
    assert len(set(got)) == 4 and got[0] == "9876543210"


def test_read_bytes_is_bounded_and_flags_long_files(tmp_path):
    f = tmp_path / "big.txt"
    f.write_bytes(b"a" * 100)
    adv.TOO_LARGE.clear()
    assert adv._read_bytes(f, limit=10) == b"a" * 10
    assert adv.TOO_LARGE == [str(f)]
    adv.TOO_LARGE.clear()
    assert adv._read_bytes(f, limit=100) == b"a" * 100 and adv.TOO_LARGE == []


def _mini_truth(tmp_path, hostile=None):
    truth = {"files": {}, "hostile": hostile or {}}
    p = tmp_path / "truth.json"
    p.write_text(json.dumps(truth), encoding="utf-8")
    return p


def test_verify_fails_without_a_release(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    assert adv.verify(out, _mini_truth(tmp_path), None) == 1


def _release(tmp_path, text):
    out = tmp_path / "out"
    (out / "sanitized").mkdir(parents=True)
    (out / "sanitized" / "a.txt").write_text(text, encoding="utf-8")
    (out / "report.json").write_text(json.dumps({"files": []}), encoding="utf-8")
    return out


def test_verify_fails_when_symlink_target_pii_is_released(tmp_path):
    ents = [{"type": "PATIENT_NAME", "surface": adv.OUTSIDE_NAME, "match": "name",
             "tokens": [t.lower() for t in adv.OUTSIDE_NAME.split()]}]
    hostile = {"hostile/link.txt": {"kind": "symlink_escape", "expect": "either", "target_pii": ents}}
    truth = _mini_truth(tmp_path, hostile)
    # the link itself is listed as quarantined; only the leaked target text should fail
    rep = {"files": [{"input_sha256": None, "status": "quarantined"}]}
    clean = _release(tmp_path, "nothing personal here")
    (clean / "report.json").write_text(json.dumps(rep), encoding="utf-8")
    truth_d = json.loads(truth.read_text(encoding="utf-8"))
    truth_d["files"]["hostile/link.txt"] = {"sha256": None, "units": {}}
    truth.write_text(json.dumps(truth_d), encoding="utf-8")
    assert adv.verify(clean, truth, None) == 0
    (clean / "sanitized" / "a.txt").write_text("leaked: " + adv.OUTSIDE_NAME, encoding="utf-8")
    assert adv.verify(clean, truth, None) == 1


def test_verify_fails_on_hostile_handling_mismatch(tmp_path):
    truth = _mini_truth(tmp_path, {"hostile/x.json": {"kind": "json_nan", "expect": "quarantine"}})
    truth_d = json.loads(truth.read_text(encoding="utf-8"))
    truth_d["files"]["hostile/x.json"] = {"sha256": "abc", "units": {}}
    truth.write_text(json.dumps(truth_d), encoding="utf-8")
    out = _release(tmp_path, "ok")
    (out / "report.json").write_text(json.dumps({"files": [{"input_sha256": "abc", "status": "sanitized"}]}),
                                     encoding="utf-8")
    assert adv.verify(out, truth, None) == 1
    (out / "report.json").write_text(json.dumps({"files": [{"input_sha256": "abc", "status": "quarantined"}]}),
                                     encoding="utf-8")
    assert adv.verify(out, truth, None) == 0
