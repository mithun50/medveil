"""End-to-end checks on the practice data (skipped when the kit is not next to the repo)."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _run(kit, out, secret):
    env = dict(os.environ, RAKSHA_SECRET=secret, PYTHONIOENCODING="utf-8")
    r = subprocess.run([sys.executable, "main.py", "--input", str(kit / "dev" / "input"), "--output", str(out)],
                       cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8")
    return r


def _digest(out: Path) -> str:
    h = hashlib.sha256()
    for name in ("sanitized", "records.jsonl"):
        p = out / name
        for f in sorted(p.rglob("*")) if p.is_dir() else [p]:
            if f.is_file():
                h.update(f.relative_to(out).as_posix().encode() + f.read_bytes())
    return h.hexdigest()


@pytest.fixture(scope="module")
def runs(tmp_path_factory, request):
    kit = ROOT.parent / "Secret-Wards-ToolKit"
    if not (kit / "dev" / "input").is_dir():
        pytest.skip("kit not found")
    base = tmp_path_factory.mktemp("e2e")
    res = {}
    for tag, secret in (("a", "e2e-one"), ("b", "e2e-one"), ("c", "e2e-two")):
        out = base / tag
        r = _run(kit, out, secret)
        res[tag] = (out, r)
    return kit, res


def test_exit_zero_and_counts_only_on_stdout(runs):
    _, res = runs
    out, r = res["a"]
    assert r.returncode == 0
    assert r.stderr == ""
    assert r.stdout.startswith("medveil: files ") and r.stdout.count("\n") == 1


def test_deterministic_and_keyed(runs):
    _, res = runs
    assert _digest(res["a"][0]) == _digest(res["b"][0])
    assert _digest(res["a"][0]) != _digest(res["c"][0])


def test_secret_never_written(runs):
    _, res = runs
    out, r = res["a"]
    assert b"e2e-one" not in (r.stdout + r.stderr).encode()
    for f in out.rglob("*"):
        if f.is_file():
            assert b"e2e-one" not in f.read_bytes()


def test_every_input_file_accounted_for(runs):
    kit, res = runs
    out = res["a"][0]
    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    # multiset: the practice data has two byte-identical files, both must be listed
    shas = sorted(hashlib.sha256(p.read_bytes()).hexdigest() for p in (kit / "dev" / "input").rglob("*") if p.is_file())
    assert sorted(f["input_sha256"] for f in rep["files"]) == shas
    for f in rep["files"]:
        if f["status"] == "sanitized":
            assert (out / f["output"]).is_file()
    assert rep["counts"]["files_sanitized"] == sum(1 for f in rep["files"] if f["status"] == "sanitized")


def test_quarantine_never_copies_raw(runs):
    kit, res = runs
    out = res["a"][0]
    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    quarantined = {f["input_sha256"] for f in rep["files"] if f["status"] == "quarantined"}
    assert quarantined, "the practice data has malformed files that must be quarantined"
    for f in rep["files"]:
        if f["status"] == "quarantined":
            assert f["output"] is None and f.get("reason")
    raw_inputs = [p.read_bytes() for p in (kit / "dev" / "input").rglob("*")
                  if p.is_file() and hashlib.sha256(p.read_bytes()).hexdigest() in quarantined and p.stat().st_size > 40]
    for f in out.rglob("*"):
        if f.is_file():
            data = f.read_bytes()
            assert hashlib.sha256(data).hexdigest() not in quarantined
            # vault blobs are encrypted: no quarantined input appears inside any output file
            for raw in raw_inputs:
                assert raw[:40] not in data


def _record_text(path: Path, loc: str) -> str:
    """The text of one exported record: a CSV/TSV row, a JSON element, or the whole file."""
    import csv
    import io
    text = path.read_text(encoding="utf-8")
    if loc.startswith("row:"):
        delim = "\t" if path.suffix.lower() == ".tsv" else ","
        rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delim))
        return delim.join(rows[int(loc[4:]) + 1])
    if loc.startswith("/"):
        node = json.loads(text)
        for part in loc.strip("/").split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            node = node[int(part)] if isinstance(node, list) else node[part]
        return json.dumps(node, ensure_ascii=False)
    return text


def test_pseudonym_inside_every_linked_record(runs):
    _, res = runs
    out = res["a"][0]
    for line in (out / "records.jsonl").read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        if r["patient"]:
            assert r["patient"] in _record_text(out / r["file"], r["loc"]), (r["file"], r["loc"])
