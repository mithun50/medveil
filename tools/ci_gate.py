#!/usr/bin/env python3
"""CI quality gate: run the pipeline on a data set and fail on regressions.

    python tools/ci_gate.py --input <dir> --truth <truth.json> [--kit ../Secret-Wards-ToolKit]
        [--max-leaks 0] [--min-kept 0.95] [--min-recall 0.95] [--min-precision 0.99]

Fails when: the contract breaks, any canary or PII piece leaks, medical values kept
drop below the floor, any wrong merge appears, linking precision or recall drops below
its floor, a FHIR bundle fails the structural checks, no FHIR bundle was checked although
the input has FHIR, or one of the checker scripts crashes.

CI logs are public: the gate prints aggregate numbers and failure reasons only, never
the leaked text itself (check_dev.py runs without --show).
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TAIL = 300  # characters of a failing script's stderr kept in the message
FHIR_BUNDLE = re.compile(rb'"resourceType"\s*:\s*"Bundle"')
MAX_SCAN = 50 * 1024 * 1024

METRICS = {
    "leaks": re.compile(r"PERSONAL DATA: (\d+) of"),
    "canaries": re.compile(r"CANARIES: (\d+) of"),
    "kept": re.compile(r"MEDICAL DATA KEPT: (\d+) of (\d+)"),
    "linking": re.compile(r"precision ([\d.]+), recall ([\d.]+)"),
    "merges": re.compile(r"wrongly merge different people: (\d+)"),
}
LEAK_ROW = re.compile(r"^\s+([A-Z][A-Z_]+)\s+leaked\s+(\d+)\s*/\s*(\d+)", re.MULTILINE)
FHIR_SUMMARY = re.compile(r"FHIR bundles checked: (\d+), with problems: (\d+)")


def sh(cmd, env=None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8",
                          errors="replace")


def tail(s: str | None, n: int = TAIL) -> str:
    s = (s or "").strip()
    return ("..." + s[-n:]) if len(s) > n else s


def script_failure(name: str, r: subprocess.CompletedProcess) -> str:
    msg = f"{name} exited with code {r.returncode}"
    err = tail(r.stderr)
    return f"{msg}: {err}" if err else msg


def parse_check_dev(txt: str):
    """Aggregate numbers from check_dev.py stdout, or (None, missing names)."""
    found = {k: rx.search(txt) for k, rx in METRICS.items()}
    missing = [k for k, m in found.items() if m is None]
    if missing:
        return None, missing
    kept_m = found["kept"]
    prec, rec = (float(x) for x in found["linking"].groups())
    return {
        "leaks": int(found["leaks"].group(1)),
        "canaries": int(found["canaries"].group(1)),
        "kept": int(kept_m.group(1)) / max(1, int(kept_m.group(2))),
        "precision": prec,
        "recall": rec,
        "merges": int(found["merges"].group(1)),
    }, []


def input_has_fhir(inp: Path) -> bool:
    """True when the input has a fhir folder with files, or any file holding a FHIR Bundle."""
    for p in inp.rglob("*"):
        if not p.is_file():
            continue
        if any(part.lower() == "fhir" for part in p.relative_to(inp).parts[:-1]):
            return True
        try:
            with open(p, "rb") as fh:
                if FHIR_BUNDLE.search(fh.read(MAX_SCAN)):
                    return True
        except OSError:
            continue
    return False


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--truth", required=True)
    ap.add_argument("--kit", default=str(ROOT.parent / "Secret-Wards-ToolKit"))
    ap.add_argument("--max-leaks", type=int, default=0)
    ap.add_argument("--min-kept", type=float, default=0.95)
    ap.add_argument("--min-recall", type=float, default=0.95)
    ap.add_argument("--min-precision", type=float, default=0.99)
    a = ap.parse_args()
    kit = Path(a.kit)
    out = Path(tempfile.mkdtemp(prefix="medveil-gate-")) / "out"
    env = dict(os.environ, RAKSHA_SECRET="ci-gate", PYTHONIOENCODING="utf-8")
    failures = []
    leak_rows = []
    try:
        r = sh([sys.executable, "main.py", "--input", a.input, "--output", str(out)], env)
        print(r.stdout.strip())
        if r.returncode != 0:
            print("GATE FAIL:", script_failure("pipeline (main.py)", r))
            print("GATE FAILED")
            return 1

        v = sh([sys.executable, str(kit / "validate_output.py"), "--input", a.input, "--output", str(out)], env)
        if v.returncode != 0 or "CONTRACT OK" not in v.stdout:
            reason = tail(v.stdout) or tail(v.stderr) or f"exit code {v.returncode}"
            if v.returncode not in (0, 1):
                reason = script_failure("validate_output.py", v)
            failures.append("contract: " + reason)

        c = sh([sys.executable, str(kit / "check_dev.py"), "--output", str(out), "--truth", a.truth], env)
        m, missing = (None, []) if c.returncode != 0 else parse_check_dev(c.stdout)
        if c.returncode != 0:
            failures.append(script_failure("check_dev.py", c))
        elif m is None:
            failures.append("check_dev.py output not understood (missing: " + ", ".join(missing) + ")"
                            + (": " + tail(c.stderr) if c.stderr.strip() else ""))
        else:
            leak_rows = [(t, int(n), int(of)) for t, n, of in LEAK_ROW.findall(c.stdout) if int(n)]
            print(f"leaks={m['leaks']} canaries={m['canaries']} kept={m['kept']:.3f} "
                  f"precision={m['precision']:.2f} recall={m['recall']:.2f} merges={m['merges']}")
            if m["leaks"] > a.max_leaks:
                failures.append(f"{m['leaks']} PII pieces leaked (max {a.max_leaks})")
            if m["canaries"]:
                failures.append(f"{m['canaries']} canaries leaked")
            if m["kept"] < a.min_kept:
                failures.append(f"medical values kept {m['kept']:.3f} < {a.min_kept}")
            if m["merges"]:
                failures.append(f"{m['merges']} wrong merges")
            if m["precision"] < a.min_precision:
                failures.append(f"linking precision {m['precision']:.2f} < {a.min_precision}")
            if m["recall"] < a.min_recall:
                failures.append(f"linking recall {m['recall']:.2f} < {a.min_recall}")

        f = sh([sys.executable, "tools/fhir_validate.py", str(out / "sanitized")], env)
        summary = FHIR_SUMMARY.search(f.stdout)
        expect_fhir = input_has_fhir(Path(a.input) if Path(a.input).is_absolute() else ROOT / a.input)
        if f.returncode not in (0, 1) or summary is None:
            failures.append(script_failure("fhir_validate.py", f) + (" (no summary line)" if summary is None else ""))
        else:
            checked, bad = int(summary.group(1)), int(summary.group(2))
            print(summary.group(0) + ("" if expect_fhir else " (input has no FHIR)"))
            if f.returncode or bad:
                failures.append(f"FHIR structural problems in {bad} of {checked} bundles")
                # paths are under the temporary output and carry sanitized names only
                for line in f.stdout.strip().splitlines()[:-1][:40]:
                    print("  fhir:", line.replace(str(out), "<out>"))
            if checked == 0 and expect_fhir:
                failures.append("no FHIR bundle was checked although the input has FHIR")
        if failures and leak_rows:
            print("leaked pieces by type: " + ", ".join(f"{t} {n}/{of}" for t, n, of in leak_rows))
    finally:
        shutil.rmtree(out.parent, ignore_errors=True)
    for x in failures:
        print("GATE FAIL:", x)
    print("GATE OK" if not failures else "GATE FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
