#!/usr/bin/env python3
"""CI quality gate: run the pipeline on a data set and fail on regressions.

    python tools/ci_gate.py --input <dir> --truth <truth.json> [--kit ../Secret-Wards-ToolKit]

Fails when: the contract breaks, any canary or PII piece leaks, medical values kept
drop below the floor, any wrong merge appears, linking recall drops below the floor,
or a FHIR bundle fails the structural checks.
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


def sh(cmd, env=None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8")


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--truth", required=True)
    ap.add_argument("--kit", default=str(ROOT.parent / "Secret-Wards-ToolKit"))
    ap.add_argument("--max-leaks", type=int, default=0)
    ap.add_argument("--min-kept", type=float, default=0.95)
    ap.add_argument("--min-recall", type=float, default=0.95)
    a = ap.parse_args()
    kit = Path(a.kit)
    out = Path(tempfile.mkdtemp(prefix="medveil-gate-")) / "out"
    env = dict(os.environ, RAKSHA_SECRET="ci-gate", PYTHONIOENCODING="utf-8")
    failures = []
    try:
        r = sh([sys.executable, "main.py", "--input", a.input, "--output", str(out)], env)
        print(r.stdout.strip())
        if r.returncode != 0:
            print(r.stderr)
            return 1
        v = sh([sys.executable, str(kit / "validate_output.py"), "--input", a.input, "--output", str(out)], env)
        if "CONTRACT OK" not in v.stdout:
            failures.append("contract: " + v.stdout.strip()[-300:])
        c = sh([sys.executable, str(kit / "check_dev.py"), "--output", str(out), "--truth", a.truth, "--show", "10"], env)
        txt = c.stdout
        leaks = int(re.search(r"PERSONAL DATA: (\d+) of", txt).group(1))
        canaries = int(re.search(r"CANARIES: (\d+) of", txt).group(1))
        kept_m = re.search(r"MEDICAL DATA KEPT: (\d+) of (\d+)", txt)
        kept = int(kept_m.group(1)) / max(1, int(kept_m.group(2)))
        prec, rec = (float(x) for x in re.search(r"precision ([\d.]+), recall ([\d.]+)", txt).groups())
        merges = int(re.search(r"wrongly merge different people: (\d+)", txt).group(1))
        print(f"leaks={leaks} canaries={canaries} kept={kept:.3f} precision={prec:.2f} recall={rec:.2f} merges={merges}")
        if leaks > a.max_leaks:
            failures.append(f"{leaks} PII pieces leaked")
        if canaries:
            failures.append(f"{canaries} canaries leaked")
        if kept < a.min_kept:
            failures.append(f"medical values kept {kept:.3f} < {a.min_kept}")
        if merges:
            failures.append(f"{merges} wrong merges")
        if rec < a.min_recall:
            failures.append(f"linking recall {rec:.2f} < {a.min_recall}")
        f = sh([sys.executable, "tools/fhir_validate.py", str(out / "sanitized")], env)
        print(f.stdout.strip().splitlines()[-1] if f.stdout.strip() else "no FHIR")
        if f.returncode:
            failures.append("FHIR structural problems")
        if failures:
            print(txt)
    finally:
        shutil.rmtree(out.parent, ignore_errors=True)
    for x in failures:
        print("GATE FAIL:", x)
    print("GATE OK" if not failures else "GATE FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
