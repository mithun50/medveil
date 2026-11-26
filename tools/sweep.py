#!/usr/bin/env python3
"""Dev-only policy sweep: privacy risk (tools/redteam.py) versus utility (check_dev.py).

Runs the pipeline once per policy variant on the practice data, attacks each release,
and prints one row per variant. Never part of `run`.

    python tools/sweep.py [--kit ../Secret-Wards-ToolKit] [--only NAME]

--only runs the variant with exactly that name, or else every variant whose name
contains the text ("--only k=3" runs just "k=3"; "--only 20y" runs both 20y rows).

Every variant sets all seven swept keys explicitly, so a row never inherits a value from
config/policy.yaml and two rows cannot silently be the same policy. In the names, "k=N"
is location.k_patients (fewer than N patients sharing gender, age band and district
publish only the state); age.k_patients is 2 unless the name says "age k=3"; the age
ladder is [10, 20] unless the name says "20y"; rare-value generalization is on with
max_profiles_rare 2 unless the name says otherwise; age.k_condition (condition-aware
band widening) is 3 unless the name says "cond-age". "k=3" is the shipped policy.

Columns "util" and "total" are tools/scorecard.py estimates (utility points of 20, total
of 100), so a privacy gain can be weighed against what it costs elsewhere.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def variant(ladder=(10, 20), age_k=2, loc_k=3, keep="district", rare=True, rare_max=2, k_cond=3) -> dict:
    return {"age": {"ladder": list(ladder), "k_patients": age_k, "k_condition": k_cond},
            "location": {"k_patients": loc_k, "keep_level": keep},
            "rare_values": {"enabled": rare, "max_profiles_rare": rare_max}}


VARIANTS = {
    "k=3": variant(loc_k=3),
    "k=3, no cond-age": variant(loc_k=3, k_cond=0),
    "k=3, cond-age k2": variant(loc_k=3, k_cond=2),
    "k=3, cond-age k4": variant(loc_k=3, k_cond=4),
    "k=2": variant(loc_k=2),
    "k=0 (no state fallback)": variant(loc_k=0),
    "20y, k=3": variant(ladder=(20,), loc_k=3),
    "age k=3, k=3": variant(age_k=3, loc_k=3),
    "state everywhere, k=3": variant(loc_k=3, keep="state"),
    "k=3, rare<=3": variant(loc_k=3, rare_max=3),
    "k=3, no rare-values": variant(loc_k=3, rare=False),
}


def run(cmd, env=None):
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          env=env, cwd=ROOT)


def why(r: subprocess.CompletedProcess) -> str:
    err = (r.stderr or "").strip().replace("\n", " | ")
    return f"exit {r.returncode}" + (f": {err[-200:]}" if err else "")


def selected(only: str) -> list[str]:
    if not only:
        return list(VARIANTS)
    if only in VARIANTS:
        return [only]
    return [n for n in VARIANTS if only in n]


def run_variant(i: int, name: str, over: dict, base: dict, kit: Path, work: Path):
    """Returns (result dict, None) or (None, failure reason)."""
    pol = json.loads(json.dumps(base))
    for k, v in over.items():
        pol.setdefault(k, {}).update(v)
    pfile = work / f"policy_{i}.yaml"
    pfile.write_text(yaml.safe_dump(pol), encoding="utf-8")
    outs = []
    for sec in ("sweep-a", "sweep-b"):
        out = work / f"out_{i}_{sec}"
        shutil.rmtree(out, ignore_errors=True)
        env = dict(os.environ, RAKSHA_SECRET=sec, PYTHONIOENCODING="utf-8")
        r = run([sys.executable, "main.py", "--input", str(kit / "dev" / "input"), "--output", str(out),
                 "--policy", str(pfile)], env)
        if r.returncode or not (out / "report.json").is_file():
            return None, f"pipeline ({sec}) {why(r)}"
        outs.append(out)
    rj = work / f"rt_{i}.json"
    rj.unlink(missing_ok=True)
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    r = run([sys.executable, "tools/redteam.py", "--output", str(outs[0]), "--other", str(outs[1]),
             "--kit", str(kit), "--json", str(rj)], env)
    if r.returncode or not rj.is_file():
        return None, f"redteam {why(r)}"
    try:
        res = json.loads(rj.read_text(encoding="utf-8"))
    except ValueError as exc:
        return None, f"redteam wrote unreadable JSON ({exc})"
    cd = run([sys.executable, str(kit / "check_dev.py"), "--output", str(outs[0])], env)
    kept = re.search(r"MEDICAL DATA KEPT: (\d+) of (\d+)", cd.stdout)
    leak = re.search(r"PERSONAL DATA: (\d+) of", cd.stdout)
    if cd.returncode or not kept or not leak:
        return None, f"check_dev {why(cd)}" if cd.returncode else "check_dev output not understood"
    # Whole-score estimate (tools/scorecard.py), reusing the red-team result above.
    sj = work / f"sc_{i}.json"
    sj.unlink(missing_ok=True)
    r = run([sys.executable, "tools/scorecard.py", "--output", str(outs[0]), "--other", str(outs[1]),
             "--input", str(kit / "dev" / "input"), "--truth", str(kit / "dev" / "truth" / "truth.json"),
             "--redteam-json", str(rj), "--json", str(sj)], env)
    score = None
    if sj.is_file():
        try:
            score = json.loads(sj.read_text(encoding="utf-8"))
        except ValueError:
            score = None
    for out in outs:
        shutil.rmtree(out, ignore_errors=True)
    return {"res": res, "kept": int(kept.group(1)) / max(1, int(kept.group(2))), "leaks": leak.group(1),
            "score": score}, None


def _total(row) -> str:
    s = row.get("score") or {}
    return f"{s['total']:.2f}" if isinstance(s.get("total"), (int, float)) else "-"


def _util(row) -> str:
    cats = (row.get("score") or {}).get("categories")
    for c in cats if isinstance(cats, list) else []:
        if isinstance(c, dict) and c.get("key") == "utility" and isinstance(c.get("points"), (int, float)):
            return f"{c['points']:.2f}"
    if isinstance(cats, dict) and isinstance((cats.get("utility") or {}).get("points"), (int, float)):
        return f"{cats['utility']['points']:.2f}"
    return "-"


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--kit", default=str(ROOT.parent / "Secret-Wards-ToolKit"))
    ap.add_argument("--only", default="")
    a = ap.parse_args()
    kit = Path(a.kit)
    names = selected(a.only)
    if not names:
        print(f"no variant matches {a.only!r}; choose from: " + "; ".join(VARIANTS))
        return 2
    base = yaml.safe_load((ROOT / "config" / "policy.yaml").read_text(encoding="utf-8"))
    work = Path(tempfile.mkdtemp(prefix="medveil-sweep-"))
    failed = 0
    print(f"{'variant':<26} {'risk':>7} {'pts':>6} {'A2/3':>6} {'A4':>6} {'A5':>6} {'kept':>6} {'leaks':>6}"
          f" {'util':>6} {'total':>6}")
    try:
        for i, name in enumerate(VARIANTS):
            if name not in names:
                continue
            row, err = run_variant(i, name, VARIANTS[name], base, kit, work)
            if err:
                failed += 1
                print(f"{name} FAILED: {err}")
                continue
            res = row["res"]
            o = res.get("ours", res)
            raw = res.get("raw", {})

            def ratio(k, o=o, raw=raw):
                rv = raw.get(k) or 1.0
                return (o.get(k) or 0.0) / rv

            risk = res.get("overall_risk", o.get("overall_risk"))
            print(f"{name:<26} {risk if risk is not None else float('nan'):>7.3f} "
                  f"{25 * (1 - (risk or 0)):>6.2f} {ratio('record_linkage_risk'):>6.3f} "
                  f"{ratio('patients_reidentified'):>6.3f} {ratio('targeted_success'):>6.3f} "
                  f"{row['kept']:>6.3f} {row['leaks']:>6} {_util(row):>6} {_total(row):>6}")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
