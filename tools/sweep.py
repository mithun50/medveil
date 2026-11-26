#!/usr/bin/env python3
"""Dev-only policy sweep: privacy risk (tools/redteam.py) versus utility (check_dev.py).

Runs the pipeline once per policy variant on the practice data, attacks each release,
and prints one row per variant. Never part of `run`.

    python tools/sweep.py [--kit ../Secret-Wards-ToolKit]
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

VARIANTS = {
    "district, k-fallback state": {},
    "district, k3 fallback": {"location": {"k_patients": 3}},
    "20y, k3 fallback": {"age": {"ladder": [20]}, "location": {"k_patients": 3}},
    "k3 age and location": {"age": {"k_patients": 3}, "location": {"k_patients": 3}},
    "district, no fallback": {"location": {"k_patients": 0}},
    "20y, k-fallback state": {"age": {"ladder": [20]}},
    "state everywhere": {"location": {"keep_level": "state"}},
    "rare3": {"rare_values": {"max_profiles_rare": 3}},
    "no rare-values": {"rare_values": {"enabled": False}},
}


def run(cmd, env=None):
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", env=env, cwd=ROOT)


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--kit", default=str(ROOT.parent / "Secret-Wards-ToolKit"))
    ap.add_argument("--only", default="")
    a = ap.parse_args()
    kit = Path(a.kit)
    base = yaml.safe_load((ROOT / "config" / "policy.yaml").read_text(encoding="utf-8"))
    work = Path(tempfile.mkdtemp(prefix="medveil-sweep-"))
    print(f"{'variant':<26} {'risk':>7} {'pts':>6} {'A2/3':>6} {'A4':>6} {'A5':>6} {'kept':>6} {'leaks':>6}")
    try:
        for name, over in VARIANTS.items():
            if a.only and a.only not in name:
                continue
            pol = json.loads(json.dumps(base))
            for k, v in over.items():
                pol.setdefault(k, {}).update(v)
            pfile = work / "policy.yaml"
            pfile.write_text(yaml.safe_dump(pol), encoding="utf-8")
            outs = []
            for sec in ("sweep-a", "sweep-b"):
                out = work / f"out_{sec}"
                shutil.rmtree(out, ignore_errors=True)
                env = dict(os.environ, RAKSHA_SECRET=sec, PYTHONIOENCODING="utf-8")
                r = run([sys.executable, "main.py", "--input", str(kit / "dev" / "input"), "--output", str(out),
                         "--policy", str(pfile)], env)
                if r.returncode:
                    print(name, "pipeline failed")
                    break
                outs.append(out)
            rj = work / "rt.json"
            run([sys.executable, "tools/redteam.py", "--output", str(outs[0]), "--other", str(outs[1]),
                 "--kit", str(kit), "--json", str(rj)])
            res = json.loads(rj.read_text(encoding="utf-8"))
            cd = run([sys.executable, str(kit / "check_dev.py"), "--output", str(outs[0])]).stdout
            kept = re.search(r"MEDICAL DATA KEPT: (\d+) of (\d+)", cd)
            leak = re.search(r"PERSONAL DATA: (\d+) of", cd)
            o = res.get("ours", res)
            raw = res.get("raw", {})

            def ratio(k, o=o, raw=raw):
                rv = raw.get(k) or 1.0
                return (o.get(k) or 0.0) / rv

            risk = res.get("overall_risk", o.get("overall_risk"))
            print(f"{name:<26} {risk if risk is not None else float('nan'):>7.3f} "
                  f"{25 * (1 - (risk or 0)):>6.2f} {ratio('record_linkage_risk'):>6.3f} "
                  f"{ratio('patients_reidentified'):>6.3f} {ratio('targeted_success'):>6.3f} "
                  f"{int(kept.group(1)) / int(kept.group(2)) if kept else 0:>6.3f} {leak.group(1) if leak else '?':>6}")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
