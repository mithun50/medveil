#!/usr/bin/env python3
"""Dev-only diagnostics against the practice answer key.

Shows leaked entities with surrounding output text, lost medical probes, missed and
wrong links. Never imported by the pipeline.

    python tools/devcheck.py --output out_dev [--kit ../Secret-Wards-ToolKit] [--n 20]
"""
from __future__ import annotations

import argparse
import json
import sys
import unicodedata
from collections import defaultdict
from pathlib import Path


def norm(s: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", s).casefold().split())


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True)
    ap.add_argument("--kit", default=str(Path(__file__).resolve().parents[2] / "Secret-Wards-ToolKit"))
    ap.add_argument("--truth", default=None)
    ap.add_argument("--n", type=int, default=25)
    a = ap.parse_args()
    out = Path(a.output)
    truth = json.loads(Path(a.truth or Path(a.kit) / "dev" / "truth" / "truth.json").read_text(encoding="utf-8"))
    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    ren = {e["input_sha256"]: e["output"] for e in rep["files"]}
    recs = defaultdict(dict)
    for line in (out / "records.jsonl").read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        recs[r["file"].replace("sanitized/", "", 1)][r["loc"]] = r["patient"]
    leaks, lost = [], []
    units = []
    for rel, f in truth["files"].items():
        o = ren.get(f["sha256"])
        if not o:
            continue
        orel = o.replace("sanitized/", "", 1)
        p = out / "sanitized" / orel
        text = p.read_text(encoding="utf-8", errors="replace")
        nt = norm(text)
        for loc, u in f["units"].items():
            for e in u["entities"]:
                s = norm(e["surface"])
                hay = norm(orel) if e["channel"] == "filename" else nt
                if s and s in hay:
                    i = hay.find(s)
                    leaks.append((e["type"], e["script"], e["channel"], rel, e["surface"], hay[max(0, i - 50):i + 50]))
            for pv in u.get("preserve") or []:
                s = norm(pv["text"])
                if s not in nt:
                    lost.append((pv["kind"], rel, pv["text"]))
            if u.get("link") == "required" and u.get("patient"):
                mine = recs.get(orel, {}).get(loc)
                if mine is None and loc.startswith("/"):
                    parts = loc.split("/")
                    for i in range(len(parts) - 1, 1, -1):
                        anc = "/".join(parts[:i])
                        if anc in recs.get(orel, {}):
                            mine = recs[orel][anc]
                            break
                if mine is None:
                    mine = recs.get(orel, {}).get("doc")
                units.append((u["patient"], mine, rel, loc, u.get("tags")))
    print(f"LEAKS {len(leaks)}")
    for x in leaks[: a.n]:
        print("  ", x[:5], "\n      ...", x[5].replace("\n", " | "))
    print(f"\nLOST PROBES {len(lost)}")
    for x in lost[: a.n]:
        print("  ", x)
    by_true = defaultdict(set)
    by_mine = defaultdict(set)
    for t, m, rel, loc, tags in units:
        by_true[t].add(m)
        if m:
            by_mine[m].add(t)
    print("\nWRONG MERGES:", {m: sorted(ts) for m, ts in by_mine.items() if len(ts) > 1})
    split = {t: ms for t, ms in by_true.items() if len(ms) > 1}
    print(f"SPLIT PATIENTS {len(split)}")
    for t, ms in list(split.items())[: a.n]:
        sizes = defaultdict(list)
        for tt, m, rel, loc, tags in units:
            if tt == t:
                sizes[m].append(f"{rel}#{loc}{'/' + ','.join(tags) if tags else ''}")
        small = sorted(sizes.items(), key=lambda kv: len(kv[1]))
        print("  ", t, [(m, len(v)) for m, v in small])
        for m, v in small[:-1]:
            print("        ", m, v[:4])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
