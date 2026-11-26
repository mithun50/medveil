"""Dev only: list every generalization field the scorer checks, with input, output and score.

Prints raw truth, input and output values: run it on synthetic data only (the kit's practice
data or our generated sets), never on real records, and never in CI logs.

    python tools/gen_detail.py --output out_a [--kind district] [--zero]
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT.parent / "Secret-Wards-ToolKit"
_spec = importlib.util.spec_from_file_location("scorecard", ROOT / "tools" / "scorecard.py")
sc = importlib.util.module_from_spec(_spec)
sys.modules["scorecard"] = sc
_spec.loader.exec_module(sc)


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True)
    ap.add_argument("--input", default=str(KIT / "dev" / "input"))
    ap.add_argument("--truth", default=str(KIT / "dev" / "truth" / "truth.json"))
    ap.add_argument("--kind")
    ap.add_argument("--zero", action="store_true", help="only fields that score 0")
    ap.add_argument("--limit", type=int, default=40)
    ap.add_argument("--tokens", action="store_true", help="list the non-PII tokens lost (token retention)")
    a = ap.parse_args()
    truth = json.loads(Path(a.truth).read_text(encoding="utf-8"))
    kit = sc.guess_kit(Path(a.truth))
    if not (kit / "scoring.toml").is_file():
        kit = KIT
    cfg_path = kit / "scoring.toml"
    ctx = sc.Ctx(truth, Path(a.truth), Path(a.input), Path(a.output), sc.load_toml(cfg_path),
                 hashlib.sha256(cfg_path.read_bytes()).hexdigest(), kit)
    if a.tokens:
        lost, lost_files = Counter(), defaultdict(Counter)
        for rel in sorted(ctx.files):
            f = ctx.files[rel]
            ind, outd = ctx.in_doc(rel), ctx.out_doc(rel)
            if f.get("expect") == "either" or ind is None:
                continue
            cin = Counter(sc.tokens_of(sc.norm(ind.whole())))
            excl = Counter()
            for u in f["units"].values():
                for e in u.get("entities") or []:
                    excl.update(sc.tokens_of(sc.norm(e.get("surface"))))
                for x in u.get("exclude") or []:
                    excl.update(sc.tokens_of(sc.norm(x)))
            cin.subtract(excl)
            cin = +cin
            cout = Counter(sc.tokens_of(sc.norm(outd.whole()))) if outd is not None else Counter()
            for tok, c in cin.items():
                miss = c - min(c, cout.get(tok, 0))
                if miss:
                    lost[tok] += miss
                    lost_files[tok][rel] += miss
        print("tokens lost: %d (distinct %d)" % (sum(lost.values()), len(lost)))
        for tok, n in lost.most_common(a.limit):
            print("  %-24s %4d  %s" % (tok, n, ", ".join("%s(%d)" % kv for kv in lost_files[tok].most_common(3))))
        return 0
    by_kind = defaultdict(list)
    by_kind_file = defaultdict(Counter)
    rows = []
    for rel in sorted(ctx.files):
        ind, outd = ctx.in_doc(rel), ctx.out_doc(rel)
        for loc, u in ctx.files[rel]["units"].items():
            for fl in u.get("fields") or []:
                if not fl.get("path"):
                    continue
                s, bad, located = sc.field_score(ctx, rel, loc, u, fl)
                k = fl.get("kind")
                by_kind[k].append(s)
                by_kind_file[k][(rel, round(s, 2))] += 1
                iv = ind.field(loc, fl["path"]) if ind is not None else None
                ov = None
                if outd is not None:
                    oloc = ctx.out_loc(rel, loc)
                    if outd.locate(oloc)[0]:
                        ov = outd.field(oloc, fl["path"], ctx.col_fallback(rel, fl["path"]))
                rows.append((k, s, bad, located, rel, loc, fl.get("true"), iv, ov))
    print("kind      n     mean")
    for k, v in sorted(by_kind.items()):
        print("%-9s %4d  %.3f" % (k, len(v), sum(v) / len(v)))
    for k in sorted(by_kind_file):
        if a.kind and k != a.kind:
            continue
        print("\n%s by file and score:" % k)
        for (rel, s), n in sorted(by_kind_file[k].items()):
            print("   %-48s %.2f x %d" % (rel, s, n))
    shown = 0
    for k, s, bad, located, rel, loc, true, iv, ov in rows:
        if a.kind and k != a.kind:
            continue
        if a.zero and s > 0:
            continue
        if shown >= a.limit:
            break
        print("%-8s %.2f bad=%d loc=%d %s %s true=%r in=%r out=%r" % (k, s, bad, located, rel, loc, true, iv, ov))
        shown += 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
