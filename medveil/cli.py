"""MedVeil command line: python main.py --input <dir> --output <dir>.

Pipeline: inventory and parse -> learn -> detect -> evidence -> link -> propagate
names -> privacy plan -> rewrite -> leak gate -> write, report.json, records.jsonl.
Only counts are printed. Exit 0 means every input file is accounted for.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

from . import guard
from .crypto import Keys, Vault
from .detect.engine import Knowledge, detect_slot, ident_tokens, learn_doc, resolve
from .detect.fields import classify_header, classify_key
from .detect.patterns import in_protected
from .gate import Ledger, scrub
from .ingest import build_slots, sniff_and_parse
from .link import extract_evidence, link
from .model import PII_TYPES, Doc, Quarantine, Record, Span
from .policy import load as load_policy
from .privacy import plan_bands, shift_for
from .rewrite import Ctx, district_name, place_psn, rename_file, rewrite_record, serialize
from .translit import key, tokens_match

ROOT = Path(__file__).resolve().parents[1]
WORD = re.compile(r"[A-Za-z][A-Za-z'\-]*|[\u0900-\u0963\u0966-\u097F]+")


def _peak_rss_mb() -> float:
    try:
        import resource
        r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(r / 1024 if sys.platform != "darwin" else r / 1048576, 1)
    except Exception:  # noqa: BLE001 - not available on Windows
        try:
            import psutil
            return round(psutil.Process().memory_info().peak_wset / 1048576, 1)
        except Exception:  # noqa: BLE001
            return 0.0


def _file_tokens(rel: str) -> set[str]:
    name = rel.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    return {t.lower() for t in re.findall(r"[A-Za-z]{3,}", name)}


def infer_date_orders(docs: list[Doc]) -> None:
    votes: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for d in docs:
        dm, md = d.date_votes
        for t in d.tokens:
            votes[t][0] += dm
            votes[t][1] += md
    for d in docs:
        dm, md = d.date_votes
        if md > dm:
            d.date_order = "mdy"
            continue
        if dm > md:
            d.date_order = "dmy"
            continue
        g_dm = g_md = 0
        for t in sorted(d.tokens):
            a, b = votes[t]
            if a + b >= 2 and (a == 0 or b == 0):
                g_dm += a
                g_md += b
        d.date_order = "mdy" if g_md > g_dm else "dmy"


def propagate(rec: Record, pat: list[str], rel: list[str]) -> None:
    """Second pass: remove this patient's name tokens wherever they appear in the record."""
    if not pat and not rel:
        return
    for sl in rec.slots:
        if sl.kind not in ("value", "text") or sl.number:
            continue
        if sl.ftype in ("DOCTOR",) or not sl.text:
            continue
        text = sl.text
        new = []
        for m in WORD.finditer(text):
            w = m.group(0)
            if w[0].isascii() and not (w[0].isupper()):
                nxt = text[m.end():m.end() + 10].lower()
                if not re.match(r"\s+(?:ji|sahab|bhai|behenji|didi|amma|bhaiya)\b", nxt):
                    continue
            k = key(w)
            if len(k) < 3:
                continue
            role = None
            if any(tokens_match(k, p, 0.93) for p in pat):
                role = "patient"
            elif any(tokens_match(k, r, 0.93) for r in rel):
                role = "relative"
            if role is None:
                continue
            s, e = m.start(), m.end()
            if in_protected(sl.protected, s, e) or any(sp.start < e and s < sp.end for sp in sl.spans):
                continue
            new.append(Span(s, e, "NAME", role=role, value=w, conf=0.8, rule="propagate"))
        if new:
            sl.spans = resolve(sl.spans + new)


def _clean_path(s: str) -> Path:
    s = s.strip()
    # cmd.exe passes POSIX-style quoting through literally: 'C:\path' -> strip it
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        s = s[1:-1]
    return Path(s).resolve()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="medveil", description="Offline privacy firewall for hospital records")
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--policy", default=str(ROOT / "config" / "policy.yaml"))
    a = ap.parse_args(argv)
    t0 = time.monotonic()
    guard.install_hooks()
    guard.block_network()
    secret = guard.take_secret()
    if not secret:
        sys.stderr.write("medveil: RAKSHA_SECRET is not set\n")
        return 2
    keys = Keys(secret, guard.take_vault_secret())
    del secret
    policy = load_policy(Path(a.policy))
    inp = _clean_path(a.input)
    out = _clean_path(a.output)
    if not inp.is_dir():
        sys.stderr.write("medveil: input folder not found\n")
        return 2
    if out == inp or inp in out.parents:
        sys.stderr.write("medveil: output must not be inside input\n")
        return 2
    out.mkdir(parents=True, exist_ok=True)
    san = out / "sanitized"
    san.mkdir(exist_ok=True)
    vault = Vault(out / "quarantine", keys.vault) if policy["quarantine"].get("vault") == "encrypted" else None

    # 1. inventory and parse -------------------------------------------------------
    paths = sorted((p for p in inp.rglob("*") if p.is_file()), key=lambda p: p.relative_to(inp).as_posix())
    docs: list[Doc] = []
    for p in paths:
        rel = p.relative_to(inp).as_posix()
        raw = p.read_bytes()
        doc = Doc(rel=rel, sha256=hashlib.sha256(raw).hexdigest())
        try:
            sniff_and_parse(doc, raw, policy)
            build_slots(doc, classify_header, classify_key)
            doc.status = "parsed"
        except Quarantine as q:
            doc.status, doc.reason = "quarantined", q.reason
        except Exception:  # noqa: BLE001 - any parser failure means we cannot clean it safely
            doc.status, doc.reason = "quarantined", "handler_error"
        if doc.status == "quarantined" and vault is not None:
            vault.put(doc.sha256, raw, doc.reason)
        doc.tokens = _file_tokens(rel)
        docs.append(doc)
    live = [d for d in docs if d.status == "parsed"]

    # 2. learn ---------------------------------------------------------------------
    K = Knowledge()
    for d in live:
        learn_doc(d, K)
    K.finalize()
    for d in live:
        for rec in d.records:
            for sl in rec.slots:
                if sl.ftype == "MRN" and sl.text:
                    m = re.match(r"[A-Za-z]{2,6}", sl.text.strip())
                    if m:
                        d.tokens.add("id:" + m.group(0).upper())
    infer_date_orders(live)

    # 3. detect --------------------------------------------------------------------
    for d in live:
        try:
            for rec in d.records:
                for sl in rec.slots:
                    detect_slot(sl, K, d, file_level=(rec.loc == "@file"))
            for fs in d.file_slots:
                detect_slot(fs, K, d, file_level=True)
        except Exception:  # noqa: BLE001
            d.status, d.reason = "quarantined", "handler_error"
    live = [d for d in live if d.status == "parsed"]

    # 4. evidence and linking --------------------------------------------------------
    recs: list[tuple[Doc, Record]] = []
    for d in live:
        for rec in d.records:
            if rec.loc == "@file":
                continue
            extract_evidence(rec, d)
            recs.append((d, rec))
    all_dates = [x for _, r in recs for x in r.dates]
    default_ref = max(all_dates) if all_dates else dt.date(2000, 1, 1)
    clusters = link([r for _, r in recs], default_ref)

    # 5. privacy plan per cluster ---------------------------------------------------
    plen = int(policy["pseudonym"].get("length", 8))
    profiles: dict[str, dict] = {}
    rec_canon: dict[int, str] = {}
    cluster_psn: dict[str, str] = {}
    used_psn: set[str] = set()
    cluster_names: dict[str, tuple[list, list]] = {}
    for root in sorted(clusters):
        members = clusters[root]
        ids = sorted({f"{k}:{v}" for i in members for k, v in recs[i][1].ev.ids})
        canon = ids[0] if ids else "rec:" + min(f"{recs[i][0].rel}#{recs[i][1].loc}" for i in members)
        salt = 0
        psn = keys.pseudonym(canon, plen)
        while psn in used_psn:
            salt += 1
            psn = keys.pseudonym(canon, plen, salt)
        used_psn.add(psn)
        cluster_psn[canon] = psn
        ages, genders, districts = [], Counter(), Counter()
        pat, rel = set(), set()
        for i in members:
            ev = recs[i][1].ev
            ages += ev.ages
            genders.update(ev.genders)
            districts.update(ev.districts)
            for n in ev.names:
                pat.update(ident_tokens(list(n)))
            for n in ev.relatives:
                rel.update(ident_tokens(list(n)))
            rec_canon[i] = canon
        profiles[canon] = {"ages": ages, "gender": genders.most_common(1)[0][0] if len(genders) == 1 else None,
                           "district": districts.most_common(1)[0][0] if districts else None}
        cluster_names[canon] = (sorted(pat), sorted(rel - pat))
    for i, (d, r) in enumerate(recs):
        if i not in rec_canon:
            canon = f"unlinked:{d.rel}#{r.loc}"
            rec_canon[i] = canon
            ev = r.ev
            profiles[canon] = {"ages": list(ev.ages), "gender": next(iter(ev.genders)) if len(ev.genders) == 1 else None,
                               "district": next(iter(sorted(ev.districts)), None)}
    bands = plan_bands(profiles, policy)
    top = int(policy["age"].get("top_code", 80))

    # 6. propagate cluster names, then rewrite -------------------------------------
    for i, (_d, r) in enumerate(recs):
        canon = rec_canon[i]
        if canon in cluster_names:
            pat, rel = cluster_names[canon]
            propagate(r, pat, rel)
    mrn_psn: dict[str, str] = {}
    for i, (_d, r) in enumerate(recs):
        psn = cluster_psn.get(rec_canon[i])
        if psn:
            for k, v in r.ev.ids:
                if k == "mrn":
                    mrn_psn.setdefault(v, psn)
    counts = Counter()
    entity_counts = Counter()
    records_out = []
    used_names: set[str] = set()
    pin_digits = int(policy["location"].get("pin_prefix_digits", 3))
    rec_index = {id(r): i for i, (_, r) in enumerate(recs)}
    for d in live:
        try:
            ledger = Ledger()
            for rec in d.records:
                i = rec_index.get(id(rec))
                canon = rec_canon.get(i) if i is not None else f"file:{d.rel}"
                psn = cluster_psn.get(canon)
                rec.psn = psn
                pat, rel = cluster_names.get(canon, ([], []))
                ctx = Ctx(psn=psn, rec_token=keys.opaque(f"{d.rel}#{rec.loc}"),
                          shift=shift_for(keys, canon, policy), band=bands.get(canon), top=top,
                          district=district_name(rec), pat_tokens=pat, rel_tokens=rel, mrn_psn=mrn_psn,
                          pin_digits=pin_digits)
                rewrite_record(rec, ctx)
                if rec.loc != "@file":
                    place_psn(rec, ctx, d)
                for sl in rec.slots:
                    for sp in sl.spans:
                        if sp.etype in PII_TYPES:
                            entity_counts[sp.etype] += 1
                            ledger.add_span(sp.etype, sl.text[sp.start:sp.end], sp.value)
                        if sp.etype in ("AGE", "DOB", "VILLAGE", "TEHSIL", "PIN"):
                            rec.generalized = True
            fctx = Ctx(psn=None, rec_token=keys.opaque(f"{d.rel}#@file"), shift=shift_for(keys, f"file:{d.rel}", policy),
                       band=None, top=top, district=None, mrn_psn=mrn_psn, pin_digits=pin_digits)
            for fs in d.file_slots:
                if fs.kind == "header":
                    from .rewrite import apply
                    fs.out = apply(fs, fctx)
                    if fs.out is not None:
                        fs.out = re.sub(r"\[(?:PERSON|PATIENT|RELATIVE)\]", "", fs.out).strip() or "[PATIENT]"
                for sp in fs.spans:
                    if sp.etype in PII_TYPES:
                        entity_counts[sp.etype] += 1
                        ledger.add_span(sp.etype, fs.text[sp.start:sp.end], sp.value)
            text = serialize(d)
            text, hits = scrub(text, ledger)
            counts["gate_hits"] += hits
            if hits:
                # second check: the scrubbed output must be clean, or the file is quarantined
                _, again = scrub(text, ledger)
                if again:
                    raise Quarantine("residual_pii")
            if d.fmt in ("json", "fhir"):
                json.loads(text)
            new_rel = rename_file(d, keys.opaque(d.rel))
            if new_rel in used_names:
                stem, dot, ext = new_rel.rpartition(".")
                new_rel = f"{stem}_{keys.opaque(d.rel + '#dup', 4)}.{ext}" if dot else new_rel + "_" + keys.opaque(d.rel, 4)
            used_names.add(new_rel)
            dest = san / new_rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(text, encoding="utf-8", newline="")
            d.out_rel = new_rel
            d.status = "sanitized"
            for rec in d.records:
                if rec.loc == "@file":
                    continue
                records_out.append({"file": f"sanitized/{new_rel}", "loc": rec.loc, "patient": rec.psn,
                                    "_g": rec.generalized})
        except Quarantine as q:
            d.status, d.reason = "quarantined", q.reason
        except Exception:  # noqa: BLE001
            d.status, d.reason = "quarantined", "handler_error"
    if vault is not None:
        vault.close()

    # 7. records.jsonl and report.json -------------------------------------------------
    records_out.sort(key=lambda r: (r["file"], _loc_key(r["loc"])))
    with open(out / "records.jsonl", "w", encoding="utf-8", newline="\n") as fh:
        for r in records_out:
            fh.write(json.dumps({"file": r["file"], "loc": r["loc"], "patient": r["patient"]},
                                ensure_ascii=False, sort_keys=True) + "\n")
    files = []
    for d in docs:
        if d.status == "sanitized":
            files.append({"input_sha256": d.sha256, "output": f"sanitized/{d.out_rel}", "status": "sanitized"})
        else:
            files.append({"input_sha256": d.sha256, "output": None, "status": "quarantined",
                          "reason": d.reason or "unsupported_format"})
    n_san = sum(1 for f in files if f["status"] == "sanitized")
    report = {
        "schema": "raksha-report/1",
        "files": files,
        "counts": {
            "files_total": len(files),
            "files_sanitized": n_san,
            "files_quarantined": len(files) - n_san,
            "records_processed": len(records_out),
            "identifiers_detected": int(sum(entity_counts.values()) + counts["gate_hits"]),
            "records_linked": sum(1 for r in records_out if r["patient"]),
            "records_generalized": sum(1 for r in records_out if r["_g"]),
            "records_suppressed": 0,
            "records_quarantined": 0,
        },
        "entities": dict(sorted(entity_counts.items())),
        "timing": {"seconds": round(time.monotonic() - t0, 2)},
        "resources": {"peak_rss_mb": _peak_rss_mb()},
    }
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"medveil: files {len(files)} sanitized {n_san} quarantined {len(files) - n_san} "
          f"records {len(records_out)} linked {report['counts']['records_linked']}")
    return 0


def _loc_key(loc: str):
    if loc.startswith("row:"):
        return (0, int(loc[4:]), "")
    return (1, 0, loc)
