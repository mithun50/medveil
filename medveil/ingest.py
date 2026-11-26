"""Ingestion: decoding, format sniffing and parsing into documents with slots.

Format is decided by content, the output path follows the input. Anything that is
binary, markup, malformed, too deep or undecodable raises Quarantine with a reason code.
"""
from __future__ import annotations

import csv
import io
import json
import math
import re
from functools import lru_cache

from .model import Doc, Quarantine, Record, Slot
from .textnorm import b64_text, normalize

MAGIC = (b"%PDF", b"\xff\xd8\xff", b"\x89PNG", b"PK\x03\x04", b"PK\x05\x06", b"\x1f\x8b", b"\xd0\xcf\x11\xe0",
         b"GIF8", b"RIFF", b"\x00\x00\x01\x00", b"Rar!", b"7z\xbc\xaf", b"ID3", b"OggS", b"\x7fELF",
         b"MZ\x90\x00", b"BZh", b"\xfd7zXZ", b"\x28\xb5\x2f\xfd", b"SQLite format 3", b"\x00asm",
         # Mach-O 32/64-bit in both byte orders, and universal ("fat") binaries in both orders
         b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
         b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")
MOJIBAKE = re.compile("Ã[\x80-\xbf\u0080-\u00ff]|â€|Â[\u00a0-\u00bf]|ï¿½|ÿþ|þÿ")
CSV_EXT = {".csv": ",", ".tsv": "\t", ".tab": "\t", ".psv": "|"}
JSON_EXT = {".json", ".fhir", ".geojson"}
TEXT_OK_EXT = {".txt", ".text", ".log", ".md", ".note", ".notes", ""}


def decode(raw: bytes) -> tuple[str, str]:
    if raw.startswith(b"\xef\xbb\xbf"):
        try:
            return raw[3:].decode("utf-8"), "utf-8-sig"
        except UnicodeDecodeError:
            raise Quarantine("undecodable_text") from None
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return raw.decode("utf-16"), "utf-16"
        except UnicodeDecodeError:
            raise Quarantine("undecodable_text") from None
    head = raw[:4000]
    if len(head) >= 8:
        odd = head[1::2].count(0)
        even = head[0::2].count(0)
        half = len(head) // 2
        if odd > 0.4 * half and even < 0.05 * half:
            try:
                return raw.decode("utf-16-le"), "utf-16-le"
            except UnicodeDecodeError:
                raise Quarantine("undecodable_text") from None
        if even > 0.4 * half and odd < 0.05 * half:
            try:
                return raw.decode("utf-16-be"), "utf-16-be"
            except UnicodeDecodeError:
                raise Quarantine("undecodable_text") from None
    try:
        return raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass
    try:
        text = raw.decode("cp1252")
    except UnicodeDecodeError:
        raise Quarantine("undecodable_text") from None
    if MOJIBAKE.search(text):
        # UTF-8 with corrupt bytes, or double-encoded text: not safe to guess.
        raise Quarantine("undecodable_text")
    return text, "cp1252"


_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def _control_ratio(text: str) -> float:
    sample = text[:20000]
    if not sample:
        return 0.0
    return len(_CTRL.findall(sample)) / len(sample)


def json_depth(text: str, limit: int) -> int:
    """Max bracket depth outside strings. Stops early once over the limit."""
    depth = best = 0
    in_str = esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            if depth > best:
                best = depth
                if best > limit:
                    return best
        elif ch in "]}":
            depth -= 1
    return best


def _json_style(text: str) -> dict:
    stripped = text.strip()
    if "\n" not in stripped:
        return {"indent": None}
    m = re.search(r"\n( +)\S", stripped)
    indent = len(m.group(1)) if m else 2
    return {"indent": indent}


def sniff_and_parse(doc: Doc, raw: bytes, policy: dict) -> None:
    limits = policy.get("ingest", {})
    max_mb = float(limits.get("max_file_mb", 200))
    if not raw:
        raise Quarantine("empty_file")
    if len(raw) > max_mb * 1024 * 1024:
        raise Quarantine("too_large")
    if raw.startswith(MAGIC):
        raise Quarantine("unsupported_binary")
    text, enc = decode(raw)
    if _control_ratio(text) > 0.01:
        raise Quarantine("unsupported_binary")
    if not text.strip():
        raise Quarantine("empty_file")
    doc.encoding = enc
    doc.newline = "\r\n" if "\r\n" in text else "\n"
    ext = "." + doc.rel.rsplit(".", 1)[-1].lower() if "." in doc.rel.rsplit("/", 1)[-1] else ""
    head = text.lstrip("\ufeff \t\r\n")[:1]
    looks_json = head in ("{", "[")
    looks_markup = head == "<"
    if looks_markup:
        raise Quarantine("unsupported_markup")
    if ext in JSON_EXT or (looks_json and ext in (".jsonl", ".ndjson")):
        if not looks_json:
            raise Quarantine("malformed_json")
        _parse_json(doc, text, policy)
        return
    if ext in CSV_EXT:
        if looks_json:
            raise Quarantine("format_mismatch")
        _parse_csv(doc, text, CSV_EXT[ext])
        return
    if looks_json and ext not in TEXT_OK_EXT:
        raise Quarantine("format_mismatch")
    if ext in TEXT_OK_EXT or ext not in (".xml", ".html", ".htm", ".pdf", ".jpg", ".jpeg", ".png"):
        doc.fmt = "text"
        doc.data = text
        return
    raise Quarantine("unsupported_format")


# --------------------------------------------------------------------------- CSV
def _parse_csv(doc: Doc, text: str, delim: str) -> None:
    first = text.split("\n", 1)[0]
    if delim == "," and first.count("\t") > first.count(",") and first.count("\t") >= 2:
        delim = "\t"
    try:
        rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delim))
    except csv.Error:
        raise Quarantine("malformed_csv") from None
    if not rows:
        raise Quarantine("empty_file")
    doc.fmt = "tsv" if delim == "\t" else "csv"
    doc.delimiter = delim
    doc.data = rows


# --------------------------------------------------------------------------- JSON
def _reject_constant(name: str):
    raise ValueError(f"non-standard JSON constant {name}")


def _finite_float(s: str) -> float:
    v = float(s)
    if not math.isfinite(v):
        raise ValueError("non-finite number")
    return v


def _parse_json(doc: Doc, text: str, policy: dict) -> None:
    limit = int(policy.get("ingest", {}).get("max_json_depth", 200))
    if json_depth(text, limit) > limit:
        raise Quarantine("too_deep")
    try:
        # NaN, Infinity and 1e400 would be written back as invalid JSON: refuse them.
        obj = json.loads(text, parse_constant=_reject_constant, parse_float=_finite_float)
    except (ValueError, RecursionError):
        raise Quarantine("malformed_json") from None
    doc.json_style = _json_style(text)
    doc.data = obj
    if isinstance(obj, dict) and isinstance(obj.get("resourceType"), str):
        doc.fmt = "fhir"
    else:
        doc.fmt = "json"


# --------------------------------------------------------------------------- slots
def build_slots(doc: Doc, classify_header, classify_key) -> None:
    """Split a parsed document into records and slots. Classifiers come from detect.fields."""
    from .detect.fields import profile_column

    name = doc.rel.rsplit("/", 1)[-1]
    doc.file_slots.append(Slot(path=("@filename",), text=normalize(name), kind="filename", orig=name))
    if doc.fmt in ("csv", "tsv"):
        rows = doc.data
        header = rows[0]
        body = rows[1:]
        ftypes = []
        for j, h in enumerate(header):
            col_vals = [r[j] for r in body if j < len(r)]
            ft = classify_header(normalize(h))
            if ft is None or ft == "TEXT_UNKNOWN":
                ft = profile_column(col_vals) or ft
            ftypes.append(ft)
            doc.file_slots.append(Slot(path=("@header", j), text=normalize(h), kind="header", key=h, orig=h))
        doc.header_hint = " ".join(header).lower()
        for i, row in enumerate(body):
            rec = Record(loc=f"row:{i}")
            for j, cell in enumerate(row):
                ft = ftypes[j] if j < len(ftypes) and len(row) == len(header) else None
                key = header[j] if j < len(header) else ""
                if len(row) != len(header) and j < len(ftypes):
                    ft = ftypes[j] if ftypes[j] in ("TEXT",) else None
                rec.slots.append(Slot(path=(i, j), text=normalize(cell), ftype=ft, key=key, orig=cell))
            doc.records.append(rec)
        return
    if doc.fmt == "text":
        rec = Record(loc="doc")
        rec.slots.append(Slot(path=(), text=normalize(doc.data, entities=True), kind="text", ftype="TEXT", orig=doc.data))
        doc.records.append(rec)
        return
    # JSON and FHIR
    obj = doc.data
    record_paths = [] if doc.fmt == "fhir" else _record_arrays(obj, classify_key)
    if not record_paths:
        doc.records.append(Record(loc="doc"))
    else:
        for p in record_paths:
            arr = _get(obj, p)
            for i in range(len(arr)):
                doc.records.append(Record(loc=_pointer(p + (i,))))
    rec_index = {r.loc: r for r in doc.records}
    meta = Record(loc="@file")

    def owner(path: tuple) -> Record:
        for p in record_paths:
            if len(path) > len(p) and path[: len(p)] == p:
                return rec_index[_pointer(path[: len(p) + 1])]
        return rec_index.get("doc", meta)

    ctx_stack: list = []
    _walk(obj, (), owner, classify_key, ctx_stack, doc)
    if meta.slots:
        doc.records.append(meta)


def _pointer(path: tuple) -> str:
    return "/" + "/".join(str(p).replace("~", "~0").replace("/", "~1") for p in path)


@lru_cache(maxsize=65536)
def _norm_key(k: str) -> str:
    return normalize(k)


def _get(obj, path):
    for p in path:
        obj = obj[p]
    return obj


_PERSONISH = {"NAME", "FIRST_NAME", "LAST_NAME", "MRN", "PHONE", "AADHAAR", "ABHA", "RELATIVE", "EMAIL"}


def _has_person_keys(obj, classify_key, depth=0) -> bool:
    if depth > 3 or not isinstance(obj, dict):
        return False
    for k, v in obj.items():
        if classify_key(k, (), None) in _PERSONISH and not isinstance(v, (dict, list)):
            return True
        if isinstance(v, dict) and _has_person_keys(v, classify_key, depth + 1):
            return True
    return False


def _record_arrays(obj, classify_key) -> list[tuple]:
    out = []
    if isinstance(obj, list):
        if obj and all(isinstance(x, dict) for x in obj):
            return [()]
        return []
    if not isinstance(obj, dict):
        return []
    # A top-level object that itself describes one patient is a single document.
    top_person = any(classify_key(k, (), None) in _PERSONISH and not isinstance(v, (dict, list))
                     for k, v in obj.items())
    nested_person = any(isinstance(v, dict) and _has_person_keys(v, classify_key, 1) and
                        k.lower() in ("patient", "subject", "person", "beneficiary")
                        for k, v in obj.items())
    if top_person or nested_person:
        return []
    for k, v in obj.items():
        if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
            if any(_has_person_keys(x, classify_key) for x in v[:50]):
                out.append((k,))
        elif isinstance(v, dict):
            for k2, v2 in v.items():
                if isinstance(v2, list) and v2 and all(isinstance(x, dict) for x in v2):
                    if any(_has_person_keys(x, classify_key) for x in v2[:50]):
                        out.append((k, k2))
    return out


def _walk(obj, path, owner, classify_key, ctx, doc):
    stack = [(obj, path, tuple(ctx))]
    while stack:
        node, p, c = stack.pop()
        if isinstance(node, dict):
            rtype = node.get("resourceType") if isinstance(node.get("resourceType"), str) else None
            cc = c + ((rtype,) if rtype else ())
            # FHIR extensions such as ".../mothers-name" carry a person name in value[x].
            url = node.get("url") if isinstance(node.get("url"), str) else ""
            ext_name = bool(re.search(r"(?i)(name|mother|father|spouse|guardian|relative|kin|husband)", url.rsplit("/", 1)[-1]))
            items = list(node.items())
            for k, v in reversed(items):
                kp = p + (k,)
                ks = _norm_key(str(k))
                # JSON keys can hold PII themselves (a dict keyed by name or UHID).
                owner(kp).slots.append(Slot(path=kp, text=ks, kind="key", key=str(k), orig=k))
                if ext_name and str(k).startswith("value") and isinstance(v, str):
                    owner(kp).slots.append(Slot(path=kp, text=normalize(v), ftype="RELATIVE", key=str(k), orig=v))
                    continue
                stack.append((v, kp, cc))
        elif isinstance(node, list):
            for i in range(len(node) - 1, -1, -1):
                stack.append((node[i], p + (i,), c))
        elif isinstance(node, str):
            keyname = next((x for x in reversed(p) if isinstance(x, str)), "")
            ft = classify_key(keyname, p, c)
            text = normalize(node)
            b64 = False
            dec = b64_text(node) if len(node) >= 16 else None
            if dec is not None and ft not in ("MRN", "NAME"):
                text, b64 = normalize(dec), True
            owner(p).slots.append(Slot(path=p, text=text, ftype=ft, key=keyname, b64=b64, orig=node))
        elif isinstance(node, (int, float)) and not isinstance(node, bool):
            keyname = next((x for x in reversed(p) if isinstance(x, str)), "")
            ft = classify_key(keyname, p, c)
            owner(p).slots.append(Slot(path=p, text=str(node), ftype=ft, key=keyname, number=True, orig=node))
    # keep slot order stable and document-ordered
    for r in doc.records:
        r.slots.sort(key=lambda s: tuple(str(x) for x in s.path) + (s.kind,))
