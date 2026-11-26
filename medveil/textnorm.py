"""Text normalization.

The official scorer normalizes both input and output before it looks for leaks
(NFKC, homoglyph folding, zero-width removal, Indic digits to ASCII, decoding of
escaped payloads). We apply the same folding before detection and write the
folded text, so a disguised name cannot slip past our detectors.
"""
from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from urllib.parse import unquote

# Zero-width and invisible formatting characters.
_ZW = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e\u200e\u200f"), None)

# Indic digits (Devanagari, Bengali, Gurmukhi, Gujarati, Oriya, Tamil, Telugu, Kannada, Malayalam).
_DIGITS: dict[int, str] = {}
for _base in (0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6, 0x0D66):
    for _i in range(10):
        _DIGITS[_base + _i] = str(_i)

# Cyrillic and Greek letters that look like Latin letters.
_HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "ӏ": "l", "һ": "h", "ԛ": "q", "ԝ": "w", "к": "k", "м": "m", "н": "h",
    "т": "t", "в": "b", "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "У": "Y", "І": "I", "Ј": "J", "Ѕ": "S",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "i", "κ": "k", "χ": "x", "υ": "u",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}
_HOMO_TABLE = str.maketrans(_HOMOGLYPHS)
_HAS_HOMO = re.compile("[" + "".join(_HOMOGLYPHS) + "]")

_U_ESC = re.compile(r"(?:\\u[0-9a-fA-F]{4})+")
_NUM_ENT = re.compile(r"&#(?:\d{2,7}|[xX][0-9a-fA-F]{2,6});")
_NAMED_ENT = re.compile(r"&(?:amp|lt|gt|quot|apos|nbsp);")
_PCT = re.compile(r"(?:%[0-9A-Fa-f]{2}){3,}")


def fold(text: str) -> str:
    """NFKC, strip zero-width characters, Indic digits to ASCII, fold homoglyphs."""
    if not text:
        return text
    text = unicodedata.normalize("NFKC", text).translate(_ZW).translate(_DIGITS)
    if _HAS_HOMO.search(text):
        text = text.translate(_HOMO_TABLE)
    return text


def _decode_u(m: re.Match) -> str:
    try:
        return m.group(0).encode("ascii").decode("unicode_escape")
    except (UnicodeDecodeError, ValueError):
        return m.group(0)


def _decode_pct(m: re.Match) -> str:
    try:
        out = unquote(m.group(0), errors="strict")
    except UnicodeDecodeError:
        return m.group(0)
    return out if out.isprintable() else m.group(0)


def decode_escapes(text: str, entities: bool = True) -> str:
    """Decode payloads the scorer also decodes: \\uXXXX, HTML entities, %-encoding."""
    if "\\u" in text:
        text = _U_ESC.sub(_decode_u, text)
    if entities and "&" in text:
        text = _NUM_ENT.sub(lambda m: html.unescape(m.group(0)), text)
        text = _NAMED_ENT.sub(lambda m: html.unescape(m.group(0)), text)
    if "%" in text:
        text = _PCT.sub(_decode_pct, text)
    return text


def normalize(text: str, entities: bool = True) -> str:
    return fold(decode_escapes(fold(text), entities=entities))


_B64_FULL = re.compile(r"^[A-Za-z0-9+/\r\n]+={0,2}$")
B64_RUN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


def b64_text(value: str) -> str | None:
    """Return the decoded text if `value` is base64 of readable UTF-8 text, else None."""
    s = value.strip()
    if len(s) < 16 or not _B64_FULL.match(s):
        return None
    compact = re.sub(r"\s+", "", s)
    if len(compact) % 4:
        return None
    # Plain words such as "Haemoglobin" are not base64 payloads.
    if not re.search(r"[0-9+/=]", compact) and len(compact) < 40:
        return None
    try:
        raw = base64.b64decode(compact, validate=True)
        txt = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if not txt:
        return None
    printable = sum(1 for c in txt if c.isprintable() or c in "\r\n\t")
    if printable / len(txt) < 0.9:
        return None
    return txt


def b64_encode_text(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


DEVA = re.compile(r"[\u0900-\u097F]")
LATIN = re.compile(r"[A-Za-z]")


def script_of(text: str) -> str:
    return "deva" if DEVA.search(text) else "latin"
