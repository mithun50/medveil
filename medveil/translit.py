"""Cross-script phonetic keys for Indian names.

`key(token)` maps a Latin or Devanagari name token to one folded Latin skeleton, so
that "मोहम्मद", "Mohammad", "Mohd." and "Md." compare equal, and "Rina" equals
"Reena". Devanagari is transliterated with our own table plus schwa deletion
(the inherent vowel is dropped word-finally and in the V C _ C V position), then
both scripts go through the same Latin folding.
"""
from __future__ import annotations

import re
import unicodedata
from functools import lru_cache

_CONS = {
    "क": "k", "ख": "kh", "ग": "g", "घ": "gh", "ङ": "n", "च": "ch", "छ": "chh", "ज": "j",
    "झ": "jh", "ञ": "n", "ट": "t", "ठ": "th", "ड": "d", "ढ": "dh", "ण": "n", "त": "t",
    "थ": "th", "द": "d", "ध": "dh", "न": "n", "प": "p", "फ": "ph", "ब": "b", "भ": "bh",
    "म": "m", "य": "y", "र": "r", "ल": "l", "व": "v", "श": "sh", "ष": "sh", "स": "s",
    "ह": "h", "ळ": "l", "ऱ": "r", "ऴ": "l",
}
_NUKTA = {"क": "q", "ख": "kh", "ग": "g", "ज": "z", "ड": "r", "ढ": "rh", "फ": "f", "य": "y"}
_VOWELS = {
    "अ": "a", "आ": "aa", "इ": "i", "ई": "ii", "उ": "u", "ऊ": "uu", "ऋ": "ri", "ए": "e",
    "ऐ": "ai", "ओ": "o", "औ": "au", "ऑ": "o", "ऍ": "e", "ऎ": "e", "ऒ": "o",
}
_MATRAS = {
    "ा": "aa", "ि": "i", "ी": "ii", "ु": "u", "ू": "uu", "ृ": "ri", "े": "e", "ै": "ai",
    "ो": "o", "ौ": "au", "ॉ": "o", "ॅ": "e", "ॆ": "e", "ॊ": "o",
}
_VIRAMA = "्"
_NASAL = {"ं": "n", "ँ": "n"}
_NUKTA_SIGN = "़"
_DEVA_RE = re.compile(r"[\u0900-\u097F]")


def deva_to_latin(word: str) -> str:
    """Transliterate one Devanagari word with schwa deletion."""
    word = unicodedata.normalize("NFD", word)
    units: list[list] = []  # [consonant or None, vowel or None, inherent?, nasal]
    i = 0
    while i < len(word):
        ch = word[i]
        if ch in _CONS:
            cons = _CONS[ch]
            if i + 1 < len(word) and word[i + 1] == _NUKTA_SIGN:
                cons = _NUKTA.get(ch, cons)
                i += 1
            units.append([cons, "a", True, ""])
        elif ch in _MATRAS and units and units[-1][0] is not None:
            units[-1][1] = _MATRAS[ch]
            units[-1][2] = False
        elif ch == _VIRAMA and units:
            units[-1][1] = None
            units[-1][2] = False
        elif ch in _NASAL and units:
            units[-1][3] += _NASAL[ch]
        elif ch == "ः" and units:
            units[-1][3] += "h"
        elif ch in _VOWELS:
            units.append([None, _VOWELS[ch], False, ""])
        elif ch == _NUKTA_SIGN:
            pass
        else:
            units.append([None, None, False, ch])
        i += 1
    n = len(units)

    def has_vowel(u) -> bool:
        return u[1] is not None

    deleted = [False] * n
    if n > 1 and units[-1][0] is not None and units[-1][2] and not units[-1][3]:
        units[-1][1] = None
        deleted[-1] = True
    for j in range(n - 2, 0, -1):
        u = units[j]
        if u[0] is None or not u[2] or u[3]:
            continue
        prev, nxt = units[j - 1], units[j + 1]
        if not has_vowel(prev) or nxt[0] is None or deleted[j + 1]:
            continue
        # V C _ C V, or V C _ C(virama) C V for a following conjunct.
        if has_vowel(nxt) or (j + 2 < n and units[j + 2][0] is not None and has_vowel(units[j + 2])):
            u[1] = None
            deleted[j] = True
    out = []
    for cons, vowel, _inh, nasal in units:
        out.append((cons or "") + (vowel or "") + nasal)
    return "".join(out)


# Spelling variants that fold to one key before the phonetic rules run.
_VARIANTS = {
    "mohammad": "mhd", "mohammed": "mhd", "muhammad": "mhd", "mohamad": "mhd", "mohd": "mhd",
    "md": "mhd", "mohamed": "mhd", "muhammed": "mhd", "mohmmad": "mhd", "mohammd": "mhd",
    "mohmad": "mhd", "mahmmad": "mhd", "mohamd": "mhd",
    "chaudhary": "cdr", "choudhary": "cdr", "chaudhari": "cdr", "chowdhury": "cdr",
    "chaudhry": "cdr", "choudhry": "cdr", "chaudhuri": "cdr", "choudhury": "cdr", "chodhary": "cdr",
    "chaudhri": "cdr", "chowdhary": "cdr",
}

_LATIN_RULES = [
    ("chh", "c"), ("ksh", "x"), ("kh", "k"), ("gh", "g"), ("jh", "j"), ("th", "t"),
    ("dh", "d"), ("ph", "f"), ("bh", "b"), ("sh", "s"), ("ch", "c"), ("ck", "k"),
    ("qu", "k"), ("z", "j"), ("q", "k"), ("w", "v"),
    ("aa", "a"), ("ee", "i"), ("ii", "i"), ("oo", "u"), ("uu", "u"), ("ou", "o"), ("au", "o"),
    ("ai", "e"),
]


def _fold_latin(word: str) -> str:
    w = re.sub(r"[^a-z]", "", word.lower())
    if not w:
        return ""
    if w in _VARIANTS:
        return _VARIANTS[w]
    if w.endswith("ey") and len(w) > 3:
        w = w[:-2] + "e"
    for a, b in _LATIN_RULES:
        w = w.replace(a, b)
    if w.endswith("y") and len(w) > 2:
        w = w[:-1] + "i"
    w = re.sub(r"(.)\1+", r"\1", w)
    return w


@lru_cache(maxsize=200_000)
def key(token: str) -> str:
    """Folded phonetic key of one name token, script-independent."""
    if not token:
        return ""
    if _DEVA_RE.search(token):
        raw = deva_to_latin(token)
        if re.sub(r"[^a-z]", "", raw) in _VARIANTS:
            return _VARIANTS[re.sub(r"[^a-z]", "", raw)]
        return _fold_latin(raw)
    return _fold_latin(token)


def consonants(k: str) -> str:
    if not k:
        return ""
    return k[0] + re.sub(r"[aeiouy]", "", k[1:])


def jaro_winkler(a: str, b: str) -> float:
    if a == b:
        return 1.0
    la, lb = len(a), len(b)
    if not la or not lb:
        return 0.0
    rng = max(la, lb) // 2 - 1
    rng = max(rng, 0)
    am = [False] * la
    bm = [False] * lb
    matches = 0
    for i in range(la):
        lo, hi = max(0, i - rng), min(lb, i + rng + 1)
        for j in range(lo, hi):
            if not bm[j] and a[i] == b[j]:
                am[i] = bm[j] = True
                matches += 1
                break
    if not matches:
        return 0.0
    t = 0
    k = 0
    for i in range(la):
        if am[i]:
            while not bm[k]:
                k += 1
            if a[i] != b[k]:
                t += 1
            k += 1
    t /= 2
    jaro = (matches / la + matches / lb + (matches - t) / matches) / 3
    prefix = 0
    for i in range(min(4, la, lb)):
        if a[i] == b[i]:
            prefix += 1
        else:
            break
    return jaro + prefix * 0.1 * (1 - jaro)


@lru_cache(maxsize=500_000)
def token_sim(a: str, b: str) -> float:
    """Similarity of two folded keys in [0, 1]."""
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    jw = jaro_winkler(a, b)
    # Vowel-spelling variants (Kamla/Kamala, Fatma/Fatima) share consonants and end the same
    # way; Kamal and Kamla share consonants but one ends in a vowel, so they stay apart.
    if (min(len(a), len(b)) >= 3 and consonants(a) == consonants(b)
            and (a[-1] in "aeiou") == (b[-1] in "aeiou")):
        jw = max(jw, 0.9)
    elif consonants(a) == consonants(b) and (a[-1] in "aeiou") != (b[-1] in "aeiou"):
        jw = min(jw, 0.85)
    return jw


def tokens_match(a: str, b: str, threshold: float = 0.9) -> bool:
    if a == b:
        return True
    if min(len(a), len(b)) < 3:
        return False
    return token_sim(a, b) >= threshold
