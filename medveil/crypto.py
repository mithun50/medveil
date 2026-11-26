"""Key schedule, keyed pseudonyms and the encrypted quarantine vault.

All keys are derived in memory from RAKSHA_SECRET with HKDF-SHA256 and distinct
labels, so pseudonyms, date shifts, file-name codes and the vault never share a key.
Nothing here writes a key anywhere.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path

LETTERS = "ABCDEFGHJKMNPQRSTVWXYZ"  # 22 letters, no I L O U: no digits that could match a real ID


def hkdf(secret: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(b"medveil-hkdf-salt-v1", secret, hashlib.sha256).digest()
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


class Keys:
    def __init__(self, secret: bytes, vault_secret: bytes | None = None):
        self.psn = hkdf(secret, b"pseudonym-v1")
        self.shift = hkdf(secret, b"date-shift-v1")
        self.name = hkdf(secret, b"filename-code-v1")
        self.vault = hkdf(vault_secret or secret, b"quarantine-vault-v1")

    @staticmethod
    def _mac(k: bytes, msg: str) -> bytes:
        return hmac.new(k, msg.encode("utf-8"), hashlib.sha256).digest()

    def code(self, k: bytes, msg: str, length: int) -> str:
        n = int.from_bytes(self._mac(k, msg), "big")
        out = []
        for _ in range(length):
            n, r = divmod(n, len(LETTERS))
            out.append(LETTERS[r])
        return "".join(out)

    def pseudonym(self, canonical: str, length: int = 8, salt: int = 0) -> str:
        return "PSN-" + self.code(self.psn, f"{salt}|{canonical}", length)

    def opaque(self, msg: str, length: int = 8) -> str:
        return self.code(self.name, msg, length)

    def shift_days(self, canonical: str, lo: int, hi: int) -> int:
        n = int.from_bytes(self._mac(self.shift, canonical)[:8], "big")
        mag = lo + n % (hi - lo + 1)
        return mag if (n >> 40) & 1 else -mag


class Vault:
    """AES-256-GCM per-file encryption for quarantined inputs (optional)."""

    def __init__(self, root: Path, kek: bytes):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except Exception:  # noqa: BLE001 - vault is optional; fail closed by storing nothing
            self.ok = False
            return
        self.ok = True
        self._aesgcm = AESGCM
        self.root = root
        self.kek = kek
        self.manifest: list[dict] = []

    def put(self, sha256: str, raw: bytes, reason: str) -> None:
        if not self.ok:
            return
        self.root.mkdir(parents=True, exist_ok=True)
        dek = os.urandom(32)
        n1, n2 = os.urandom(12), os.urandom(12)
        aad = sha256.encode("ascii")
        blob = self._aesgcm(dek).encrypt(n1, raw, aad)
        wrapped = self._aesgcm(self.kek).encrypt(n2, dek, aad)
        name = hmac.new(self.kek, aad, hashlib.sha256).hexdigest()[:32]
        (self.root / f"{name}.bin").write_bytes(n1 + blob)
        self.manifest.append({"blob": f"{name}.bin", "input_sha256": sha256, "reason": reason,
                              "wrapped_key": (n2 + wrapped).hex(), "alg": "AES-256-GCM"})

    def close(self) -> None:
        if self.ok and self.manifest:
            self.manifest.sort(key=lambda m: m["blob"])
            (self.root / "manifest.json").write_text(json.dumps({"files": self.manifest}, indent=1), encoding="utf-8")
