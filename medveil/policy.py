"""Policy loading. config/policy.yaml overrides the defaults below key by key."""
from __future__ import annotations

import copy
from pathlib import Path

DEFAULTS: dict = {
    "pseudonym": {"length": 8},
    "dates": {"shift_min_days": 30, "shift_max_days": 365},
    "dob": {"mode": "suppress"},
    "age": {"ladder": [10, 20], "top_code": 80, "k_patients": 2},
    "location": {"keep_level": "district", "pin_prefix_digits": 3},
    "rare_values": {"max_profiles_rare": 3, "enabled": False},
    "ingest": {"max_file_mb": 200, "max_json_depth": 200, "on_garbled_text": "quarantine"},
    "quarantine": {"vault": "encrypted"},
}


DOB_MODES = ("suppress", "shift")


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load(path: Path) -> dict:
    data: dict = {}
    if path.is_file():
        try:
            import yaml
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:  # noqa: BLE001 - a broken policy must not stop the run; defaults apply
            data = {}
    pol = _merge(DEFAULTS, data if isinstance(data, dict) else {})
    # Only these DOB modes are implemented; anything else falls back to the safest one.
    if not isinstance(pol.get("dob"), dict) or pol["dob"].get("mode") not in DOB_MODES:
        pol["dob"] = dict(DEFAULTS["dob"])
    return pol
