import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
KIT = ROOT.parent / "Secret-Wards-ToolKit"


@pytest.fixture
def kit():
    if not (KIT / "dev" / "input").is_dir():
        pytest.skip("Secret-Wards-ToolKit not found next to the repo")
    return KIT
