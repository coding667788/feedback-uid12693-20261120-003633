"""测试公共工具：定位仓库根、装载 cases.json、生成临时工作区。"""

from __future__ import annotations

import json
import os
import shutil
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CASES_PATH = os.path.join(REPO_ROOT, "cases.json")


def load_document() -> dict:
    with open(CASES_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


class TempWorkspace:
    def __init__(self, prefix: str = "aec-test-"):
        self.path = tempfile.mkdtemp(prefix=prefix)

    def cleanup(self) -> None:
        shutil.rmtree(self.path, ignore_errors=True)

    def sub(self, name: str) -> str:
        path = os.path.join(self.path, name)
        os.makedirs(path, exist_ok=True)
        return path
