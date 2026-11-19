"""可注入时钟。

所有时间判定都走 Clock，测试与重放时用固定时间，保证 cases.json
可重放、到期相关用例确定可控。时间统一为 UTC ISO-8601 字符串，
字典序即时间序。
"""

from __future__ import annotations

from datetime import datetime, timezone


class Clock:
    def __init__(self, fixed: str | None = None):
        self._fixed = fixed

    def now(self) -> str:
        if self._fixed is not None:
            return self._fixed
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def advance(self, iso: str) -> None:
        self._fixed = iso
