# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
from __future__ import annotations

from typing import Any


class PollObj:
    __slots__ = ("src", "raw", "app", "id", "question", "closed", "kind")

    def __init__(self, src: str, raw: dict[str, Any], app: Any) -> None:
        self.src = src
        self.raw = raw
        self.app = app
        self.id = raw.get("poll_id") or raw.get("id")
        self.question = raw.get("question", "")
        self.closed = bool(raw.get("is_closed", False))
        self.kind = raw.get("kind", "poll")
