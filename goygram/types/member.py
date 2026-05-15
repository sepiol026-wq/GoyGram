# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
from __future__ import annotations

from typing import Any


class MemberObj:
    __slots__ = ("src", "raw", "app", "chat_id", "from_id", "user_id", "old", "new", "kind")

    def __init__(self, src: str, raw: dict[str, Any], app: Any) -> None:
        self.src = src
        self.raw = raw
        self.app = app
        self.chat_id = raw.get("chat_id")
        self.from_id = raw.get("from_id")
        self.user_id = raw.get("user_id")
        self.old = raw.get("old_status")
        self.new = raw.get("new_status")
        self.kind = raw.get("kind", "member")
