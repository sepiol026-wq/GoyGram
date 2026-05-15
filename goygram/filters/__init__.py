# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Filter:
    fn: Callable[[object], bool]

    def __call__(self, event: object) -> bool:
        return bool(self.fn(event))

    def __and__(self, other: "Filter") -> "Filter":
        return Filter(lambda e: self(e) and other(e))

    def __or__(self, other: "Filter") -> "Filter":
        return Filter(lambda e: self(e) or other(e))

    def __invert__(self) -> "Filter":
        return Filter(lambda e: not self(e))


text = Filter(lambda e: bool(getattr(e, "text", None)))
me = Filter(lambda e: bool(getattr(e, "is_me", False) or getattr(e, "from_id", None) == getattr(getattr(e, "app", None), "self_id", object())))

__all__ = ["Filter", "text", "me"]
