# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
from __future__ import annotations

import inspect
from typing import Any

from goygram.filters import Filter, me, text


def print_methods(app: Any) -> None:
    """Print a DX-oriented overview of API entry points and filters."""
    lines: list[str] = []
    lines.append("=== GoyGram Developer Help ===")
    lines.append("• Dynamic methods:")
    lines.append("  - app.sendDocument(...), app.getChat(...), app.getUpdates(...)")
    lines.append("  - app.mt_<method>(...) for MTProto actions, e.g. app.mt_get_dialogs(...)")
    lines.append("• Built-in shortcuts:")
    for name in sorted(x for x in dir(app) if not x.startswith("_") and callable(getattr(app, x, None))):
        if name in {"send_msg", "send_photo", "send_doc", "edit_text", "del_msg", "answer_cb", "help"}:
            sig = inspect.signature(getattr(app, name))
            lines.append(f"  - {name}{sig}")
    lines.append("• Filters:")
    lines.append("  - text: Message has text")
    lines.append("  - me: Event from current account/bot")
    lines.append("  - Combine with &, |, ~ (Filter operators)")
    print("\n".join(lines))


__all__ = ["print_methods", "Filter", "text", "me"]
