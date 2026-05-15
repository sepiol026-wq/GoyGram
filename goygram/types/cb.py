# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
from __future__ import annotations

from typing import Any


class CbObj:
    __slots__ = ("src", "raw", "app", "id", "chat_id", "from_id", "msg_id", "data", "text")

    def __init__(self, src: str, raw: dict[str, Any], app: Any) -> None:
        self.src = src
        self.raw = raw
        self.app = app
        self.id = raw.get("query_id") or raw.get("id")
        self.chat_id = raw.get("chat_id")
        self.from_id = raw.get("from_id")
        self.msg_id = raw.get("msg_id")
        self.data = raw.get("data", "")
        self.text = raw.get("text", "")

    async def answer(self, text: str | None = None, alert: bool = False, url: str | None = None, cache_time: int = 0) -> Any:
        if self.id is None:
            return None
        if hasattr(self.app, "answer_cb"):
            return await self.app.answer_cb(str(self.id), text=text, alert=alert, url=url, cache_time=cache_time)
        if self.app.bot is None:
            raise RuntimeError("bot net is not configured")
        return await self.app.bot.call("answerCallbackQuery", callback_query_id=str(self.id), text=text, show_alert=alert, url=url, cache_time=cache_time)

    async def edit(self, text: str, kbd: Any | None = None, **kw: Any) -> Any:
        if self.chat_id is None or self.msg_id is None:
            return None
        if hasattr(self.app, "edit_text"):
            return await self.app.edit_text(self.chat_id, int(self.msg_id), text, kbd=kbd, via=self.src, **kw)
        if self.app.bot is None:
            raise RuntimeError("bot net is not configured")
        data = dict(kw)
        if kbd is not None:
            data["reply_markup"] = kbd
        return await self.app.bot.call("editMessageText", chat_id=self.chat_id, message_id=int(self.msg_id), text=text, **data)
