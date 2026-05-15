# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
from __future__ import annotations

from typing import Any


class MsgObj:
    __slots__ = ("src", "raw", "app", "id", "chat_id", "from_id", "text")

    src: str
    raw: dict[str, Any]
    app: Any
    id: int | None
    chat_id: int | str | None
    from_id: int | None
    text: str

    def __init__(self, src: str, raw: dict[str, Any], app: Any) -> None:
        self.src = src
        self.raw = raw
        self.app = app
        self.id = raw.get("msg_id")
        self.chat_id = raw.get("chat_id")
        self.from_id = raw.get("from_id")
        self.text = str(raw.get("text", ""))

    def net(self) -> Any:
        if self.src == "bot":
            if self.app.bot is None:
                raise RuntimeError("bot net is not configured")
            return self.app.bot
        if self.app.mt is None:
            raise RuntimeError("mt net is not configured")
        return self.app.mt

    async def reply(self, txt: str, kbd: Any | None = None, topic_id: int | None = None, link_options: Any | None = None, **kw: Any) -> Any:
        if self.chat_id is None:
            return None
        if hasattr(self.app, "send_msg"):
            return await self.app.send_msg(self.chat_id, txt, reply_to=self.id, kbd=kbd, topic_id=topic_id, via=self.src, link_options=link_options, **kw)
        data = dict(kw)
        data["reply_to"] = self.id
        if kbd is not None:
            data["kbd"] = kbd
        if topic_id is not None:
            data["topic_id"] = topic_id
        if link_options is not None:
            data["link_options"] = link_options
        return await self.net().send_msg(self.chat_id, txt, **data)

    async def delete(self) -> Any:
        if self.chat_id is None or self.id is None:
            return None
        return await self.net().del_msg(self.chat_id, int(self.id))
