# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
from __future__ import annotations

import json
import secrets
from typing import Any


class Obj:
    src: str
    raw: dict[str, Any]
    app: Any
    id: int | None
    chat_id: int | str | None
    from_id: int | None
    msg_id: int | None
    kind: str

    def __init__(self, src: str, raw: dict[str, Any], app: Any) -> None:
        self.src = src
        self.raw = raw
        self.app = app
        self.id = raw.get("msg_id") or raw.get("query_id") or raw.get("poll_id") or raw.get("id")
        self.chat_id = raw.get("chat_id")
        self.from_id = raw.get("from_id")
        self.msg_id = raw.get("msg_id")
        self.kind = raw.get("kind", raw.get("update_type", "msg"))
        self.match = None

    @property
    def text(self) -> str:
        return str(self.raw.get("text", ""))

    @property
    def data(self) -> Any:
        return self.raw.get("data")

    @property
    def query(self) -> Any:
        return self.raw.get("query")

    @property
    def cmd(self) -> str | None:
        return self.raw.get("cmd")

    @property
    def args(self) -> Any:
        return self.raw.get("args")

    @property
    def is_me(self) -> bool:
        return bool(self.raw.get("is_me", False))

    @property
    def update_type(self) -> str:
        return str(self.raw.get("update_type") or self.raw.get("_") or self.kind)

    @property
    def inline_message_id(self) -> Any:
        return self.raw.get("inline_message_id")

    @property
    def old(self) -> Any:
        return self.raw.get("old_status", self.raw.get("old"))

    @property
    def new(self) -> Any:
        return self.raw.get("new_status", self.raw.get("new"))

    @property
    def user_id(self) -> Any:
        return self.raw.get("user_id")

    @property
    def closed(self) -> Any:
        return self.raw.get("is_closed", False)

    @property
    def question(self) -> Any:
        return self.raw.get("question", "")

    @property
    def offset(self) -> Any:
        return self.raw.get("offset", "")

    @property
    def chat_type(self) -> Any:
        return self.raw.get("chat_type")

    @property
    def location(self) -> Any:
        return self.raw.get("location")

    def _value(self, key: str, default: Any = None) -> Any:
        if key in self.raw:
            return self.raw[key]
        source = self.raw.get("raw")
        if isinstance(source, dict):
            if key in source:
                return source[key]
            for name in ("message", "edited_message", "channel_post", "edited_channel_post"):
                obj = source.get(name)
                if isinstance(obj, dict) and key in obj:
                    return obj[key]
        update = self.raw.get("raw_update")
        if isinstance(update, dict):
            obj = update.get("message")
            if isinstance(obj, dict) and key in obj:
                return obj[key]
            if key in update:
                return update[key]
        return default

    def get(self, key: str, default: Any = None) -> Any:
        return self._value(key, default)

    def __getitem__(self, key: str) -> Any:
        value = self._value(key)
        if value is None and key not in self.raw:
            raise KeyError(key)
        return value

    def __getattr__(self, name: str) -> Any:
        key = "from" if name == "from_user" else name
        value = self._value(key)
        if value is None:
            raise AttributeError(name)
        return value

    def to_dict(self) -> dict[str, Any]:
        return self.raw

    async def respond(self, text: str, **kw: Any) -> Any:
        return await self.app.send_msg(self.chat_id, text, via=self.src, **kw)

    async def answer(self, text: str | None = None, alert: bool = False, url: str | None = None, cache_time: int = 0, results: list[dict[str, Any]] | None = None, **kw: Any) -> Any:
        if self.kind == "inline" and results is not None:
            if self.id is None:
                return None
            if self.app.bot is None:
                raise RuntimeError("bot net is not configured")
            data: dict[str, Any] = {
                "inline_query_id": str(self.id),
                "results": results,
                "cache_time": kw.pop("cache_time", cache_time),
                "is_personal": kw.pop("is_personal", True),
            }
            for opt in ("next_offset", "button", "switch_pm_text", "switch_pm_parameter"):
                if opt in kw:
                    data[opt] = kw.pop(opt)
            data.update(kw)
            return await self.app.bot_req("answerInlineQuery", **data)
        if self.id is None:
            return None
        if self.app.bot is None:
            raise RuntimeError("bot net is not configured")
        return await self.app.bot_req("answerCallbackQuery", callback_query_id=str(self.id), text=text, show_alert=alert, url=url, cache_time=cache_time)

    async def edit(self, text: str, kbd: Any | None = None, **kw: Any) -> Any:
        if self.app is None or self.app.bot is None:
            raise RuntimeError("bot net is not configured")
        data = dict(kw)
        if kbd is not None:
            data["reply_markup"] = kbd.to_dict() if hasattr(kbd, "to_dict") else kbd
        if self.chat_id is None or self.msg_id is None:
            if self.inline_message_id is None:
                return None
            return await self.app.bot_req("editMessageText", inline_message_id=self.inline_message_id, text=text, **data)
        return await self.app.bot_req("editMessageText", chat_id=self.chat_id, message_id=int(self.msg_id), text=text, **data)

    async def reply(self, txt: str, kbd: Any | None = None, topic_id: int | None = None, link_options: Any | None = None, **kw: Any) -> Any:
        from goygram import ext as rx
        if self.chat_id is None:
            return None
        if self.src == "bot" and self.app.bot is not None:
            data = dict(kw)
            if self.id is not None:
                data["reply_parameters"] = {"message_id": self.id}
            if kbd is not None:
                self._kbd(data, kbd)
            if topic_id is not None:
                data["message_thread_id"] = topic_id
            if link_options is not None:
                data["link_preview_options"] = link_options.to_dict() if hasattr(link_options, "to_dict") else link_options
            return await self.app.bot_req("sendMessage", chat_id=self.chat_id, text=txt, **data)
        if self.app.mt is not None:
            data = dict(kw)
            peer = await self.app.mt.resolve_peer(self.chat_id)
            if self.id is not None:
                data["reply_to"] = bytes(rx.serialize_constructor('inputReplyToMessage',
                    json.dumps({'reply_to_msg_id': int(self.id)})))
            if kbd is not None:
                data["kbd"] = kbd
            if link_options is not None:
                data["link_options"] = link_options
            return await self.app.mt_req("messages.sendMessage",
                peer=peer,
                message=txt,
                random_id=secrets.randbits(63),
                **data)
        return None

    def _kbd(self, data: dict[str, Any], kbd: Any) -> None:
        data["reply_markup"] = kbd.to_dict() if hasattr(kbd, "to_dict") else kbd

    async def forward_to(self, chat_id: int | str, *, via: str | None = None, **kw: Any) -> Any:
        if self.chat_id is None or self.id is None:
            return None
        if self.src == "bot":
            return await self.app.bot_req("forwardMessage", chat_id=chat_id, from_chat_id=self.chat_id, message_id=int(self.id), **kw)
        from_peer = await self.app.mt.resolve_peer(self.chat_id)
        to_peer = await self.app.mt.resolve_peer(self.app.raw_chat(chat_id))
        return await self.app.mt_req("messages.forwardMessages", from_peer=from_peer, to_peer=to_peer, id=[int(self.id)], random_id=[secrets.randbits(63)], **kw)

    async def pin(self, *, disable_notification: bool = False, **kw: Any) -> Any:
        if self.chat_id is None or self.id is None:
            return None
        if self.src == "bot":
            return await self.app.bot_req("pinChatMessage", chat_id=self.chat_id, message_id=int(self.id), disable_notification=disable_notification, **kw)
        peer = await self.app.mt.resolve_peer(self.chat_id)
        return await self.app.mt_req("messages.updatePinnedMessage", peer=peer, id=int(self.id), silent=disable_notification, **kw)

    async def unpin(self, **kw: Any) -> Any:
        if self.chat_id is None or self.id is None:
            return None
        if self.src == "bot":
            return await self.app.bot_req("unpinChatMessage", chat_id=self.chat_id, message_id=int(self.id), **kw)
        peer = await self.app.mt.resolve_peer(self.chat_id)
        return await self.app.mt_req("messages.updatePinnedMessage", peer=peer, id=int(self.id), unpin=True, **kw)

    async def react(self, reaction: Any, **kw: Any) -> Any:
        if self.chat_id is None or self.id is None:
            return None
        if self.src == "bot":
            return await self.app.bot_req("setMessageReaction", chat_id=self.chat_id, message_id=int(self.id), reaction=reaction, **kw)
        peer = await self.app.mt.resolve_peer(self.chat_id)
        return await self.app.mt_req("messages.sendReaction", peer=peer, msg_id=int(self.id), reaction=reaction, **kw)

    async def download(self, destination: str | None = None) -> Any:
        if self.src != "bot":
            raise RuntimeError("MTProto media download requires an upload.getFile location")
        media = self.get("document") or self.get("video") or self.get("audio") or self.get("voice") or self.get("animation") or self.get("video_note") or self.get("photo")
        if isinstance(media, list):
            media = media[-1] if media else None
        file_id = media.get("file_id") if isinstance(media, dict) else None
        if not file_id:
            raise ValueError("message has no downloadable Bot API file_id")
        return await self.app.download_file(file_id, destination)

    def net(self) -> Any:
        if self.src == "bot":
            if self.app.bot is None:
                raise RuntimeError("bot net is not configured")
            return self.app.bot
        if self.app.mt is None:
            raise RuntimeError("mt net is not configured")
        return self.app.mt

    async def delete(self) -> Any:
        if self.chat_id is None or self.id is None:
            return None
        if self.src == "bot" and self.app.bot is not None:
            return await self.app.bot_req("deleteMessage", chat_id=self.chat_id, message_id=self.id)
        if self.app.mt is not None:
            return await self.app.mt_req("messages.deleteMessages", id=[int(self.id)], revoke=True)
        return None

    @staticmethod
    def article(
        result_id: str,
        title: str,
        text: str,
        *,
        description: str | None = None,
        parse_mode: str | None = None,
        kbd: Any | None = None,
        url: str | None = None,
        hide_url: bool | None = None,
        thumb_url: str | None = None,
        thumb_width: int | None = None,
        thumb_height: int | None = None,
    ) -> dict[str, Any]:
        message: dict[str, Any] = {"message_text": text}
        if parse_mode is not None:
            message["parse_mode"] = parse_mode
        result: dict[str, Any] = {
            "type": "article",
            "id": result_id,
            "title": title,
            "input_message_content": message,
        }
        if kbd is not None:
            markup = kbd.to_dict() if hasattr(kbd, "to_dict") else kbd
            if isinstance(markup, list):
                markup = {"inline_keyboard": markup}
            result["reply_markup"] = markup
        if description is not None:
            result["description"] = description
        if url is not None:
            result["url"] = url
        if hide_url is not None:
            result["hide_url"] = hide_url
        if thumb_url is not None:
            result["thumb_url"] = thumb_url
        if thumb_width is not None:
            result["thumb_width"] = thumb_width
        if thumb_height is not None:
            result["thumb_height"] = thumb_height
        return result
