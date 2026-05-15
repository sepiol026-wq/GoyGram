# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
# Contains elements of Aiogram (MIT) / Pyrogram (LGPL-3.0)
from __future__ import annotations

import asyncio
import json
from typing import Any

from goygram.logging import get_logger

try:
    import aiohttp
except Exception:
    aiohttp = None


class BotNet:
    def __init__(
        self,
        token: str,
        bus: Any,
        timeout: int = 25,
        base: str = "https://api.telegram.org",
    ) -> None:
        self.token = token
        self.bus = bus
        self.timeout = timeout
        self.base = f"{base}/bot{token}"
        self.sess: Any | None = None
        self.off = 0
        self.stop_ev = asyncio.Event()
        self.log = get_logger("goygram.botapi")

    def mod(self) -> Any:
        if aiohttp is None:
            raise RuntimeError("aiohttp is not installed; run: pip install aiohttp")
        return aiohttp

    async def boot(self) -> None:
        if self.sess and not self.sess.closed:
            return
        mod = self.mod()
        self.sess = mod.ClientSession(
            timeout=mod.ClientTimeout(total=self.timeout + 10),
            trust_env=True,
        )

    async def close(self) -> None:
        self.stop_ev.set()
        if not self.sess:
            return
        if self.sess.closed:
            return
        await self.sess.close()

    async def req(self, m: str, data: dict[str, Any] | None = None) -> Any:
        await self.boot()
        assert self.sess is not None
        body = self.body(data or {})
        self.log.debug("Outgoing request method=%s payload=%s", m, data)
        async with self.sess.post(f"{self.base}/{m}", **body) as r:
            try:
                raw = await r.json(content_type=None)
            except Exception:
                txt = await r.text()
                try:
                    raw = json.loads(txt)
                except Exception:
                    raw = {"ok": False, "text": txt}
        if r.status >= 400:
            if r.status == 409 and m == "getUpdates":
                await self.req("deleteWebhook", {"drop_pending_updates": False})
                self.log.error("Webhook conflict detected. Webhook deleted and polling will retry.")
                return []
            raise RuntimeError(f"botapi {m} http {r.status}: {raw}")
        if not raw.get("ok"):
            raise RuntimeError(f"botapi {m} fail: {raw}")
        return raw["result"]

    def body(self, data: dict[str, Any]) -> dict[str, Any]:
        mod = self.mod()
        if not self.has_file(data):
            return {"json": data}
        form = mod.FormData()
        for k, v in data.items():
            self.add_form(form, k, v)
        return {"data": form}

    def has_file(self, v: Any) -> bool:
        if isinstance(v, (bytes, bytearray, memoryview)):
            return True
        if isinstance(v, tuple) and len(v) >= 2 and isinstance(v[1], (bytes, bytearray, memoryview)):
            return True
        if isinstance(v, list):
            return any(self.has_file(x) for x in v)
        if isinstance(v, dict):
            return any(self.has_file(x) for x in v.values())
        return False

    def add_form(self, form: Any, k: str, v: Any) -> None:
        if v is None:
            return
        if hasattr(v, "to_dict"):
            self.add_form(form, k, v.to_dict())
            return
        if isinstance(v, tuple) and len(v) >= 2 and isinstance(v[1], (bytes, bytearray, memoryview)):
            name = str(v[0])
            data = bytes(v[1])
            ct = v[2] if len(v) > 2 else "application/octet-stream"
            form.add_field(k, data, filename=name, content_type=ct)
            return
        if isinstance(v, (bytes, bytearray, memoryview)):
            form.add_field(k, bytes(v), filename=f"{k}.bin", content_type="application/octet-stream")
            return
        if isinstance(v, (dict, list)):
            form.add_field(k, json.dumps(v, ensure_ascii=False))
            return
        if isinstance(v, bool):
            form.add_field(k, "true" if v else "false")
            return
        form.add_field(k, str(v))

    def norm(self, upd: dict[str, Any]) -> dict[str, Any] | None:
        poll = upd.get("poll")
        if isinstance(poll, dict):
            return {
                "kind": "poll",
                "src": "bot",
                "upd_id": upd.get("update_id"),
                "poll_id": poll.get("id"),
                "question": poll.get("question", ""),
                "is_closed": bool(poll.get("is_closed", False)),
                "raw": upd,
            }
        mem = upd.get("chat_member") or upd.get("my_chat_member")
        if isinstance(mem, dict):
            chat = mem.get("chat") or {}
            usr = mem.get("from") or {}
            old = mem.get("old_chat_member") or {}
            new = mem.get("new_chat_member") or {}
            target = new.get("user") or old.get("user") or {}
            return {
                "kind": "member",
                "src": "bot",
                "upd_id": upd.get("update_id"),
                "chat_id": chat.get("id"),
                "from_id": usr.get("id"),
                "user_id": target.get("id"),
                "old_status": old.get("status"),
                "new_status": new.get("status"),
                "raw": upd,
            }
        cb = upd.get("callback_query")
        if isinstance(cb, dict):
            msg = cb.get("message") or {}
            chat = msg.get("chat") or {}
            usr = cb.get("from") or {}
            return {
                "kind": "cb",
                "src": "bot",
                "upd_id": upd.get("update_id"),
                "query_id": cb.get("id"),
                "msg_id": msg.get("message_id"),
                "chat_id": chat.get("id"),
                "from_id": usr.get("id"),
                "data": cb.get("data", ""),
                "text": (msg.get("text") or msg.get("caption") or ""),
                "raw": upd,
            }
        msg = upd.get("message") or upd.get("edited_message")
        if not isinstance(msg, dict):
            return None
        chat = msg.get("chat") or {}
        usr = msg.get("from") or {}
        txt = msg.get("text")
        if txt is None:
            txt = msg.get("caption") or ""
        return {
            "kind": "msg",
            "src": "bot",
            "upd_id": upd.get("update_id"),
            "msg_id": msg.get("message_id"),
            "chat_id": chat.get("id"),
            "from_id": usr.get("id"),
            "text": txt,
            "raw": upd,
        }

    async def send_msg(
        self,
        chat_id: int | str,
        text: str,
        reply_to: int | None = None,
        kbd: Any | None = None,
        topic_id: int | None = None,
        media: Any | None = None,
        link_options: Any | None = None,
        link_preview_options: Any | None = None,
        **kw: Any,
    ) -> dict[str, Any]:
        data: dict[str, Any] = {"chat_id": chat_id, "text": text, **kw}
        if reply_to is not None:
            data["reply_parameters"] = {"message_id": reply_to}
        if kbd is not None:
            data["reply_markup"] = kbd.to_dict() if hasattr(kbd, "to_dict") else kbd
        if topic_id is not None:
            data["message_thread_id"] = topic_id
        if media is not None:
            data["media"] = media.to_dict() if hasattr(media, "to_dict") else media
        opts = link_preview_options if link_preview_options is not None else link_options
        if opts is not None:
            data["link_preview_options"] = opts.to_dict() if hasattr(opts, "to_dict") else opts
        return await self.req("sendMessage", data)

    async def del_msg(self, chat_id: int | str, msg_id: int) -> bool:
        res = await self.req("deleteMessage", {"chat_id": chat_id, "message_id": msg_id})
        return bool(res)

    async def call(self, meth: str, **kw: Any) -> Any:
        return await self.req(meth, {k: v for k, v in kw.items() if v is not None})

    async def spin(self) -> None:
        await self.boot()
        while not self.stop_ev.is_set():
            try:
                res = await self.req(
                    "getUpdates",
                    {
                        "offset": self.off,
                        "timeout": self.timeout,
                        "allowed_updates": ["message", "edited_message", "callback_query", "poll", "chat_member", "my_chat_member"],
                    },
                )
                for upd in res:
                    uid = int(upd.get("update_id", 0))
                    if uid >= self.off:
                        self.off = uid + 1
                    pkt = self.norm(upd)
                    if not pkt:
                        continue
                    self.log.debug("Incoming packet: %s", pkt)
                    await self.bus.push("bot", pkt)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.log.error("Polling error: %r", e)
                await self.bus.push("sys", {"kind": "err", "src": "bot", "text": repr(e)})
                await asyncio.sleep(1.0)
