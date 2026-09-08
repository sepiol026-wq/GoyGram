# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from goygram.logging import get_logger
from goygram.errors import FloodWaitError

try:
    import aiohttp
    from aiohttp import web
except Exception:
    aiohttp = None
    web: Any = None


class BotNet:
    def __init__(
        self,
        token: str,
        bus: Any,
        timeout: int = 25,
        base: str = "https://api.telegram.org",
        webhook_url: str | None = None,
        webhook_host: str = "127.0.0.1",
        webhook_port: int = 8080,
        webhook_path: str = "/telegram/webhook",
        webhook_secret_token: str | None = None,
        webhook_max_body: int = 1024 * 1024,
        webhook_drop_pending_updates: bool = False,
        offset_path: str | Path | None = None,
    ) -> None:
        self.token = token
        self.bus = bus
        self.timeout = timeout
        self.base = f"{base}/bot{token}"
        self.sess: Any | None = None
        if offset_path is None:
            offset_path = Path.home() / ".goygram" / "offsets" / f"{hashlib.sha256(token.encode()).hexdigest()[:24]}.offset"
        self.offset_path = Path(offset_path)
        try:
            self.off = max(0, int(self.offset_path.read_text().strip()))
        except (OSError, ValueError):
            self.off = 0
        self.stop_ev = asyncio.Event()
        self.log = get_logger("goygram.botapi")
        self.webhook_url = webhook_url
        self.webhook_host = webhook_host
        self.webhook_port = int(webhook_port)
        self.webhook_path = "/" + webhook_path.strip("/")
        self.webhook_secret_token = webhook_secret_token
        self.webhook_max_body = int(webhook_max_body)
        self.webhook_drop_pending_updates = bool(webhook_drop_pending_updates)
        if self.webhook_port < 1 or self.webhook_port > 65535:
            raise ValueError("webhook_port must be between 1 and 65535")
        if self.webhook_max_body < 1024:
            raise ValueError("webhook_max_body must be at least 1024 bytes")
        if self.webhook_secret_token is not None and (
            not 1 <= len(self.webhook_secret_token) <= 256
            or re.fullmatch(r"[A-Za-z0-9_-]+", self.webhook_secret_token) is None
        ):
            raise ValueError("webhook_secret_token must contain 1-256 letters, digits, _ or -")
        self.web_runner: Any | None = None
        self.web_site: Any | None = None
        self.webhook_seen: set[int] = set()
        self.webhook_highest_update_id = -1

    def _save_offset(self, offset: int) -> None:
        self.offset_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", dir=self.offset_path.parent, delete=False) as handle:
            handle.write(str(offset))
            temp_path = Path(handle.name)
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, self.offset_path)

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
        await self.stop_webhook(delete_remote=True)
        if not self.sess:
            return
        if self.sess.closed:
            return
        await self.sess.close()

    async def set_webhook(self) -> Any:
        if not self.webhook_url:
            raise ValueError("webhook_url is required")
        data: dict[str, Any] = {
            "url": self.webhook_url,
            "drop_pending_updates": self.webhook_drop_pending_updates,
        }
        if self.webhook_secret_token is not None:
            data["secret_token"] = self.webhook_secret_token
        return await self.req("setWebhook", data)

    async def delete_webhook(self, drop_pending_updates: bool = False) -> Any:
        return await self.req("deleteWebhook", {"drop_pending_updates": drop_pending_updates})

    async def get_webhook_info(self) -> Any:
        return await self.req("getWebhookInfo")

    async def _webhook_request(self, request: Any) -> Any:
        if self.webhook_secret_token is not None:
            received = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
            if not hmac.compare_digest(received, self.webhook_secret_token):
                return web.json_response({"ok": False, "error": "forbidden"}, status=403)
        content_length = request.headers.get("Content-Length")
        if content_length is not None:
            try:
                if int(content_length) > self.webhook_max_body:
                    return web.json_response({"ok": False, "error": "body too large"}, status=413)
            except ValueError:
                return web.json_response({"ok": False, "error": "invalid content length"}, status=400)
        raw = await request.read()
        if len(raw) > self.webhook_max_body:
            return web.json_response({"ok": False, "error": "body too large"}, status=413)
        try:
            update = json.loads(raw)
        except (TypeError, ValueError):
            return web.json_response({"ok": False, "error": "invalid json"}, status=400)
        if not isinstance(update, dict) or not isinstance(update.get("update_id"), int):
            return web.json_response({"ok": False, "error": "invalid update"}, status=400)
        update_id = int(update["update_id"])
        if update_id <= self.webhook_highest_update_id or update_id in self.webhook_seen:
            return web.json_response({"ok": True, "duplicate": True})
        pkt = self.norm(update)
        if pkt is not None:
            await self.bus.push("bot", pkt)
        self.webhook_seen.add(update_id)
        self.webhook_highest_update_id = max(self.webhook_highest_update_id, update_id)
        if len(self.webhook_seen) > 4096:
            floor = self.webhook_highest_update_id - 2048
            self.webhook_seen = {item for item in self.webhook_seen if item >= floor}
        return web.json_response({"ok": True})

    async def start_webhook(self) -> None:
        if not self.webhook_url:
            raise ValueError("webhook_url is required")
        if web is None:
            raise RuntimeError("aiohttp is not installed; run: pip install aiohttp")
        web_mod: Any = web
        if self.web_runner is not None:
            return
        await self.boot()
        app = web_mod.Application(client_max_size=self.webhook_max_body)
        app.router.add_post(self.webhook_path, self._webhook_request)
        self.web_runner = web_mod.AppRunner(app, access_log=None)
        await self.web_runner.setup()
        self.web_site = web_mod.TCPSite(self.web_runner, self.webhook_host, self.webhook_port)
        await self.web_site.start()
        try:
            await self.set_webhook()
        except Exception:
            await self.stop_webhook(delete_remote=False)
            raise
        self.log.info("Bot webhook is enabled at %s", self.webhook_path)

    async def stop_webhook(self, delete_remote: bool = True) -> None:
        if self.web_runner is None:
            return
        if delete_remote and self.sess and not self.sess.closed:
            try:
                await self.delete_webhook(drop_pending_updates=False)
            except Exception as exc:
                self.log.warning("Failed to delete webhook during shutdown: %r", exc)
        if self.web_runner is not None:
            await self.web_runner.cleanup()
        self.web_site = None
        self.web_runner = None

    async def req(self, m: str, data: dict[str, Any] | None = None, _attempt: int = 0) -> Any:
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
            if r.status == 429 and _attempt < 5:
                retry_after = raw.get("parameters", {}).get("retry_after", 1) if isinstance(raw, dict) else 1
                await asyncio.sleep(max(1, min(int(retry_after), 300)))
                return await self.req(m, data, _attempt + 1)
            if r.status == 429:
                retry_after = raw.get("parameters", {}).get("retry_after", 1) if isinstance(raw, dict) else 1
                raise FloodWaitError(429, "BOT_API_RATE_LIMIT", max(1, int(retry_after)))
            raise RuntimeError(f"botapi {m} http {r.status}: {raw}")
        if not raw.get("ok"):
            raise RuntimeError(f"botapi {m} fail: {raw}")
        return raw["result"]

    async def download_file(self, file_id: str, destination: str | Path | None = None) -> bytes | Path:
        info = await self.req("getFile", {"file_id": file_id})
        if not isinstance(info, dict) or not isinstance(info.get("file_path"), str):
            raise RuntimeError("botapi getFile returned no file_path")
        await self.boot()
        assert self.sess is not None
        url = f"https://api.telegram.org/file/bot{self.token}/{info['file_path']}"
        async with self.sess.get(url) as response:
            if response.status >= 400:
                raise RuntimeError(f"botapi download file http {response.status}")
            if destination is None:
                return await response.read()
            target = Path(destination)
            target.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as handle:
                temp_path = Path(handle.name)
                async for chunk in response.content.iter_chunked(1024 * 1024):
                    handle.write(chunk)
            os.replace(temp_path, target)
            return target

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
                "update_type": "chat_member" if "chat_member" in upd else "my_chat_member",
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
                "update_type": "callback_query",
                "upd_id": upd.get("update_id"),
                "query_id": cb.get("id"),
                "msg_id": msg.get("message_id"),
                "chat_id": chat.get("id"),
                "from_id": usr.get("id"),
                "inline_message_id": cb.get("inline_message_id"),
                "data": cb.get("data", ""),
                "text": (msg.get("text") or msg.get("caption") or ""),
                "raw": upd,
            }
        inline = upd.get("inline_query")
        if isinstance(inline, dict):
            usr = inline.get("from") or {}
            return {
                "kind": "inline",
                "src": "bot",
                "update_type": "inline_query",
                "upd_id": upd.get("update_id"),
                "query_id": inline.get("id"),
                "from_id": usr.get("id"),
                "query": inline.get("query", ""),
                "offset": inline.get("offset", ""),
                "chat_type": inline.get("chat_type"),
                "location": inline.get("location"),
                "raw": upd,
            }
        chosen = upd.get("chosen_inline_result")
        if isinstance(chosen, dict):
            usr = chosen.get("from") or {}
            return {
                "kind": "update",
                "src": "bot",
                "update_type": "chosen_inline_result",
                "upd_id": upd.get("update_id"),
                "result_id": chosen.get("result_id"),
                "from_id": usr.get("id"),
                "query": chosen.get("query", ""),
                "inline_message_id": chosen.get("inline_message_id"),
                "raw": upd,
            }
        message_key = next(
            (
                key
                for key in (
                    "message",
                    "edited_message",
                    "channel_post",
                    "edited_channel_post",
                )
                if isinstance(upd.get(key), dict)
            ),
            None,
        )
        if message_key is not None:
            msg = upd[message_key]
            chat = msg.get("chat") or {}
            usr = msg.get("from") or {}
            txt = msg.get("text")
            if txt is None:
                txt = msg.get("caption") or ""
            return {
                "kind": "edit" if message_key.startswith("edited_") else "msg",
                "src": "bot",
                "update_type": message_key,
                "upd_id": upd.get("update_id"),
                "msg_id": msg.get("message_id"),
                "chat_id": chat.get("id"),
                "from_id": usr.get("id"),
                "text": txt,
                "raw": upd,
            }
        update_type = next((key for key in upd if key != "update_id"), "unknown")
        return {
            "kind": "update",
            "src": "bot",
            "upd_id": upd.get("update_id"),
            "update_type": update_type,
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
                        "allowed_updates": [],
                    },
                )
                for upd in res:
                    uid = int(upd.get("update_id", 0))
                    if uid < self.off:
                        continue
                    pkt = self.norm(upd)
                    if pkt:
                        self.log.debug("Incoming packet: %s", pkt)
                        await self.bus.push("bot", pkt)
                    self.off = uid + 1
                    self._save_offset(self.off)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                message = str(e)
                if "botapi getUpdates http 401" in message or "botapi getUpdates http 404" in message:
                    self.log.critical("Bot API authentication or endpoint failure; polling stopped.")
                    self.stop_ev.set()
                    break
                self.log.error("Polling error: %r", e)
                await self.bus.push("sys", {"kind": "err", "src": "bot", "text": repr(e)})
                await asyncio.sleep(1.0)
