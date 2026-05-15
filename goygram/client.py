# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
from __future__ import annotations

import asyncio
import signal
from collections.abc import Awaitable, Callable
import logging
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from goygram.api.methods import BotAPI
from goygram.core.bus import Bus
from goygram.core.disp import Disp
from goygram.types.cb import CbObj
from goygram.types.member import MemberObj
from goygram.types.msg import MsgObj
from goygram.types.poll import PollObj
from goygram.logging import get_logger
from goygram.security import bootstrap_session
from goygram.filters import Filter
from goygram.dc_fetcher import get_dynamic_dc_config, pick_dc_endpoint
from goygram.utils import print_methods

Fn = Callable[[MsgObj], Awaitable[Any]]
CbFn = Callable[[CbObj], Awaitable[Any]]
PollFn = Callable[[PollObj], Awaitable[Any]]
MemFn = Callable[[MemberObj], Awaitable[Any]]


class BotCfg(BaseModel):
    model_config = ConfigDict(frozen=True)
    token: str
    timeout: int = 25
    base: str = "https://api.telegram.org"


class MtCfg(BaseModel):
    model_config = ConfigDict(frozen=True)
    host: str
    port: int
    key: bytes | None = None
    iv: bytes | None = None


class AppCfg(BaseModel):
    model_config = ConfigDict(frozen=True)
    bot: BotCfg | None = None
    mt: MtCfg | None = None
    bus_max: int = 0


class AppCore:
    def __init__(self, cfg: AppCfg, api_id: int | str | None = None, api_hash: str | None = None) -> None:
        self.cfg = cfg
        self.bus = Bus(cfg.bus_max)
        self.bot = None
        self.mt = None
        self.api = None
        if cfg.bot:
            from goygram.vendor.botapi import BotNet

            self.bot = BotNet(cfg.bot.token, self.bus, cfg.bot.timeout, cfg.bot.base)
            self.api = BotAPI(self.bot)
        if cfg.mt:
            from goygram.vendor.mtproto import MTNet

            self.mt = MTNet(cfg.mt.host, cfg.mt.port, self.bus, cfg.mt.key, cfg.mt.iv)
        self.disp = Disp(self, self.bus)
        self.hook: list[Fn] = []
        self.cb_hook: list[CbFn] = []
        self.cmd_hook: list[Fn] = []
        self.poll_hook: list[PollFn] = []
        self.member_hook: list[MemFn] = []
        self.stop_ev = asyncio.Event()
        self.log = get_logger("goygram.app")
        self.self_id: int | None = None
        self.api_id = api_id
        self.api_hash = api_hash

    def on_msg(self, fn: Fn | None = None, filt: Filter | None = None):
        def wrap(inner: Fn) -> Fn:
            if filt is None:
                self.hook.append(inner)
                return inner
            async def guarded(msg: MsgObj) -> Any:
                if filt(msg):
                    return await inner(msg)
                return None
            self.hook.append(guarded)
            return inner
        if fn is not None:
            return wrap(fn)
        return wrap

    def on_cb(self, fn: CbFn) -> CbFn:
        self.cb_hook.append(fn)
        return fn

    def on_poll(self, fn: PollFn) -> PollFn:
        self.poll_hook.append(fn)
        return fn

    def on_member(self, fn: MemFn) -> MemFn:
        self.member_hook.append(fn)
        return fn

    def on_cmd(self, *name: str) -> Callable[[Fn], Fn]:
        cmd = {x.lower().lstrip("/") for x in name}
        def wrap(fn: Fn) -> Fn:
            async def inner(msg: MsgObj) -> Any:
                txt = (msg.text or "").strip()
                if not txt.startswith("/"):
                    return None
                head = txt.split(None, 1)[0][1:]
                base = head.split("@", 1)[0].lower()
                if base not in cmd:
                    return None
                return await fn(msg)
            self.cmd_hook.append(inner)
            return fn
        return wrap

    def _bot_method_name(self, name: str) -> str:
        if "_" in name:
            parts = name.split("_")
            return parts[0] + "".join(x[:1].upper() + x[1:] for x in parts[1:])
        return name

    def _dynamic_method(self, name: str):
        async def call(**kw: Any) -> Any:
            if name.startswith("mt_"):
                return await self.mt_req(name[3:], **kw)
            return await self.bot_req(self._bot_method_name(name), **kw)
        return call

    def help(self) -> None:
        print_methods(self)

    def __getattr__(self, name: str) -> Any:
        if self.api is not None and hasattr(self.api, name):
            return getattr(self.api, name)
        if (self.bot is not None and not name.startswith("mt_")) or (self.mt is not None and name.startswith("mt_")):
            return self._dynamic_method(name)
        raise AttributeError(name)

    def __dir__(self) -> list[str]:
        base = set(super().__dir__())
        base.update({"help", "sendDocument", "getChat", "getUpdates", "mt_get_dialogs"})
        return sorted(base)

    def stop(self) -> None:
        self.stop_ev.set()

    def raw_chat(self, chat_id: int | str) -> int | str:
        if isinstance(chat_id, str) and ":" in chat_id:
            pfx, raw = chat_id.split(":", 1)
            if pfx in {"bot", "mt"}:
                if raw.lstrip("-").isdigit():
                    return int(raw)
                return raw
        return chat_id

    def via(self, chat_id: int | str, via: str | None = None) -> str:
        if via in {"bot", "mt"}:
            if via == "bot" and self.bot is None:
                raise RuntimeError("bot net is not configured")
            if via == "mt" and self.mt is None:
                raise RuntimeError("mt net is not configured")
            return via
        if isinstance(chat_id, str) and chat_id.startswith("bot:"):
            if self.bot is None:
                raise RuntimeError("bot net is not configured")
            return "bot"
        if isinstance(chat_id, str) and chat_id.startswith("mt:"):
            if self.mt is None:
                raise RuntimeError("mt net is not configured")
            return "mt"
        if self.bot is not None:
            return "bot"
        if self.mt is not None:
            return "mt"
        raise RuntimeError("no transport configured")

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
        via: str | None = None,
        **kw: Any,
    ) -> Any:
        way = self.via(chat_id, via)
        dst = self.raw_chat(chat_id)
        opts = link_preview_options if link_preview_options is not None else link_options
        if way == "bot":
            if self.api is not None:
                data = dict(kw)
                if reply_to is not None:
                    data["reply_parameters"] = {"message_id": reply_to}
                if kbd is not None:
                    data["reply_markup"] = kbd.to_dict() if hasattr(kbd, "to_dict") else kbd
                if topic_id is not None:
                    data["message_thread_id"] = topic_id
                if media is not None:
                    data["media"] = media
                if opts is not None:
                    data["link_preview_options"] = opts.to_dict() if hasattr(opts, "to_dict") else opts
                if "link_preview_options" in data:
                    return await self.bot_req("sendMessage", chat_id=dst, text=text, **data)
                return await self.api.send_message(dst, text, **data)
            assert self.bot is not None
            data = dict(kw)
            if reply_to is not None:
                data["reply_to"] = reply_to
            if kbd is not None:
                data["kbd"] = kbd
            if topic_id is not None:
                data["topic_id"] = topic_id
            if media is not None:
                data["media"] = media
            if opts is not None:
                data["link_options"] = opts
            return await self.bot.send_msg(dst, text, **data)
        assert self.mt is not None
        data = dict(kw)
        if reply_to is not None:
            data["reply_to"] = reply_to
        if kbd is not None:
            data["kbd"] = kbd
        if topic_id is not None:
            data["topic_id"] = topic_id
        if media is not None:
            data["media"] = media
        if opts is not None:
            data["link_options"] = opts.to_dict() if hasattr(opts, "to_dict") else opts
        return await self.mt.send_msg(dst, text, **data)

    async def del_msg(self, chat_id: int | str, msg_id: int, via: str | None = None) -> Any:
        way = self.via(chat_id, via)
        dst = self.raw_chat(chat_id)
        if way == "bot":
            assert self.bot is not None
            return await self.bot.del_msg(dst, msg_id)
        assert self.mt is not None
        return await self.mt.del_msg(dst, msg_id)

    async def edit_text(self, chat_id: int | str, msg_id: int, text: str, kbd: Any | None = None, via: str | None = None, **kw: Any) -> Any:
        way = self.via(chat_id, via)
        dst = self.raw_chat(chat_id)
        if way == "bot":
            if self.api is not None:
                data = dict(kw)
                if kbd is not None:
                    data["reply_markup"] = kbd.to_dict() if hasattr(kbd, "to_dict") else kbd
                return await self.api.edit_message_text(text=text, chat_id=dst, message_id=msg_id, **data)
            data = dict(kw)
            if kbd is not None:
                data["reply_markup"] = kbd
            return await self.bot_req("editMessageText", chat_id=dst, message_id=msg_id, text=text, **data)
        raise RuntimeError("edit_text is only available for bot transport")

    async def answer_cb(self, cb_id: str, text: str | None = None, alert: bool = False, url: str | None = None, cache_time: int = 0) -> Any:
        return await self.bot_req("answerCallbackQuery", callback_query_id=cb_id, text=text, show_alert=alert, url=url, cache_time=cache_time)

    async def send_photo(self, chat_id: int | str, photo: Any, caption: str | None = None, kbd: Any | None = None, via: str | None = None, **kw: Any) -> Any:
        way = self.via(chat_id, via)
        dst = self.raw_chat(chat_id)
        if way == "bot":
            data = dict(kw)
            if caption is not None:
                data["caption"] = caption
            if kbd is not None:
                data["reply_markup"] = kbd.to_dict() if hasattr(kbd, "to_dict") else kbd
            return await self.bot_req("sendPhoto", chat_id=dst, photo=photo, **data)
        return await self.send_msg(dst, caption or "", media={"kind": "photo", "photo": photo}, kbd=kbd, via=way, **kw)

    async def send_doc(self, chat_id: int | str, document: Any, caption: str | None = None, kbd: Any | None = None, via: str | None = None, **kw: Any) -> Any:
        way = self.via(chat_id, via)
        dst = self.raw_chat(chat_id)
        if way == "bot":
            data = dict(kw)
            if caption is not None:
                data["caption"] = caption
            if kbd is not None:
                data["reply_markup"] = kbd.to_dict() if hasattr(kbd, "to_dict") else kbd
            return await self.bot_req("sendDocument", chat_id=dst, document=document, **data)
        return await self.send_msg(dst, caption or "", media={"kind": "document", "document": document}, kbd=kbd, via=way, **kw)

    async def send_media_group(self, chat_id: int | str, media: list[dict[str, Any]], via: str | None = None, **kw: Any) -> Any:
        way = self.via(chat_id, via)
        dst = self.raw_chat(chat_id)
        if way == "bot":
            return await self.bot_req("sendMediaGroup", chat_id=dst, media=media, **kw)
        return await self.send_msg(dst, "", media={"kind": "group", "items": media}, via=way, **kw)

    async def set_webhook(self, url: str, **kw: Any) -> Any:
        return await self.bot_req("setWebhook", url=url, **kw)

    async def delete_webhook(self, drop_pending_updates: bool = False) -> Any:
        return await self.bot_req("deleteWebhook", drop_pending_updates=drop_pending_updates)

    async def get_webhook_info(self) -> Any:
        return await self.bot_req("getWebhookInfo")

    def html(self, text: str) -> dict[str, Any]:
        return {"text": text, "parse_mode": "HTML"}

    def md(self, text: str) -> dict[str, Any]:
        return {"text": text, "parse_mode": "MarkdownV2"}

    async def bot_req(self, meth: str, **kw: Any) -> Any:
        if self.bot is None:
            raise RuntimeError("bot net is not configured")
        data = {k: v for k, v in kw.items() if v is not None}
        if hasattr(self.bot, "call"):
            return await self.bot.call(meth, **data)
        return await self.bot.req(meth, data)

    async def mt_req(self, act: str, **kw: Any) -> Any:
        if self.mt is None:
            raise RuntimeError("mt net is not configured")
        data = {k: v.to_dict() if hasattr(v, "to_dict") else v for k, v in kw.items() if v is not None}
        if hasattr(self.mt, "call"):
            return await self.mt.call(act, **data)
        if hasattr(self.mt, "req"):
            return await self.mt.req(act, data)
        return await self.mt.send({"act": act, **data})

    async def get_admins(self, chat_id: int | str, via: str | None = None) -> Any:
        way = self.via(chat_id, via)
        dst = self.raw_chat(chat_id)
        if way == "bot":
            return await self.bot_req("getChatAdministrators", chat_id=dst)
        return await self.mt_req("get_admins", chat_id=dst)

    async def get_owner(self, chat_id: int | str, via: str | None = None) -> Any:
        way = self.via(chat_id, via)
        dst = self.raw_chat(chat_id)
        if way == "bot":
            admins = await self.get_admins(dst, via="bot")
            if isinstance(admins, list):
                for item in admins:
                    status = item.get("status")
                    if status in {"creator", "owner"}:
                        return item
            return await self.bot_req("getChat", chat_id=dst)
        return await self.mt_req("get_owner", chat_id=dst)

    async def get_chat_full(self, chat_id: int | str, via: str | None = None) -> Any:
        way = self.via(chat_id, via)
        dst = self.raw_chat(chat_id)
        if way == "bot":
            return await self.bot_req("getChat", chat_id=dst)
        return await self.mt_req("get_chat_full", chat_id=dst)

    async def create_topic(self, chat_id: int | str, name: str, icon_color: int | None = None, via: str | None = None, **kw: Any) -> Any:
        way = self.via(chat_id, via)
        dst = self.raw_chat(chat_id)
        if way == "bot":
            return await self.bot_req("createForumTopic", chat_id=dst, name=name, icon_color=icon_color, **kw)
        return await self.mt_req("create_topic", chat_id=dst, name=name, icon_color=icon_color, **kw)

    async def edit_topic(self, chat_id: int | str, topic_id: int, name: str | None = None, icon_custom_emoji_id: str | None = None, via: str | None = None) -> Any:
        way = self.via(chat_id, via)
        dst = self.raw_chat(chat_id)
        if way == "bot":
            return await self.bot_req("editForumTopic", chat_id=dst, message_thread_id=topic_id, name=name, icon_custom_emoji_id=icon_custom_emoji_id)
        return await self.mt_req("edit_topic", chat_id=dst, topic_id=topic_id, name=name, icon_custom_emoji_id=icon_custom_emoji_id)

    async def close_topic(self, chat_id: int | str, topic_id: int, via: str | None = None) -> Any:
        way = self.via(chat_id, via)
        dst = self.raw_chat(chat_id)
        if way == "bot":
            return await self.bot_req("closeForumTopic", chat_id=dst, message_thread_id=topic_id)
        return await self.mt_req("close_topic", chat_id=dst, topic_id=topic_id)

    async def reopen_topic(self, chat_id: int | str, topic_id: int, via: str | None = None) -> Any:
        way = self.via(chat_id, via)
        dst = self.raw_chat(chat_id)
        if way == "bot":
            return await self.bot_req("reopenForumTopic", chat_id=dst, message_thread_id=topic_id)
        return await self.mt_req("reopen_topic", chat_id=dst, topic_id=topic_id)

    async def delete_topic(self, chat_id: int | str, topic_id: int, via: str | None = None) -> Any:
        way = self.via(chat_id, via)
        dst = self.raw_chat(chat_id)
        if way == "bot":
            return await self.bot_req("deleteForumTopic", chat_id=dst, message_thread_id=topic_id)
        return await self.mt_req("delete_topic", chat_id=dst, topic_id=topic_id)

    async def unpin_all_topic_msgs(self, chat_id: int | str, topic_id: int, via: str | None = None) -> Any:
        way = self.via(chat_id, via)
        dst = self.raw_chat(chat_id)
        if way == "bot":
            return await self.bot_req("unpinAllForumTopicMessages", chat_id=dst, message_thread_id=topic_id)
        return await self.mt_req("unpin_all_topic_msgs", chat_id=dst, topic_id=topic_id)

    async def edit_general_topic(self, chat_id: int | str, name: str, via: str | None = None) -> Any:
        way = self.via(chat_id, via)
        dst = self.raw_chat(chat_id)
        if way == "bot":
            return await self.bot_req("editGeneralForumTopic", chat_id=dst, name=name)
        return await self.mt_req("edit_general_topic", chat_id=dst, name=name)

    async def close_general_topic(self, chat_id: int | str, via: str | None = None) -> Any:
        way = self.via(chat_id, via)
        dst = self.raw_chat(chat_id)
        if way == "bot":
            return await self.bot_req("closeGeneralForumTopic", chat_id=dst)
        return await self.mt_req("close_general_topic", chat_id=dst)

    async def reopen_general_topic(self, chat_id: int | str, via: str | None = None) -> Any:
        way = self.via(chat_id, via)
        dst = self.raw_chat(chat_id)
        if way == "bot":
            return await self.bot_req("reopenGeneralForumTopic", chat_id=dst)
        return await self.mt_req("reopen_general_topic", chat_id=dst)

    async def hide_general_topic(self, chat_id: int | str, via: str | None = None) -> Any:
        way = self.via(chat_id, via)
        dst = self.raw_chat(chat_id)
        if way == "bot":
            return await self.bot_req("hideGeneralForumTopic", chat_id=dst)
        return await self.mt_req("hide_general_topic", chat_id=dst)

    async def unhide_general_topic(self, chat_id: int | str, via: str | None = None) -> Any:
        way = self.via(chat_id, via)
        dst = self.raw_chat(chat_id)
        if way == "bot":
            return await self.bot_req("unhideGeneralForumTopic", chat_id=dst)
        return await self.mt_req("unhide_general_topic", chat_id=dst)

    async def close(self) -> None:
        self.stop_ev.set()
        await self.disp.close()
        if self.bot:
            await self.bot.close()
        if self.mt:
            await self.mt.close()

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self.stop)
            except Exception:
                continue
        self.log.info("Starting GoyGram core.")
        tasks = [asyncio.create_task(self.disp.consume(), name="disp")]
        if self.bot:
            self.log.info("Bot transport is enabled.")
            try:
                await self.delete_webhook(drop_pending_updates=False)
            except Exception as e:
                self.log.error("Failed to clear webhook before polling: %r", e)
            tasks.append(asyncio.create_task(self.bot.spin(), name="bot"))
        if self.mt:
            self.log.info("MT transport is enabled.")
            tasks.append(asyncio.create_task(self.mt.spin(), name="mt"))
            await bootstrap_session(self, api_id=self.api_id, api_hash=self.api_hash)
        try:
            await self.stop_ev.wait()
        finally:
            await self.close()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


class GoyGram:
    def __init__(
        self,
        bot_token: str | None = None,
        mt_host: str | None = None,
        mt_port: int | None = None,
        mt_key: bytes | None = None,
        mt_iv: bytes | None = None,
        bot_timeout: int = 25,
        bot_base: str = "https://api.telegram.org",
        bus_max: int = 0,
        api_id: int | str | None = None,
        api_hash: str | None = None,
    ) -> None:
        bot = BotCfg(token=bot_token, timeout=bot_timeout, base=bot_base) if bot_token is not None else None
        log = get_logger("goygram.dc")
        resolved_host = mt_host
        resolved_port = mt_port

        if bot is None and resolved_host is None:
            try:
                dc_map = get_dynamic_dc_config()
                selected = pick_dc_endpoint(dc_map, preferred_dc=2)
                resolved_host, resolved_port = selected.host, selected.port
                log.info("Dynamic DC routing selected dc%s %s:%s", selected.dc_id, selected.host, selected.port)
            except Exception as e:
                log.error("Dynamic DC routing failed: %r", e)
                resolved_host, resolved_port = "149.154.167.50", 443
                log.warning("Using fallback MT endpoint %s:%s", resolved_host, resolved_port)

        mt = MtCfg(host=resolved_host, port=resolved_port, key=mt_key, iv=mt_iv) if resolved_host is not None and resolved_port is not None else None
        self.core = AppCore(AppCfg(bot=bot, mt=mt, bus_max=bus_max), api_id=api_id, api_hash=api_hash)

    def on_msg(self, fn: Fn | None = None, filt: Filter | None = None):
        return self.core.on_msg(fn, filt=filt)

    def _bot_method_name(self, name: str) -> str:
        if "_" in name:
            parts = name.split("_")
            return parts[0] + "".join(x[:1].upper() + x[1:] for x in parts[1:])
        return name

    def _dynamic_method(self, name: str):
        async def call(**kw: Any) -> Any:
            if name.startswith("mt_"):
                return await self.mt_req(name[3:], **kw)
            return await self.bot_req(self._bot_method_name(name), **kw)
        return call

    def help(self) -> None:
        print_methods(self)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.core, name)

    def on_cb(self, fn: CbFn) -> CbFn:
        return self.core.on_cb(fn)

    def on_cmd(self, *name: str) -> Callable[[Fn], Fn]:
        return self.core.on_cmd(*name)

    def on_poll(self, fn: PollFn) -> PollFn:
        return self.core.on_poll(fn)

    def on_member(self, fn: MemFn) -> MemFn:
        return self.core.on_member(fn)

    def help(self) -> None:
        self.core.help()

    def __dir__(self) -> list[str]:
        return sorted(set(super().__dir__()) | set(dir(self.core)))

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
        via: str | None = None,
        **kw: Any,
    ) -> Any:
        return await self.core.send_msg(chat_id, text, reply_to=reply_to, kbd=kbd, topic_id=topic_id, media=media, link_options=link_options, link_preview_options=link_preview_options, via=via, **kw)

    async def del_msg(self, chat_id: int | str, msg_id: int, via: str | None = None) -> Any:
        return await self.core.del_msg(chat_id, msg_id, via=via)

    async def edit_text(self, chat_id: int | str, msg_id: int, text: str, kbd: Any | None = None, via: str | None = None, **kw: Any) -> Any:
        return await self.core.edit_text(chat_id, msg_id, text, kbd=kbd, via=via, **kw)

    async def answer_cb(self, cb_id: str, text: str | None = None, alert: bool = False, url: str | None = None, cache_time: int = 0) -> Any:
        return await self.core.answer_cb(cb_id, text=text, alert=alert, url=url, cache_time=cache_time)

    async def send_photo(self, chat_id: int | str, photo: Any, caption: str | None = None, kbd: Any | None = None, via: str | None = None, **kw: Any) -> Any:
        return await self.core.send_photo(chat_id, photo, caption=caption, kbd=kbd, via=via, **kw)

    async def send_doc(self, chat_id: int | str, document: Any, caption: str | None = None, kbd: Any | None = None, via: str | None = None, **kw: Any) -> Any:
        return await self.core.send_doc(chat_id, document, caption=caption, kbd=kbd, via=via, **kw)

    async def send_media_group(self, chat_id: int | str, media: list[dict[str, Any]], via: str | None = None, **kw: Any) -> Any:
        return await self.core.send_media_group(chat_id, media, via=via, **kw)

    async def set_webhook(self, url: str, **kw: Any) -> Any:
        return await self.core.set_webhook(url, **kw)

    async def delete_webhook(self, drop_pending_updates: bool = False) -> Any:
        return await self.core.delete_webhook(drop_pending_updates=drop_pending_updates)

    async def get_webhook_info(self) -> Any:
        return await self.core.get_webhook_info()

    async def get_admins(self, chat_id: int | str, via: str | None = None) -> Any:
        return await self.core.get_admins(chat_id, via=via)

    async def get_owner(self, chat_id: int | str, via: str | None = None) -> Any:
        return await self.core.get_owner(chat_id, via=via)

    async def get_chat_full(self, chat_id: int | str, via: str | None = None) -> Any:
        return await self.core.get_chat_full(chat_id, via=via)

    async def create_topic(self, chat_id: int | str, name: str, icon_color: int | None = None, via: str | None = None, **kw: Any) -> Any:
        return await self.core.create_topic(chat_id, name, icon_color=icon_color, via=via, **kw)

    async def edit_topic(self, chat_id: int | str, topic_id: int, name: str | None = None, icon_custom_emoji_id: str | None = None, via: str | None = None) -> Any:
        return await self.core.edit_topic(chat_id, topic_id, name=name, icon_custom_emoji_id=icon_custom_emoji_id, via=via)

    async def close_topic(self, chat_id: int | str, topic_id: int, via: str | None = None) -> Any:
        return await self.core.close_topic(chat_id, topic_id, via=via)

    async def reopen_topic(self, chat_id: int | str, topic_id: int, via: str | None = None) -> Any:
        return await self.core.reopen_topic(chat_id, topic_id, via=via)

    async def delete_topic(self, chat_id: int | str, topic_id: int, via: str | None = None) -> Any:
        return await self.core.delete_topic(chat_id, topic_id, via=via)

    async def unpin_all_topic_msgs(self, chat_id: int | str, topic_id: int, via: str | None = None) -> Any:
        return await self.core.unpin_all_topic_msgs(chat_id, topic_id, via=via)

    async def edit_general_topic(self, chat_id: int | str, name: str, via: str | None = None) -> Any:
        return await self.core.edit_general_topic(chat_id, name, via=via)

    async def close_general_topic(self, chat_id: int | str, via: str | None = None) -> Any:
        return await self.core.close_general_topic(chat_id, via=via)

    async def reopen_general_topic(self, chat_id: int | str, via: str | None = None) -> Any:
        return await self.core.reopen_general_topic(chat_id, via=via)

    async def hide_general_topic(self, chat_id: int | str, via: str | None = None) -> Any:
        return await self.core.hide_general_topic(chat_id, via=via)

    async def unhide_general_topic(self, chat_id: int | str, via: str | None = None) -> Any:
        return await self.core.unhide_general_topic(chat_id, via=via)

    def html(self, text: str) -> dict[str, Any]:
        return self.core.html(text)

    def md(self, text: str) -> dict[str, Any]:
        return self.core.md(text)

    def __dir__(self) -> list[str]:
        base = set(super().__dir__())
        base.update({"help", "sendDocument", "getChat", "getUpdates", "mt_get_dialogs"})
        return sorted(base)

    def stop(self) -> None:
        self.core.stop()

    async def run(self) -> None:
        await self.core.run()


_BOT_WRAP = [
    "ban_chat_member", "unban_chat_member", "restrict_chat_member", "promote_chat_member", "set_chat_administrator_custom_title",
    "ban_chat_sender_chat", "unban_chat_sender_chat", "set_chat_permissions", "export_chat_invite_link", "create_chat_invite_link",
    "edit_chat_invite_link", "revoke_chat_invite_link", "approve_chat_join_request", "decline_chat_join_request", "set_chat_photo",
    "delete_chat_photo", "set_chat_title", "set_chat_description", "pin_chat_message", "unpin_chat_message",
    "unpin_all_chat_messages", "leave_chat", "get_chat", "get_chat_member", "set_chat_sticker_set",
    "delete_chat_sticker_set", "get_forum_topic_icon_stickers", "answer_inline_query", "answer_web_app_query", "set_my_commands",
    "delete_my_commands", "get_my_commands", "set_my_name", "get_my_name", "set_my_description",
    "get_my_description", "set_my_short_description", "get_my_short_description", "set_chat_menu_button", "get_chat_menu_button",
    "set_my_default_administrator_rights", "get_my_default_administrator_rights", "send_poll", "stop_poll", "send_dice",
    "send_venue", "send_contact", "send_location", "edit_message_caption", "edit_message_reply_markup",
]

_MT_WRAP = [
    "get_me", "resolve_peer", "get_dialogs", "get_history", "get_messages",
    "send_reaction", "forward_messages", "copy_messages", "pin_message", "unpin_message",
    "read_history", "delete_history", "get_participants", "get_full_user", "get_full_chat",
    "get_full_channel", "join_channel", "leave_channel", "edit_admin", "invite_to_channel",
    "kick_participant", "ban_participant", "unban_participant", "mute_participant", "unmute_participant",
    "create_group", "create_channel", "edit_title", "edit_about", "set_photo",
    "delete_photo", "get_pinned_message", "search_messages", "search_global", "send_typing",
    "upload_file", "download_file", "save_draft", "clear_draft", "mark_read",
    "mark_unread", "get_stats", "get_admin_logs", "create_topic", "edit_topic",
    "close_topic", "reopen_topic", "delete_topic", "get_admins", "get_owner",
]


def _camel(name: str) -> str:
    parts = name.split("_")
    return parts[0] + "".join(x[:1].upper() + x[1:] for x in parts[1:])


def _mk_bot(name: str) -> Any:
    async def fn(self: AppCore, **kw: Any) -> Any:
        return await self.bot_req(_camel(name), **kw)
    fn.__name__ = name
    return fn


def _mk_mt(name: str) -> Any:
    async def fn(self: AppCore, **kw: Any) -> Any:
        return await self.mt_req(name, **kw)
    fn.__name__ = name
    return fn


def _mk_fac(name: str) -> Any:
    async def fn(self: GoyGram, *a: Any, **kw: Any) -> Any:
        return await getattr(self.core, name)(*a, **kw)
    fn.__name__ = name
    return fn


for _name in _BOT_WRAP:
    setattr(AppCore, _name, _mk_bot(_name))
    setattr(GoyGram, _name, _mk_fac(_name))

for _name in _MT_WRAP:
    setattr(AppCore, f"mt_{_name}", _mk_mt(_name))
    setattr(GoyGram, f"mt_{_name}", _mk_fac(f"mt_{_name}"))
