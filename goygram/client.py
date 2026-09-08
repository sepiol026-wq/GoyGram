# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
from __future__ import annotations

import asyncio
import hashlib
import secrets
import signal
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
import logging
from pathlib import Path
from typing import Any, Literal

from goygram.api.methods import BotAPI
from goygram.core.bus import Bus
from goygram.core.disp import Disp
from goygram.core.fsm import FSMEngine
from goygram.types.obj import Obj
from goygram.logging import get_logger
from goygram.security import bootstrap_session
from goygram.filters import Filter
from goygram.dc_fetcher import get_dynamic_dc_config, pick_dc_endpoint
from goygram.utils import print_methods

Fn = Callable[["Obj"], Awaitable[Any]]
CbFn = Fn
PollFn = Fn
MemFn = Fn
InlineFn = Fn


@dataclass(frozen=True, slots=True)
class BotCfg:
    token: str
    timeout: int = 25
    base: str = "https://api.telegram.org"
    webhook_url: str | None = None
    webhook_host: str = "127.0.0.1"
    webhook_port: int = 8080
    webhook_path: str = "/telegram/webhook"
    webhook_secret_token: str | None = None
    webhook_max_body: int = 1024 * 1024
    webhook_drop_pending_updates: bool = False
    offset_path: str | None = None


@dataclass(frozen=True, slots=True)
class MtCfg:
    host: str
    port: int
    key: bytes | None = None
    iv: bytes | None = None


@dataclass(frozen=True, slots=True)
class AppCfg:
    bot: BotCfg | None = None
    mt: MtCfg | None = None
    bus_max: int = 0


class AppCore:
    def __init__(
        self,
        cfg: AppCfg,
        api_id: int | str | None = None,
        api_hash: str | None = None,
        session_name: str = "default",
        *,
        session: Any | None = None,
        default_transport: str = "auto",
        proxy: str | None = None,
        app_name: str | None = None,
        app_version: str | None = None,
        device_model: str | None = None,
        system_version: str | None = None,
        system_lang_code: str = "en",
        lang_pack: str = "",
        lang_code: str = "en",
        fsm_backend: Any | None = None,
        fsm_on_change: Callable[[list[dict[str, Any]]], Any] | None = None,
    ) -> None:
        self.cfg = cfg
        self.bus = Bus(cfg.bus_max)
        self.bot = None
        self.mt = None
        self.api = None
        self.self_id: int | None = None
        if cfg.bot:
            from goygram.transports.botapi import BotNet

            self.bot = BotNet(
                cfg.bot.token,
                self.bus,
                cfg.bot.timeout,
                cfg.bot.base,
                webhook_url=cfg.bot.webhook_url,
                webhook_host=cfg.bot.webhook_host,
                webhook_port=cfg.bot.webhook_port,
                webhook_path=cfg.bot.webhook_path,
                webhook_secret_token=cfg.bot.webhook_secret_token,
                webhook_max_body=cfg.bot.webhook_max_body,
                webhook_drop_pending_updates=cfg.bot.webhook_drop_pending_updates,
                offset_path=cfg.bot.offset_path,
            )
            self.api = BotAPI(self.bot)
        if cfg.mt:
            from goygram.transports.mtproto import MTNet

            self.mt = MTNet(
                cfg.mt.host,
                cfg.mt.port,
                self.bus,
                cfg.mt.key,
                cfg.mt.iv,
                proxy=proxy,
                app_name=app_name,
                app_version=app_version,
                device_model=device_model,
                system_version=system_version,
                system_lang_code=system_lang_code,
                lang_pack=lang_pack,
                lang_code=lang_code,
                cursor_path=Path.home() / ".goygram" / "cursors" / f"{hashlib.sha256(session_name.encode()).hexdigest()[:24]}.json",
            )
            if api_id is not None:
                self.mt._api_id = int(api_id)
            self._init_tl_schema()
            self._load_vault_from_disk(session_name, api_id, api_hash)
        self.fsm = FSMEngine(backend=fsm_backend, on_change=fsm_on_change)
        self.disp = Disp(self, self.bus)
        self.hook: list[Fn] = []
        self.edit_hook: list[Fn] = []
        self.update_hook: list[Fn] = []
        self.cb_hook: list[CbFn] = []
        self.inline_hook: list[InlineFn] = []
        self.poll_hook: list[PollFn] = []
        self.member_hook: list[MemFn] = []
        self.stop_ev = asyncio.Event()
        self.log = get_logger("goygram.app")
        self.api_id = api_id
        self.api_hash = api_hash
        self.session_name = session_name
        self.bot_token = cfg.bot.token if cfg.bot else None
        self.default_transport = default_transport
        from goygram.session import STRING_PREFIX, Session
        if session is None:
            self.session = Session(name=session_name)
        elif isinstance(session, Session):
            self.session = session
        elif isinstance(session, str) and session.startswith(STRING_PREFIX):
            self.session = Session.from_string(session, name=session_name)
        elif isinstance(session, str):
            self.session = Session(name=session)
        else:
            raise TypeError("session must be a Session instance or an encrypted session string")

    def _init_tl_schema(self) -> None:
        from goygram.schema_manager import init_schema, CURRENT_LAYER_FLOOR
        from goygram import ext as _ext
        if _ext is None:
            return
        self.mt.layer = init_schema(
            _ext,
            None,
            lambda layer: self.mt.update_layer(layer),
            self._can_reload_schema,
        ) or CURRENT_LAYER_FLOOR

    def _can_reload_schema(self) -> bool:
        return self.mt is not None and self.mt.auth_ready.is_set() and not self.mt.pending

    def _load_vault_from_disk(self, session_name: str, api_id: Any, api_hash: Any) -> None:
        import logging
        from pathlib import Path
        from goygram.security import _read_vault, _extract_auth_blob
        from goygram.dc_fetcher import get_dynamic_dc_config, pick_dc_endpoint
        log = logging.getLogger("goygram.dc")
        vault = Path(f"{session_name}.vault")
        if not vault.exists() or vault.stat().st_size == 0:
            return
        vault_key = Path(session_name).name
        try:
            data = _read_vault(vault, vault_key)
            auth_key = data.get("auth_key")
            if auth_key and self.mt is not None:
                self.mt.auth_key = _extract_auth_blob({"auth_key": auth_key})
            server_salt = data.get("server_salt")
            if server_salt and self.mt is not None:
                try:
                    self.mt.server_salt = _extract_auth_blob({"auth_key": server_salt}) or self.mt.server_salt
                except Exception:
                    pass
            dc = data.get("dc")
            if dc is not None and self.mt is not None:
                dc_map = get_dynamic_dc_config()
                endpoint = pick_dc_endpoint(dc_map, preferred_dc=int(dc))
                self.mt.host = endpoint.host
                self.mt.port = endpoint.port
            user_data = data.get("user", {})
            uid = user_data.get("id", 0) if isinstance(user_data, dict) else 0
            if uid and uid != 0 and self.mt is not None:
                self.self_id = uid
                self.mt.self_id = uid
        except Exception:
            pass

    def on_msg(self, fn: Fn | None = None, filt: Filter | None = None):
        if isinstance(fn, Filter):
            filt = fn
            fn = None
        def wrap(inner: Fn) -> Fn:
            if filt is None:
                self.hook.append(inner)
                return inner
            async def guarded(msg: "Obj") -> Any:
                if filt(msg):
                    return await inner(msg)
                return None
            self.hook.append(guarded)
            return inner
        if fn is not None:
            return wrap(fn)
        return wrap

    def on_edit(self, fn: Fn | None = None, filt: Filter | None = None):
        if isinstance(fn, Filter):
            filt = fn
            fn = None
        def wrap(inner: Fn) -> Fn:
            if filt is None:
                self.edit_hook.append(inner)
                return inner
            async def guarded(msg: "Obj") -> Any:
                if filt(msg):
                    return await inner(msg)
                return None
            self.edit_hook.append(guarded)
            return inner
        if fn is not None:
            return wrap(fn)
        return wrap

    def on_cb(self, fn: CbFn | None = None, *, filt: Filter | None = None):
        if isinstance(fn, Filter):
            filt = fn
            fn = None
        def wrap(inner: CbFn) -> CbFn:
            if filt is None:
                self.cb_hook.append(inner)
                return inner
            async def guarded(cb: "Obj") -> Any:
                if filt(cb):
                    return await inner(cb)
                return None
            self.cb_hook.append(guarded)
            return inner
        if fn is not None:
            return wrap(fn)
        return wrap

    def on_inline(self, fn: InlineFn | None = None, *, filt: Filter | None = None):
        if isinstance(fn, Filter):
            filt = fn
            fn = None
        def wrap(inner: InlineFn) -> InlineFn:
            if filt is None:
                self.inline_hook.append(inner)
                return inner
            async def guarded(inline: "Obj") -> Any:
                if filt(inline):
                    return await inner(inline)
                return None
            self.inline_hook.append(guarded)
            return inner
        if fn is not None:
            return wrap(fn)
        return wrap

    def on_poll(self, fn: PollFn | None = None, *, filt: Filter | None = None):
        if isinstance(fn, Filter):
            filt = fn
            fn = None
        def wrap(inner: PollFn) -> PollFn:
            if filt is None:
                self.poll_hook.append(inner)
                return inner
            async def guarded(poll: "Obj") -> Any:
                if filt(poll):
                    return await inner(poll)
                return None
            self.poll_hook.append(guarded)
            return inner
        if fn is not None:
            return wrap(fn)
        return wrap

    def on_member(self, fn: MemFn | None = None, *, filt: Filter | None = None):
        if isinstance(fn, Filter):
            filt = fn
            fn = None
        def wrap(inner: MemFn) -> MemFn:
            if filt is None:
                self.member_hook.append(inner)
                return inner
            async def guarded(mem: "Obj") -> Any:
                if filt(mem):
                    return await inner(mem)
                return None
            self.member_hook.append(guarded)
            return inner
        if fn is not None:
            return wrap(fn)
        return wrap

    def on_update(self, fn: Callable[[object], Awaitable[Any]] | None = None, *, filt: Filter | None = None):
        def wrap(inner: Callable[[object], Awaitable[Any]]) -> Callable[[object], Awaitable[Any]]:
            if filt is None:
                self.update_hook.append(inner)
                return inner
            async def guarded(event: object) -> Any:
                if filt(event):
                    return await inner(event)
                return None
            self.update_hook.append(guarded)
            return inner
        if fn is not None:
            return wrap(fn)
        return wrap

    def on_cmd(self, *name: str) -> Callable[[Fn], Fn]:
        from goygram.filters import command as _cmd_filt
        return self.on_msg(filt=_cmd_filt(*name))

    def _bot_method_name(self, name: str) -> str:
        if "_" in name:
            parts = name.split("_")
            return parts[0] + "".join(x[:1].upper() + x[1:] for x in parts[1:])
        return name

    def _mt_method_name(self, name: str) -> str:
        name = name[3:] if name.startswith("mt_") else name
        if "." in name:
            return name
        parts = name.split("_")
        if len(parts) < 2:
            return name
        ns = parts[0]
        rest = parts[1:]
        return ns + "." + rest[0] + "".join(p[:1].upper() + p[1:] for p in rest[1:])

    def _dynamic_method(self, name: str):
        async def call(**kw: Any) -> Any:
            if name.startswith("mt_"):
                return await self.mt_req(self._mt_method_name(name), **kw)
            return await self.bot_req(self._bot_method_name(name), **kw)
        return call

    def help(self) -> None:
        print_methods(self)

    def __getattr__(self, name: str) -> Any:
        if self.api is not None and hasattr(self.api, name):
            return getattr(self.api, name)
        if name.startswith("mt_") and self.mt is not None:
            return self._dynamic_method(name)
        if not name.startswith("mt_") and not name.startswith("_") and self.bot is not None:
            return self._dynamic_method(name)
        raise AttributeError(name)

    def __dir__(self) -> list[str]:
        base = set(super().__dir__())
        base.add("help")
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
        _alias = {"api": "bot", "bot": "bot", "mtproto": "mt", "mt": "mt"}
        if via is not None:
            resolved = _alias.get(via)
            if resolved is None:
                raise ValueError(f"unknown transport {via!r}; use 'api' or 'mtproto'")
            if resolved == "bot" and self.bot is None:
                raise RuntimeError("bot net is not configured")
            if resolved == "mt" and self.mt is None:
                raise RuntimeError("mt net is not configured")
            return resolved
        if isinstance(chat_id, str) and chat_id.startswith("bot:"):
            if self.bot is None:
                raise RuntimeError("bot net is not configured")
            return "bot"
        if isinstance(chat_id, str) and chat_id.startswith("mt:"):
            if self.mt is None:
                raise RuntimeError("mt net is not configured")
            return "mt"
        if self.default_transport == "api" and self.bot is not None:
            return "bot"
        if self.default_transport == "mtproto" and self.mt is not None:
            return "mt"
        if self.bot is not None:
            return "bot"
        if self.mt is not None:
            return "mt"
        raise RuntimeError("no transport configured")

    def ikb(self) -> Any:
        from goygram.types.kbd import KbdBuilder
        return KbdBuilder(kind="inline")

    def rkb(self, **opts: Any) -> Any:
        from goygram.types.kbd import KbdBuilder
        return KbdBuilder(kind="reply", **opts)

    def frk(self, **opts: Any) -> Any:
        from goygram.types.kbd import KbdBuilder
        return KbdBuilder(kind="force", **opts)

    def rgk(self, **opts: Any) -> Any:
        from goygram.types.kbd import KbdBuilder
        return KbdBuilder(kind="remove", **opts)

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

    async def download_file(self, file_id: str, destination: str | None = None) -> Any:
        if self.bot is None:
            raise RuntimeError("bot net is not configured")
        return await self.bot.download_file(file_id, destination)

    async def upload_file(self, source: Any, **kw: Any) -> Any:
        if self.mt is None:
            raise RuntimeError("mt net is not configured")
        return await self.mt.upload_file(source, **kw)

    async def send_msg(self, chat_id: int | str, text: str, *, via: str | None = None, reply_to: int | None = None, kbd: Any | None = None, **kw: Any) -> Any:
        transport = self.via(chat_id, via)
        target = self.raw_chat(chat_id)
        if transport == "bot":
            return await self.bot.send_msg(target, text, reply_to=reply_to, kbd=kbd, **kw)
        peer = await self.mt.resolve_peer(target)
        data = dict(kw)
        if reply_to is not None:
            data["reply_to"] = reply_to
        if kbd is not None:
            from goygram.types.kbd import kbd_to_tl
            tl_kbd = kbd_to_tl(kbd)
            if tl_kbd is not None:
                data["reply_markup"] = tl_kbd
        data["_dispatch_chat_id"] = target
        data["_dispatch_message_text"] = text
        return await self.mt_req("messages.sendMessage", peer=peer, message=text, random_id=secrets.randbits(63), **data)

    async def mt_req(self, act: str, **kw: Any) -> Any:
        if self.mt is None:
            raise RuntimeError("mt net is not configured")
        data = {k: v.to_dict() if hasattr(v, "to_dict") else v for k, v in kw.items() if v is not None}
        if act.startswith("messages.") and isinstance(data.get("reply_markup"), dict) and "inline_keyboard" in data.get("reply_markup", {}):
            from goygram.types.kbd import kbd_to_tl
            tl_kbd = kbd_to_tl(data["reply_markup"])
            if tl_kbd is not None:
                data["reply_markup"] = tl_kbd
        if 'api_id' not in data and self.api_id is not None:
            data['api_id'] = self.api_id
        if 'api_hash' not in data and self.api_hash is not None:
            data['api_hash'] = self.api_hash
        if hasattr(self.mt, "call"):
            return await self.mt.call(act, **data)
        if hasattr(self.mt, "req"):
            return await self.mt.req(act, data)
        return await self.mt.send({"act": act, **data})

    def set_state(self, chat_id: int | str, user_id: int | str, state: str, data: dict[str, Any] | None = None, ttl: float | None = None) -> None:
        self.fsm.set(chat_id, user_id, state, data, ttl)

    def get_state(self, chat_id: int | str, user_id: int | str) -> str | None:
        return self.fsm.get(chat_id, user_id)

    def get_state_data(self, chat_id: int | str, user_id: int | str) -> dict[str, Any] | None:
        return self.fsm.get_data(chat_id, user_id)

    def clear_state(self, chat_id: int | str, user_id: int | str) -> None:
        self.fsm.clear(chat_id, user_id)

    async def close(self) -> None:
        self.stop_ev.set()
        await self.fsm.stop()
        await self.disp.close()
        if self.bot:
            await self.bot.close()
        if self.mt:
            await self.mt.close()

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        self.log.info("Starting GoyGram core.")
        tasks = []
        stop_wait = None
        try:
            tasks.append(asyncio.create_task(self.disp.consume(), name="disp"))
            await self.fsm.start()
            if self.bot:
                self.log.info("Bot transport is enabled.")
                if self.mt is not None:
                    self.log.info("Hybrid mode: updates are served exclusively by MTProto; Bot API polling is off.")
                if self.bot.webhook_url and self.mt is None:
                    await self.bot.start_webhook()
                elif self.mt is None:
                    try:
                        await self.bot_req("deleteWebhook", drop_pending_updates=False)
                    except Exception as e:
                        self.log.error("Failed to clear webhook before polling: %r", e)
                    tasks.append(asyncio.create_task(self.bot.spin(), name="bot"))
            if self.mt:
                self.log.info("MT transport is enabled.")
                await bootstrap_session(self, api_id=self.api_id, api_hash=self.api_hash, session_name=self.session_name, bot_token=self.bot_token, session=self.session)
                await self.mt.start()
                tasks.append(self.mt._reader_task)
                try:
                    await self.mt.call("updates.getState", api_id=self.api_id)
                except Exception as exc:
                    self.log.debug("Initial MTProto state request failed: %s", type(exc).__name__)
            stop_wait = asyncio.create_task(self.stop_ev.wait(), name="stop-wait")
            done, _ = await asyncio.wait({stop_wait, *tasks}, return_when=asyncio.FIRST_COMPLETED)
            if stop_wait not in done:
                self.stop_ev.set()
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            await self.close()
            if stop_wait is not None:
                stop_wait.cancel()
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
        session_name: str = "default",
        session: Any | None = None,
        default_transport: str = "auto",
        proxy: str | None = None,
        app_name: str | None = None,
        app_version: str | None = None,
        device_model: str | None = None,
        system_version: str | None = None,
        system_lang_code: str = "en",
        lang_pack: str = "",
        lang_code: str = "en",
        fsm_backend: Any | None = None,
        fsm_on_change: Callable[[list[dict[str, Any]]], Any] | None = None,
        webhook_url: str | None = None,
        webhook_host: str = "127.0.0.1",
        webhook_port: int = 8080,
        webhook_path: str = "/telegram/webhook",
        webhook_secret_token: str | None = None,
        webhook_max_body: int = 1024 * 1024,
        webhook_drop_pending_updates: bool = False,
        bot_offset_path: str | None = None,
    ) -> None:
        if webhook_url is not None and bot_token is None:
            raise ValueError("webhook_url requires bot_token")
        bot = BotCfg(
            token=bot_token,
            timeout=bot_timeout,
            base=bot_base,
            webhook_url=webhook_url,
            webhook_host=webhook_host,
            webhook_port=webhook_port,
            webhook_path=webhook_path,
            webhook_secret_token=webhook_secret_token,
            webhook_max_body=webhook_max_body,
            webhook_drop_pending_updates=webhook_drop_pending_updates,
            offset_path=bot_offset_path,
        ) if bot_token is not None else None
        log = get_logger("goygram.dc")
        resolved_host = mt_host
        resolved_port = mt_port

        if resolved_host is None and (bot is None or api_id is not None or api_hash is not None):
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
        self.core = AppCore(
            AppCfg(bot=bot, mt=mt, bus_max=bus_max),
            api_id=api_id,
            api_hash=api_hash,
            session_name=session_name,
            session=session,
            default_transport=default_transport,
            proxy=proxy,
            app_name=app_name,
            app_version=app_version,
            device_model=device_model,
            system_version=system_version,
            system_lang_code=system_lang_code,
            lang_pack=lang_pack,
            lang_code=lang_code,
            fsm_backend=fsm_backend,
            fsm_on_change=fsm_on_change,
        )

    def on_msg(self, fn: Fn | None = None, filt: Filter | None = None):
        return self.core.on_msg(fn, filt=filt)

    def on_cb(self, fn: CbFn | None = None, *, filt: Filter | None = None):
        return self.core.on_cb(fn, filt=filt)

    def on_inline(self, fn: InlineFn | None = None, *, filt: Filter | None = None):
        return self.core.on_inline(fn, filt=filt)

    def on_cmd(self, *name: str) -> Callable[[Fn], Fn]:
        return self.core.on_cmd(*name)

    def on_poll(self, fn: PollFn | None = None, *, filt: Filter | None = None):
        return self.core.on_poll(fn, filt=filt)

    def on_member(self, fn: MemFn | None = None, *, filt: Filter | None = None):
        return self.core.on_member(fn, filt=filt)

    def on_edit(self, fn: Fn | None = None, filt: Filter | None = None):
        return self.core.on_edit(fn, filt=filt)

    def on_update(self, fn: Callable[[object], Awaitable[Any]] | None = None, *, filt: Filter | None = None):
        return self.core.on_update(fn, filt=filt)

    def help(self) -> None:
        self.core.help()

    def __getattr__(self, name: str) -> Any:
        return getattr(self.core, name)

    def __dir__(self) -> list[str]:
        return sorted(set(super().__dir__()) | set(dir(self.core)))

    def stop(self) -> None:
        self.core.stop()

    async def run(self) -> None:
        await self.core.run()
