# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from goygram.logging import get_logger

from goygram.errors import StopPropagation
from goygram.types.obj import Obj

Fn = Callable[["Obj"], Awaitable[Any]]
CbFn = Fn
PollFn = Fn
MemFn = Fn
InlineFn = Fn


class Disp:
    def __init__(self, app: Any, bus: Any) -> None:
        self.app = app
        self.bus = bus
        self.stop_ev = asyncio.Event()
        self.log = get_logger("goygram.disp")

    async def close(self) -> None:
        self.stop_ev.set()

    async def one(self, pkt: dict[str, Any]) -> None:
        data = pkt.get("data")
        if not isinstance(data, dict):
            return
        kind = data.get("kind")
        if kind == "err":
            self.log.warning("Disp error event: %s", data.get("text", ""))
            return
        if kind != "update":
            update = Obj(pkt.get("src", "sys"), data, self.app)
            for fn in list(getattr(self.app, "update_hook", [])):
                try:
                    await fn(update)
                except StopPropagation:
                    return
                except Exception as e:
                    self.log.error("Handler failure: %r", e)
                    await self.bus.push("sys", {"kind": "err", "src": "disp", "text": repr(e)})
        if kind == "msg":
            msg = Obj(pkt.get("src", "sys"), data, self.app)
            for fn in list(self.app.hook):
                try:
                    await fn(msg)
                except StopPropagation:
                    return
                except Exception as e:
                    self.log.error("Handler failure: %r", e)
                    await self.bus.push("sys", {"kind": "err", "src": "disp", "text": repr(e)})
            return
        if kind == "edit":
            msg = Obj(pkt.get("src", "sys"), data, self.app)
            for fn in list(getattr(self.app, "edit_hook", [])):
                try:
                    await fn(msg)
                except StopPropagation:
                    return
                except Exception as e:
                    self.log.error("Handler failure: %r", e)
                    await self.bus.push("sys", {"kind": "err", "src": "disp", "text": repr(e)})
            return
        if kind == "poll":
            poll = Obj(pkt.get("src", "sys"), data, self.app)
            for fn in list(getattr(self.app, "poll_hook", [])):
                try:
                    await fn(poll)
                except StopPropagation:
                    return
                except Exception as e:
                    self.log.error("Handler failure: %r", e)
                    await self.bus.push("sys", {"kind": "err", "src": "disp", "text": repr(e)})
            return
        if kind == "cb":
            cb = Obj(pkt.get("src", "sys"), data, self.app)
            for fn in list(self.app.cb_hook):
                try:
                    await fn(cb)
                except StopPropagation:
                    return
                except Exception as e:
                    self.log.error("Handler failure: %r", e)
                    await self.bus.push("sys", {"kind": "err", "src": "disp", "text": repr(e)})
            return
        if kind == "inline":
            inline = Obj(pkt.get("src", "sys"), data, self.app)
            for fn in list(getattr(self.app, "inline_hook", [])):
                try:
                    await fn(inline)
                except StopPropagation:
                    return
                except Exception as e:
                    self.log.error("Handler failure: %r", e)
                    await self.bus.push("sys", {"kind": "err", "src": "disp", "text": repr(e)})
            return
        if kind == "update":
            update = Obj(pkt.get("src", "sys"), data, self.app)
            for fn in list(getattr(self.app, "update_hook", [])):
                try:
                    await fn(update)
                except StopPropagation:
                    return
                except Exception as e:
                    self.log.error("Handler failure: %r", e)
                    await self.bus.push("sys", {"kind": "err", "src": "disp", "text": repr(e)})
            return
        if kind != "member":
            return
        mem = Obj(pkt.get("src", "sys"), data, self.app)
        for fn in list(getattr(self.app, "member_hook", [])):
            try:
                await fn(mem)
            except StopPropagation:
                return
            except Exception as e:
                self.log.error("Handler failure: %r", e)
                await self.bus.push("sys", {"kind": "err", "src": "disp", "text": repr(e)})

    async def consume(self) -> None:
        while not self.stop_ev.is_set():
            try:
                pkt = await self.bus.fetch()
                await self.one(pkt)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.log.error("Handler failure: %r", e)
                await self.bus.push("sys", {"kind": "err", "src": "disp", "text": repr(e)})
