# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from goygram.logging import get_logger

from goygram.types.cb import CbObj
from goygram.types.member import MemberObj
from goygram.types.msg import MsgObj
from goygram.types.poll import PollObj

Fn = Callable[[MsgObj], Awaitable[Any]]
CbFn = Callable[[CbObj], Awaitable[Any]]
PollFn = Callable[[PollObj], Awaitable[Any]]
MemFn = Callable[[MemberObj], Awaitable[Any]]


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
        if kind == "msg":
            msg = MsgObj(pkt.get("src", "sys"), data, self.app)
            for fn in list(self.app.hook):
                try:
                    await fn(msg)
                except Exception as e:
                    self.log.error("Handler failure: %s", e)
                    await self.bus.push("sys", {"kind": "err", "src": "disp", "text": str(e)})
            for fn in list(getattr(self.app, "cmd_hook", [])):
                try:
                    await fn(msg)
                except Exception as e:
                    self.log.error("Handler failure: %s", e)
                    await self.bus.push("sys", {"kind": "err", "src": "disp", "text": str(e)})
            return
        if kind == "poll":
            poll = PollObj(pkt.get("src", "sys"), data, self.app)
            for fn in list(getattr(self.app, "poll_hook", [])):
                try:
                    await fn(poll)
                except Exception as e:
                    self.log.error("Handler failure: %s", e)
                    await self.bus.push("sys", {"kind": "err", "src": "disp", "text": str(e)})
            return
        if kind == "cb":
            cb = CbObj(pkt.get("src", "sys"), data, self.app)
            for fn in list(getattr(self.app, "cb_hook", [])):
                try:
                    await fn(cb)
                except Exception as e:
                    self.log.error("Handler failure: %s", e)
                    await self.bus.push("sys", {"kind": "err", "src": "disp", "text": str(e)})
            return
        if kind != "member":
            return
        mem = MemberObj(pkt.get("src", "sys"), data, self.app)
        for fn in list(getattr(self.app, "member_hook", [])):
            try:
                await fn(mem)
            except Exception as e:
                self.log.error("Handler failure: %s", e)
                await self.bus.push("sys", {"kind": "err", "src": "disp", "text": str(e)})

    async def consume(self) -> None:
        while not self.stop_ev.is_set():
            try:
                pkt = await self.bus.fetch()
                await self.one(pkt)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.log.error("Handler failure: %s", e)
                await self.bus.push("sys", {"kind": "err", "src": "disp", "text": str(e)})
