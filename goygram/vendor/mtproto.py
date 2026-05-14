# Copyleft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
# Contains elements of Aiogram (MIT) / Pyrogram (LGPL-3.0)
from __future__ import annotations

import asyncio
import json
from typing import Any

try:
    from goygram.ext import _ext as rx
except Exception:
    rx = None


class MTNet:
    def __init__(
        self,
        host: str,
        port: int,
        bus: Any,
        key: bytes | None = None,
        iv: bytes | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.bus = bus
        self.key = key
        self.iv = iv
        self.rd: asyncio.StreamReader | None = None
        self.wr: asyncio.StreamWriter | None = None
        self.buf = bytearray()
        self.stop_ev = asyncio.Event()
        self.seq = 0

    def need_rx(self) -> Any:
        if rx is None:
            raise RuntimeError("ext_rust is not built; run: maturin develop")
        return rx

    def pick(self, obj: dict[str, Any], *keys: str) -> Any:
        for key in keys:
            if key in obj:
                return obj[key]
        return None

    async def boot(self) -> None:
        if self.rd and self.wr and not self.wr.is_closing():
            return
        self.rd, self.wr = await asyncio.open_connection(self.host, self.port)

    async def close(self) -> None:
        self.stop_ev.set()
        if not self.wr:
            return
        self.wr.close()
        await self.wr.wait_closed()

    def enc(self, raw: bytes) -> bytes:
        if not self.key or not self.iv:
            return raw
        mod = self.need_rx()
        return bytes(mod.aes_ige_enc(raw, self.key, self.iv))

    def dec(self, raw: bytes) -> bytes:
        if not self.key or not self.iv:
            return raw
        mod = self.need_rx()
        return bytes(mod.aes_ige_dec(raw, self.key, self.iv))

    def cut(self) -> list[bytes]:
        if rx is not None:
            items, tail = rx.cut(bytes(self.buf))
            self.buf[:] = bytes(tail)
            return [bytes(x) for x in items]
        out: list[bytes] = []
        i = 0
        raw = bytes(self.buf)
        while i + 4 <= len(raw):
            n = int.from_bytes(raw[i : i + 4], "little")
            if n == 0:
                raise ValueError("zero frame")
            if i + 4 + n > len(raw):
                break
            out.append(raw[i + 4 : i + 4 + n])
            i += 4 + n
        self.buf[:] = raw[i:]
        return out

    def pack(self, raw: bytes) -> bytes:
        if rx is not None:
            return bytes(rx.pack(raw))
        return len(raw).to_bytes(4, "little") + raw

    def norm(self, obj: dict[str, Any]) -> dict[str, Any]:
        return {
            "kind": obj.get("kind", "msg"),
            "src": "mt",
            "msg_id": self.pick(obj, "msg_id", "id"),
            "chat_id": self.pick(obj, "chat_id", "peer_id"),
            "from_id": self.pick(obj, "from_id", "user_id"),
            "text": self.pick(obj, "text", "body") or "",
            "raw": obj,
        }

    async def send(self, obj: dict[str, Any]) -> None:
        await self.boot()
        assert self.wr is not None
        raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode()
        pkt = self.pack(self.enc(raw))
        self.wr.write(pkt)
        await self.wr.drain()

    async def call(self, act: str, **kw: Any) -> dict[str, Any]:
        self.seq += 1
        obj = {"act": act, "id": self.seq}
        obj.update({k: v for k, v in kw.items() if v is not None})
        await self.send(obj)
        return obj

    async def send_msg(
        self,
        chat_id: int | str,
        text: str,
        reply_to: int | None = None,
        kbd: Any | None = None,
        topic_id: int | None = None,
        media: Any | None = None,
        **kw: Any,
    ) -> dict[str, Any]:
        self.seq += 1
        obj = {"act": "send_msg", "id": self.seq, "chat_id": chat_id, "text": text}
        if reply_to is not None:
            obj["reply_to"] = reply_to
        if kbd is not None:
            obj["kbd"] = kbd.to_dict() if hasattr(kbd, "to_dict") else kbd
        if topic_id is not None:
            obj["topic_id"] = topic_id
        if media is not None:
            obj["media"] = media.to_dict() if hasattr(media, "to_dict") else media
        if "link_options" in kw and hasattr(kw["link_options"], "to_dict"):
            kw["link_options"] = kw["link_options"].to_dict()
        if "link_preview_options" in kw and hasattr(kw["link_preview_options"], "to_dict"):
            kw["link_preview_options"] = kw["link_preview_options"].to_dict()
        if kw:
            obj.update(kw)
        await self.send(obj)
        return obj

    async def del_msg(self, chat_id: int | str, msg_id: int) -> dict[str, Any]:
        self.seq += 1
        obj = {"act": "del_msg", "id": self.seq, "chat_id": chat_id, "msg_id": msg_id}
        await self.send(obj)
        return obj

    async def spin(self) -> None:
        while not self.stop_ev.is_set():
            try:
                await self.boot()
                assert self.rd is not None
                raw = await self.rd.read(65536)
                if not raw:
                    raise ConnectionError("mt socket closed")
                self.buf.extend(raw)
                for pkt in self.cut():
                    dec = self.dec(pkt)
                    obj = json.loads(dec.decode("utf-8"))
                    if not isinstance(obj, dict):
                        continue
                    await self.bus.push("mt", self.norm(obj))
            except asyncio.CancelledError:
                raise
            except Exception as e:
                await self.bus.push("sys", {"kind": "err", "src": "mt", "text": str(e)})
                if self.wr and not self.wr.is_closing():
                    self.wr.close()
                    await self.wr.wait_closed()
                self.rd = None
                self.wr = None
                await asyncio.sleep(1.0)
