# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
# Contains elements of Aiogram (MIT) / Pyrogram (LGPL-3.0)
from __future__ import annotations

import asyncio
import json
import os
import urllib.parse
from typing import Any

try:
    from goygram.ext import _ext as rx
except Exception:
    rx = None


class ProxyCfg:
    def __init__(self, scheme: str, host: str, port: int, user: str | None = None, pwd: str | None = None) -> None:
        self.scheme = scheme
        self.host = host
        self.port = port
        self.user = user
        self.pwd = pwd


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
        self.pending: dict[int, asyncio.Future[dict[str, Any]]] = {}

    def need_rx(self) -> Any:
        if rx is None:
            raise RuntimeError("ext_rust is not built; run: maturin develop")
        return rx

    def pick(self, obj: dict[str, Any], *keys: str) -> Any:
        for key in keys:
            if key in obj:
                return obj[key]
        return None

    def proxy_cfg(self) -> ProxyCfg | None:
        raw = os.getenv("ALL_PROXY") or os.getenv("all_proxy") or os.getenv("HTTPS_PROXY") or os.getenv("https_proxy") or os.getenv("HTTP_PROXY") or os.getenv("http_proxy")
        if not raw:
            return None
        val = raw if "://" in raw else f"socks5://{raw}"
        url = urllib.parse.urlparse(val)
        host = url.hostname
        if not host:
            return None
        scheme = (url.scheme or "socks5").lower()
        if scheme not in {"socks5", "socks5h", "http", "https"}:
            return None
        port = int(url.port or (1080 if scheme.startswith("socks5") else 8080))
        user = urllib.parse.unquote(url.username) if url.username else None
        pwd = urllib.parse.unquote(url.password) if url.password else None
        return ProxyCfg(scheme=scheme, host=host, port=port, user=user, pwd=pwd)

    async def boot(self) -> None:
        if self.rd and self.wr and not self.wr.is_closing():
            return
        proxy = self.proxy_cfg()
        if proxy is None:
            self.rd, self.wr = await asyncio.open_connection(self.host, self.port)
            return
        self.rd, self.wr = await self.open_via_proxy(proxy)

    async def open_via_proxy(self, proxy: ProxyCfg) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        rd, wr = await asyncio.open_connection(proxy.host, proxy.port)
        try:
            if proxy.scheme.startswith("socks5"):
                await self.socks5_handshake(rd, wr, proxy)
            else:
                await self.http_connect_handshake(rd, wr, proxy)
            return rd, wr
        except Exception:
            wr.close()
            await wr.wait_closed()
            raise

    async def socks5_handshake(self, rd: asyncio.StreamReader, wr: asyncio.StreamWriter, proxy: ProxyCfg) -> None:
        methods = [2] if proxy.user is not None else [0]
        wr.write(bytes([5, len(methods), *methods]))
        await wr.drain()
        hello = await rd.readexactly(2)
        if hello[0] != 5 or hello[1] == 0xFF:
            raise ConnectionError("socks5 method negotiation failed")
        if hello[1] == 2:
            user = (proxy.user or "").encode()
            pwd = (proxy.pwd or "").encode()
            wr.write(bytes([1, len(user)]) + user + bytes([len(pwd)]) + pwd)
            await wr.drain()
            auth = await rd.readexactly(2)
            if auth[1] != 0:
                raise ConnectionError("socks5 auth failed")
        host = self.host.encode()
        req = bytes([5, 1, 0, 3, len(host)]) + host + self.port.to_bytes(2, "big")
        wr.write(req)
        await wr.drain()
        rep = await rd.readexactly(4)
        if rep[1] != 0:
            raise ConnectionError(f"socks5 connect failed code={rep[1]}")
        atyp = rep[3]
        if atyp == 1:
            await rd.readexactly(4 + 2)
        elif atyp == 3:
            n = await rd.readexactly(1)
            await rd.readexactly(n[0] + 2)
        elif atyp == 4:
            await rd.readexactly(16 + 2)

    async def http_connect_handshake(self, rd: asyncio.StreamReader, wr: asyncio.StreamWriter, proxy: ProxyCfg) -> None:
        lines = [f"CONNECT {self.host}:{self.port} HTTP/1.1", f"Host: {self.host}:{self.port}"]
        if proxy.user is not None:
            import base64
            token = base64.b64encode(f"{proxy.user}:{proxy.pwd or ''}".encode()).decode()
            lines.append(f"Proxy-Authorization: Basic {token}")
        req = "\r\n".join(lines) + "\r\n\r\n"
        wr.write(req.encode())
        await wr.drain()
        head = await rd.readuntil(b"\r\n\r\n")
        first = head.split(b"\r\n",1)[0].decode("latin1", "ignore")
        if " 200 " not in first:
            raise ConnectionError(f"http proxy connect failed: {first}")

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
        req_id = self.seq
        obj = {"act": act, "id": req_id}
        obj.update({k: v for k, v in kw.items() if v is not None})
        fut: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self.pending[req_id] = fut
        await self.send(obj)
        try:
            return await fut
        finally:
            self.pending.pop(req_id, None)

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
                    msg_id = self.pick(obj, "id", "req_id", "msg_id")
                    if isinstance(msg_id, int) and msg_id in self.pending:
                        fut = self.pending[msg_id]
                        if not fut.done():
                            fut.set_result(obj)
                    await self.bus.push("mt", self.norm(obj))
            except asyncio.CancelledError:
                raise
            except Exception as e:
                for fut in self.pending.values():
                    if not fut.done():
                        fut.set_exception(e)
                self.pending.clear()
                await self.bus.push("sys", {"kind": "err", "src": "mt", "text": repr(e)})
                if self.wr and not self.wr.is_closing():
                    self.wr.close()
                    await self.wr.wait_closed()
                self.rd = None
                self.wr = None
                await asyncio.sleep(1.0)
