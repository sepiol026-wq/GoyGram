from __future__ import annotations
import asyncio, os, secrets, time, urllib.parse
from hashlib import sha1
from typing import Any

from .tl_core import IntermediateTransport, MTCodec, MTMessage, MsgIdGen, Reader, factorize, kdf, kdf_msg, rsa_pad_encrypt

try:
    from goygram.ext import _ext as rx
except Exception:
    rx = None

class ProxyCfg:
    def __init__(self, scheme:str, host:str, port:int, user:str|None=None, pwd:str|None=None)->None:
        self.scheme, self.host, self.port, self.user, self.pwd = scheme, host, port, user, pwd

class MTNet:
    def __init__(self, host:str, port:int, bus:Any, key:bytes|None=None, iv:bytes|None=None)->None:
        self.host=host; self.port=port; self.bus=bus; self.key=key; self.iv=iv
        self.rd=None; self.wr=None; self.buf=bytearray(); self.stop_ev=asyncio.Event(); self.seq=0
        self.pending:dict[int,asyncio.Future[dict[str,Any]]]={}
        self.transport=IntermediateTransport(); self.codec=MTCodec(); self.msg_ids=MsgIdGen(); self.wrote_tag=False
        self.auth_key:bytes|None=None; self.server_salt:bytes=b'\x00'*8; self.session_id=secrets.token_bytes(8)

    def pick(self,obj:dict[str,Any],*keys:str)->Any:
        for k in keys:
            if k in obj: return obj[k]
        return None

    def pack(self, raw:bytes)->bytes: return self.transport.pack(raw)
    def proxy_cfg(self)->ProxyCfg|None:
        raw = os.getenv("ALL_PROXY") or os.getenv("all_proxy")
        if not raw:
            return None
        p = urllib.parse.urlparse(raw)
        if p.scheme.lower() not in {"socks5", "socks5h"}:
            return None
        if not p.hostname or not p.port:
            return None
        user = urllib.parse.unquote(p.username) if p.username else None
        pwd = urllib.parse.unquote(p.password) if p.password else None
        return ProxyCfg(p.scheme.lower(), p.hostname, p.port, user, pwd)

    async def open_via_proxy(self, px:ProxyCfg)->tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        rd, wr = await asyncio.open_connection(px.host, px.port)
        await self.socks5_handshake(rd, wr, px, self.host, self.port)
        return rd, wr

    async def socks5_handshake(self, rd:asyncio.StreamReader, wr:asyncio.StreamWriter, px:ProxyCfg, dst_host:str, dst_port:int)->None:
        methods = [0]
        if px.user is not None or px.pwd is not None:
            methods.append(2)
        wr.write(bytes([5, len(methods), *methods])); await wr.drain()
        rsp = await rd.readexactly(2)
        if rsp[0] != 5 or rsp[1] == 0xFF:
            raise ConnectionError(f"SOCKS5 auth method negotiation failed: {rsp.hex()}")
        if rsp[1] == 2:
            u = (px.user or "").encode()
            pw = (px.pwd or "").encode()
            if len(u) > 255 or len(pw) > 255:
                raise ValueError("SOCKS5 username/password too long")
            wr.write(bytes([1, len(u)]) + u + bytes([len(pw)]) + pw); await wr.drain()
            ar = await rd.readexactly(2)
            if ar[1] != 0:
                raise ConnectionError(f"SOCKS5 auth failed: {ar.hex()}")
        host_b = dst_host.encode("idna")
        if len(host_b) > 255:
            raise ValueError("SOCKS5 destination host too long")
        req = bytes([5, 1, 0, 3, len(host_b)]) + host_b + dst_port.to_bytes(2, "big")
        wr.write(req); await wr.drain()
        head = await rd.readexactly(4)
        if head[0] != 5 or head[1] != 0:
            raise ConnectionError(f"SOCKS5 connect failed: {head.hex()}")
        atyp = head[3]
        if atyp == 1:
            await rd.readexactly(4 + 2)
        elif atyp == 3:
            ln = await rd.readexactly(1)
            await rd.readexactly(ln[0] + 2)
        elif atyp == 4:
            await rd.readexactly(16 + 2)
        else:
            raise ConnectionError(f"SOCKS5 reply has unknown ATYP={atyp}")

    async def boot(self)->None:
        if self.rd and self.wr and not self.wr.is_closing(): return
        px = self.proxy_cfg()
        if px is not None:
            self.rd, self.wr = await self.open_via_proxy(px)
        else:
            self.rd,self.wr=await asyncio.open_connection(self.host,self.port)
        self.wr.write(b"\xee\xee\xee\xee"); await self.wr.drain(); self.wrote_tag=True

    def cut(self)->list[bytes]:
        out=[]; i=0; raw=bytes(self.buf)
        while i < len(raw):
            if i+4>len(raw): break
            ln=int.from_bytes(raw[i:i+4], 'little'); i+=4
            if i+ln>len(raw):
                i -= 4
                break
            out.append(raw[i:i+ln]); i+=ln
        self.buf[:]=raw[i:]
        return out

    def _log_socket_close(self)->None:
        if self.buf:
            print(f"[RX] Socket closed. Left in buffer: {self.buf.hex()}")
            if len(self.buf) >= 4:
                err = int.from_bytes(self.buf[:4], 'little', signed=True)
                print(f"[RX] Possible Telegram int32 error: {err}")

    async def read_packet(self)->bytes:
        while True:
            for p in self.cut(): return p
            raw=await self.rd.read(65536)
            if not raw:
                self._log_socket_close()
                raise ConnectionError('mt socket closed')
            print(f"[RX] <<< {raw.hex()}")
            self.buf.extend(raw)

    async def invoke_unencrypted(self, body:bytes)->bytes:
        await self.boot(); assert self.wr
        pkt=self.pack(MTMessage.unencrypted(self.msg_ids.next(), body))
        print(f"[TX] >>> {pkt.hex()}")
        self.wr.write(pkt); await self.wr.drain()
        resp=await self.read_packet(); return resp

    def _read_unencrypted_body(self, pkt:bytes)->bytes:
        r=Reader(pkt); _=r.i64(); _=r.i64(); ln=r.i32(); return r.take(ln)

    async def ensure_auth_key(self)->None:
        if self.auth_key is not None: return
        nonce=secrets.token_bytes(16)
        res=self._read_unencrypted_body(await self.invoke_unencrypted(self.codec.req_pq_multi(nonce)))
        rr=Reader(res); cid=rr.u32();
        if cid != 0x05162463: raise RuntimeError(f'unexpected resPQ cid={cid:x}')
        n=rr.take(16); server_nonce=rr.take(16); pq=rr.tl_bytes(); _vec=rr.u32(); cnt=rr.i32(); fps=[rr.i64() for _ in range(cnt)]
        if n!=nonce: raise RuntimeError('nonce mismatch')
        # Telegram RSA key #1 (ported from pyrogram.crypto.rsa)
        fp=-4344800451088585951
        if fp not in fps: fp=fps[0]
        n_mod=int('C150023E2F70DB7985DED064759CFECF0AF328E69A41DAF4D6F01B538135A6F91F8F8B2A0EC9BA9720CE352EFCF6C5680FFC424BD634864902DE0B4BD6D49F4E580230E3AE97D95C8B19442B3C0A10D8F5633FECEDD6926A7F6DAB0DDB7D457F9EA81B8465FCD6FFFEED114011DF91C059CAEDAF97625F6C96ECC74725556934EF781D866B34F011FCE4D835A090196E9A5F0E4449AF7EB697DDB9076494CA5F81104A305B6DD27665722C46B60E5DF680FB16B210607EF217652E60236C255F6A28315F4083A96791D7214BF64C1DF4FD0DB1944FB26A2A57031B32EEE64AD15A8BA68885CDE74A5BFC920F6ABF59BA5C75506373E7130F9042DA922179251F',16)
        e=65537
        p,q=sorted(factorize(int.from_bytes(pq,'big')))
        new_nonce=secrets.token_bytes(32)
        inner=self.codec.p_q_inner_data_dc(pq=pq,p=p.to_bytes(4,'big'),q=q.to_bytes(4,'big'),nonce=nonce,server_nonce=server_nonce,new_nonce=new_nonce,dc=2)
        enc=rsa_pad_encrypt(inner,n_mod,e)
        dh=self._read_unencrypted_body(await self.invoke_unencrypted(self.codec.req_dh_params(nonce=nonce,server_nonce=server_nonce,p=p.to_bytes(4,'big'),q=q.to_bytes(4,'big'),fp=fp,encrypted_data=enc)))
        rd=Reader(dh); dcid=rd.u32();
        if dcid!=0xd0e8075c: raise RuntimeError(f'unexpected dh params cid={dcid:x}')
        _=rd.take(16); _=rd.take(16); encrypted_answer=rd.tl_bytes()
        tmp_key,tmp_iv=kdf(new_nonce,server_nonce)
        dec=bytes(rx.aes_ige_dec_raw(encrypted_answer,tmp_key,tmp_iv)) if rx else b''
        answer=dec[20:]
        ra=Reader(answer); aid=ra.u32()
        if aid!=0xb5890dba: raise RuntimeError('unexpected server_DH_inner_data')
        _=ra.take(16); _=ra.take(16); g=ra.i32(); dh_prime=int.from_bytes(ra.tl_bytes(),'big'); g_a=int.from_bytes(ra.tl_bytes(),'big'); _=ra.i32(); _=ra.i32()
        b=int.from_bytes(secrets.token_bytes(256),'big'); g_b=pow(g,b,dh_prime).to_bytes(256,'big')
        cli=self.codec.client_dh_inner(nonce=nonce,server_nonce=server_nonce,retry_id=0,g_b=g_b)
        payload=sha1(cli).digest()+cli; payload+=b'\x00'*((16-len(payload)%16)%16)
        enc2=bytes(rx.aes_ige_enc_raw(payload,tmp_key,tmp_iv)) if rx else b''
        ans=self._read_unencrypted_body(await self.invoke_unencrypted(self.codec.set_client_dh_params(nonce=nonce,server_nonce=server_nonce,encrypted_data=enc2)))
        c=Reader(ans).u32()
        if c!=0x3bcbf734: raise RuntimeError(f'dh_gen not ok: {c:x}')
        self.auth_key=pow(g_a,b,dh_prime).to_bytes(256,'big')
        self.server_salt=bytes(a^b for a,b in zip(new_nonce[:8],server_nonce[:8]))

    def _parse_phone_code_hash(self, result:bytes)->str|None:
        # auth.sentCode: constructor + flags + type + phone_code_hash + ...
        # We keep this parser intentionally small and tolerant to schema drift.
        try:
            r = Reader(result)
            _cid = r.u32()
            _flags = r.i32()
            # Skip auth.SentCodeType object (constructor + best-effort fields).
            st = r.u32()
            if st in {0x9fd736, 0x3dbb5986, 0xc000bba2, 0x5353e5a7, 0xab03c6d9}:
                # Known variants usually carry either one int or a pattern string.
                if st in {0x3dbb5986, 0xc000bba2, 0x9fd736, 0xab03c6d9}:
                    _ = r.i32()
                elif st == 0x5353e5a7:
                    _ = r.tl_bytes()
            else:
                # Unknown sentCodeType; continue with heuristic below.
                pass
            v = r.tl_bytes().decode("utf-8", errors="ignore")
            if v:
                return v
        except Exception:
            pass
        # Heuristic fallback: locate first plausible TL-string token in payload.
        i = 0
        while i < len(result):
            n0 = result[i]
            if n0 == 254:
                if i + 4 > len(result):
                    break
                ln = int.from_bytes(result[i + 1:i + 4], "little")
                head = 4
            else:
                ln = n0
                head = 1
            j = i + head
            if 0 < ln <= 256 and j + ln <= len(result):
                raw = result[j:j + ln]
                try:
                    s = raw.decode("utf-8")
                    if 6 <= len(s) <= 256 and all(ch.isalnum() or ch in "_-=" for ch in s):
                        return s
                except Exception:
                    pass
            i += 1
        return None

    def _handle_encrypted_packet(self, pkt:bytes)->None:
        if not self.auth_key or rx is None:
            return
        if len(pkt) < 24:
            return
        _auth_key_id = pkt[:8]
        msg_key = pkt[8:24]
        enc = pkt[24:]
        aes_key, aes_iv = kdf_msg(self.auth_key, msg_key, False)
        dec = bytes(rx.aes_ige_dec_raw(enc, aes_key, aes_iv))
        r = Reader(dec)
        _salt = r.take(8); _sid = r.take(8); _msg_id = r.i64(); _seq = r.i32(); ln = r.i32()
        msg = r.take(ln)
        if len(msg) < 12:
            return
        rm = Reader(msg)
        cid = rm.u32()
        if cid != 0xf35c6d01:  # rpc_result
            return
        req_msg_id = rm.i64()
        result = msg[12:]
        fut = self.pending.pop(req_msg_id, None)
        if not fut or fut.done():
            return
        phone_code_hash = self._parse_phone_code_hash(result)
        if phone_code_hash:
            fut.set_result({"phone_code_hash": phone_code_hash})
        else:
            fut.set_result({"ok": True, "raw_result_hex": result.hex()})

    async def send(self,obj:dict[str,Any], req_msg_id:int|None=None)->int:
        await self.ensure_auth_key()
        if obj.get('act') not in {'auth.sendCode','auth_send_code'}: raise NotImplementedError(obj.get('act'))
        body=self.codec.auth_send_code(str(obj.get('phone_number') or obj.get('phone')), int(obj['api_id']), str(obj['api_hash']))
        msg_id=req_msg_id if req_msg_id is not None else self.msg_ids.next(); seq_no=1
        m=b''
        m += self.server_salt + self.session_id + msg_id.to_bytes(8,'little',signed=True) + seq_no.to_bytes(4,'little',signed=True)
        m += len(body).to_bytes(4,'little',signed=True) + body
        pad=secrets.token_bytes((16-(len(m)+12)%16)%16 + 12)
        msg_key_large=sha256(self.auth_key[88:120]+m+pad).digest(); msg_key=msg_key_large[8:24]
        aes_key,aes_iv=kdf_msg(self.auth_key,msg_key,True)
        enc=bytes(rx.aes_ige_enc_raw(m+pad,aes_key,aes_iv))
        pkt=self.pack(int.from_bytes(sha1(self.auth_key).digest()[-8:],'little').to_bytes(8,'little')+msg_key+enc)
        print(f"[TX] >>> {pkt.hex()}")
        self.wr.write(pkt); await self.wr.drain()
        return msg_id


    async def close(self)->None:
        if self.wr:
            self.wr.close(); await self.wr.wait_closed()
            self.wr=None; self.rd=None

    async def send_msg(self, chat_id:int|str, text:str, **kw:Any)->dict[str,Any]:
        raise NotImplementedError('send_msg over MT not mapped yet')

    async def del_msg(self, chat_id:int|str, msg_id:int)->dict[str,Any]:
        raise NotImplementedError('del_msg over MT not mapped yet')

    async def call(self,act:str,**kw:Any)->dict[str,Any]:
        loop = asyncio.get_running_loop()
        fut:asyncio.Future[dict[str,Any]] = loop.create_future()
        req_msg_id = self.msg_ids.next()
        self.pending[req_msg_id] = fut
        obj={'act':act}; obj.update({k:v for k,v in kw.items() if v is not None})
        await self.send(obj, req_msg_id=req_msg_id)
        return await fut

    async def spin(self)->None:
        while not self.stop_ev.is_set():
            pkt = await self.read_packet()
            self._handle_encrypted_packet(pkt)
