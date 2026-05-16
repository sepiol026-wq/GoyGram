# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
# Contains elements of Aiogram (MIT) / Pyrogram (LGPL-3.0)
from __future__ import annotations
import asyncio, os, secrets, struct, urllib.parse
from hashlib import sha1, sha256
from typing import Any

from .tl_core import IntermediateTransport, MTCodec, MTMessage, MsgIdGen, Reader, factorize, kdf, kdf_msg, rsa_pad_encrypt

try:
    from goygram.ext import _ext as rx
except Exception:
    rx = None

TELEGRAM_RSA_KEYS: dict[int, int] = {
    847625836280919973: int("22081946531037833540524260580660774032207476521197121128740358761486364763467087828766873972338019078976854986531076484772771735399701424566177039926855356719497736439289455286277202113900509554266057302466528985253648318314129246825219640197356165626774276930672688973278712614800066037531599375044750753580126415613086372604312320014358994394131667022861767539879232149461579922316489532682165746762569651763794500923643656753278887871955676253526661694459370047843286685859688756429293184148202379356802488805862746046071921830921840273062124571073336369210703400985851431491295910187179045081526826572515473914151"),
    1562291298945373506: int("23978758553106631992002580305620005835060400692492410830911253690968985161770919571023213268734637655796435779238577529598157303153929847488434262037216243092374262144086701552588446162198373312512977891135864544907383666560742498178155572733831904785232310227644261688873841336264291123806158164086416723396618993440700301670694812377102225720438542027067699276781356881649272759102712053106917756470596037969358935162126553921536961079884698448464480018715128825516337818216719699963463996161433765618041475321701550049005950467552064133935768219696743607832667385715968297285043180567281391541729832333512747963903"),
    -5859577972006586033: int("22718646979021445086805300267873836551952264292680929983215333222894263271262525404635917732844879510479026727119219632282263022986926715926905675829369119276087034208478103497496557160062032769614235480480336458978483235018994623019124956728706285653879392359295937777480998285327855536342942377483433941973435757959758939732133845114873967169906896837881767555178893700532356888631557478214225236142802178882405660867509208028117895779092487773043163348085906022471454630364430126878252139917614178636934412103623869072904053827933244809215364242885476208852061471203189128281292392955960922615335169478055469443233"),
    6491968696586960280: int("24037766801008650742980770419085067708599000106468359115503808361335510549334399420739246345211161442047800836519033544747025851693968269285475039555231773313724462564908666239840898204833183290939296455776367417572678362602041185421910456164281750840651140599266716366431221860463163678044675384797103831824697137394559208723253047225996994374103488753637228569081911062604259973219466527532055001206549020539767836549715548081391829906556645384762696840019083743214331245456023666332360278739093925808884746079174665122518196162846505196334513910135812480878181576802670132412681595747104670774040613733524133809153"),
    -4344800451088585951: int("24403446649145068056824081744112065346446136066297307473868293895086332508101251964919587745984311372853053253457835208829824428441874946556659953519213382748319518214765985662663680818277989736779506318868003755216402538945900388706898101286548187286716959100102939636333452457308619454821845196109544157601096359148241435922125602449263164512290854366930013825808102403072317738266383237191313714482187326643144603633877219028262697593882410403273959074350849923041765639673335775605842311578109726403165298875058941765362622936097839775380070572921007586266115476975819175319995527916042178582540628652481530373407"),
    -7306692244673891685: int("25081407810410225030931722734886059247598515157516470397242545867550116598436968553551465554653745201634977779380884774534457386795922003815072071558370597290368737862981871277312823942822144802509055492512145589734772907225259038113414940384446493111736999668652848440655603157665903721517224934142301456312994547591626081517162758808439979745328030376796953660042629868902013177751703385501412640560275067171555763725421377065095231095517201241069856888933358280729674273422117201596511978645878544308102076746465468955910659145532699238576978901011112475698963666091510778777356966351191806495199073754705289253783"),
    -5738946642031285640: int("22347337644621997830323797217583448833849627595286505527328214795712874535417149457567295215523199212899872122674023936713124024124676488204889357563104452250187725437815819680799441376434162907889288526863223004380906766451781702435861040049293189979755757428366240570457372226323943522935844086838355728767565415115131238950994049041950699006558441163206523696546297006014416576123345545601004508537089192869558480948139679182328810531942418921113328804749485349441503927570568778905918696883174575510385552845625481490900659718413892216221539684717773483326240872061786759868040623935592404144262688161923519030977"),
    8205599988028290019: int("24573455207957565047870011785254215390918912369814947541785386299516827003508659346069416840622922416779652050319196701077275060353178142796963682024347858398319926119639265555410256455471016400261630917813337515247954638555325280392998950756512879748873422896798579889820248358636937659872379948616822902110696986481638776226860777480684653756042166610633513404129518040549077551227082262066602286208338952016035637334787564972991208252928951876463555456715923743181359826124083963758009484867346318483872552977652588089928761806897223231500970500186019991032176060579816348322451864584743414550721639495547636008351"),
}


def _tl_bytes_at(b:bytes, p:int)->tuple[bytes,int]:
    n0 = b[p]
    p += 1
    if n0 == 254:
        n = int.from_bytes(b[p:p+3], "little")
        p += 3
        head = 4
    else:
        n = n0
        head = 1
    d = b[p:p+n]
    p += n
    pad = (4 - ((head + n) % 4)) % 4
    p += pad
    return d, p


def _skip_tl_object(b:bytes, p:int)->int:
    if p + 4 > len(b):
        return len(b)
    cid = int.from_bytes(b[p:p+4], "little")
    p += 4
    if cid == 0x1cb5c415:
        if p + 4 > len(b):
            return len(b)
        cnt = int.from_bytes(b[p:p+4], "little", signed=True)
        p += 4
        for _ in range(max(cnt, 0)):
            p = _skip_tl_object(b, p)
        return p
    if cid in {0x997275b5, 0xbc799737}:
        return p
    if cid == 0x2144ca19:
        p += 4
        _, p = _tl_bytes_at(b, p)
        return p
    if cid in {0xb5757299, 0x44747e9a}:
        flags = int.from_bytes(b[p:p+4], "little", signed=True); p += 4
        p += 8
        _, p = _tl_bytes_at(b, p)
        _, p = _tl_bytes_at(b, p)
        if flags & (1 << 1):
            _, p = _tl_bytes_at(b, p)
        if flags & (1 << 4):
            _, p = _tl_bytes_at(b, p)
        _, p = _tl_bytes_at(b, p)
        if flags & (1 << 0):
            p += 4
        _, p = _tl_bytes_at(b, p)
        _, p = _tl_bytes_at(b, p)
        _, p = _tl_bytes_at(b, p)
        p += 4
        if flags & (1 << 2):
            p += 4
        if flags & (1 << 3):
            p += 4
        if flags & (1 << 5):
            p += 4
        if flags & (1 << 6):
            p += 4
        return p
    return len(b)


def _parse_user_obj(b:bytes)->dict[str,Any]|None:
    if len(b) < 12:
        return None
    cid = int.from_bytes(b[:4], "little")
    if cid != 0x20b1422:
        return None
    p = 4
    flags = int.from_bytes(b[p:p+4], "little", signed=True); p += 4
    user_id = int.from_bytes(b[p:p+8], "little", signed=True); p += 8
    if flags & (1 << 0):
        _, p = _tl_bytes_at(b, p)
    if flags & (1 << 1):
        _, p = _tl_bytes_at(b, p)
    if flags & (1 << 2):
        _, p = _tl_bytes_at(b, p)
    username = None
    if flags & (1 << 3):
        u, p = _tl_bytes_at(b, p)
        username = u.decode("utf-8", errors="ignore")
    phone = None
    if flags & (1 << 4):
        ph, p = _tl_bytes_at(b, p)
        phone = ph.decode("utf-8", errors="ignore")
    out = {"id": user_id}
    if username:
        out["username"] = username
    if phone:
        out["phone"] = phone
    return out

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
        rr=Reader(res); cid=rr.u32()
        if cid != 0x05162463: raise RuntimeError(f'unexpected resPQ cid={cid:x}')
        n=rr.take(16); server_nonce=rr.take(16); pq=rr.tl_bytes(); _vec=rr.u32(); cnt=rr.i32(); fps=[rr.i64() for _ in range(cnt)]
        if n!=nonce: raise RuntimeError('nonce mismatch')
        fp = next((x for x in fps if x in TELEGRAM_RSA_KEYS), None)
        if fp is None:
            raise RuntimeError(f"no known Telegram RSA key fingerprint in resPQ: {fps!r}")
        n_mod = TELEGRAM_RSA_KEYS[fp]
        e=65537
        p,q=sorted(factorize(int.from_bytes(pq,'big')))
        new_nonce=secrets.token_bytes(32)
        inner=self.codec.p_q_inner_data_dc(pq=pq,p=p.to_bytes(4,'big'),q=q.to_bytes(4,'big'),nonce=nonce,server_nonce=server_nonce,new_nonce=new_nonce,dc=2)
        enc=rsa_pad_encrypt(inner,n_mod,e)
        dh=self._read_unencrypted_body(await self.invoke_unencrypted(self.codec.req_dh_params(nonce=nonce,server_nonce=server_nonce,p=p.to_bytes(4,'big'),q=q.to_bytes(4,'big'),fp=fp,encrypted_data=enc)))
        rd=Reader(dh); dcid=rd.u32()
        if dcid!=0xd0e8075c: raise RuntimeError(f'unexpected dh params cid={dcid:x}')
        _=rd.take(16); _=rd.take(16); encrypted_answer=rd.tl_bytes()
        tmp_key,tmp_iv=kdf(new_nonce,server_nonce)
        if rx is None: raise RuntimeError('rx (goygram.ext._ext) is not available; cannot decrypt DH answer')
        dec=bytes(rx.aes_ige_dec_raw(encrypted_answer,tmp_key,tmp_iv))
        answer=dec[20:]
        ra=Reader(answer); aid=ra.u32()
        if aid!=0xb5890dba: raise RuntimeError('unexpected server_DH_inner_data')
        _=ra.take(16); _=ra.take(16); g=ra.i32(); dh_prime=int.from_bytes(ra.tl_bytes(),'big'); g_a=int.from_bytes(ra.tl_bytes(),'big'); _=ra.i32(); _=ra.i32()
        b=int.from_bytes(secrets.token_bytes(256),'big'); g_b=pow(g,b,dh_prime).to_bytes(256,'big')
        cli=self.codec.client_dh_inner(nonce=nonce,server_nonce=server_nonce,retry_id=0,g_b=g_b)
        payload=sha1(cli).digest()+cli; payload+=b'\x00'*((16-len(payload)%16)%16)
        enc2=bytes(rx.aes_ige_enc_raw(payload,tmp_key,tmp_iv))
        ans=self._read_unencrypted_body(await self.invoke_unencrypted(self.codec.set_client_dh_params(nonce=nonce,server_nonce=server_nonce,encrypted_data=enc2)))
        c=Reader(ans).u32()
        if c!=0x3bcbf734: raise RuntimeError(f'dh_gen not ok: {c:x}')
        self.auth_key=pow(g_a,b,dh_prime).to_bytes(256,'big')
        self.server_salt=bytes(a^b for a,b in zip(new_nonce[:8],server_nonce[:8]))

    def _parse_phone_code_hash(self, result:bytes)->str|None:
        try:
            r = Reader(result)
            _cid = r.u32()
            _flags = r.i32()
            st = r.u32()
            if st in {0x9fd736, 0x3dbb5986, 0xc000bba2, 0x5353e5a7, 0xab03c6d9}:
                if st in {0x3dbb5986, 0xc000bba2, 0x9fd736, 0xab03c6d9}:
                    _ = r.i32()
                elif st == 0x5353e5a7:
                    _ = r.tl_bytes()
            v = r.tl_bytes().decode("utf-8", errors="ignore")
            if v:
                return v
        except Exception:
            pass
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
        if cid != 0xf35c6d01:
            return
        req_msg_id = rm.i64()
        result = msg[12:]
        fut = self.pending.pop(req_msg_id, None)
        if not fut or fut.done():
            return
        parsed = self._parse_rpc_result(result)
        fut.set_result(parsed)

    def _parse_auth_result(self, result:bytes)->dict[str,Any]|None:
        if len(result) < 8:
            return None
        cid = int.from_bytes(result[:4], "little")
        if cid not in {0xb5757299, 0x44747e9a}:
            return None
        p = 4
        flags = int.from_bytes(result[p:p+4], "little", signed=True); p += 4
        p += 8
        _, p = _tl_bytes_at(result, p)
        _, p = _tl_bytes_at(result, p)
        if flags & (1 << 1):
            _, p = _tl_bytes_at(result, p)
        if flags & (1 << 4):
            _, p = _tl_bytes_at(result, p)
        _, p = _tl_bytes_at(result, p)
        if flags & (1 << 0):
            p += 4
        _, p = _tl_bytes_at(result, p)
        _, p = _tl_bytes_at(result, p)
        _, p = _tl_bytes_at(result, p)
        p += 4
        if flags & (1 << 2):
            p += 4
        if flags & (1 << 3):
            p += 4
        if flags & (1 << 5):
            p += 4
        if flags & (1 << 6):
            p += 4
        user = _parse_user_obj(result[p:])
        out = {"ok": True, "auth_key": self.auth_key or b""}
        if user is not None:
            out["user"] = user
        return out

    def _parse_rpc_result(self, result:bytes)->dict[str,Any]:
        if len(result) >= 4:
            cid = int.from_bytes(result[:4], "little")
            if cid == 0x2144ca19:
                r = Reader(result)
                _ = r.u32()
                ec = r.i32()
                em = r.tl_bytes().decode("utf-8", errors="ignore")
                return {"ok": False, "error_code": ec, "error": em, "error_message": em}
        phone_code_hash = self._parse_phone_code_hash(result)
        if phone_code_hash:
            return {"ok": True, "phone_code_hash": phone_code_hash}
        auth = self._parse_auth_result(result)
        if auth is not None:
            return auth
        return {"ok": True, "raw_result_hex": result.hex()}

    async def send(self, obj:dict[str,Any], req_msg_id:int|None=None)->int:
        await self.ensure_auth_key()
        if rx is None: raise RuntimeError('rx (goygram.ext._ext) is not available; cannot encrypt')
        act = obj.get('act')
        if act in {'auth.sendCode', 'auth_send_code'}:
            body=self.codec.auth_send_code(str(obj.get('phone_number') or obj.get('phone')), int(obj['api_id']), str(obj['api_hash']))
        elif act in {'auth.signIn', 'auth_sign_in'}:
            body=self.codec.auth_sign_in(
                str(obj.get('phone_number') or obj.get('phone')),
                str(obj.get('phone_code_hash')),
                str(obj.get('phone_code') or obj.get('code'))
            )
        elif act in {'auth.checkPassword', 'auth_check_password'}:
            body=self.codec.auth_check_password(str(obj.get('password') or ''))
        elif act == 'send_msg':
            raise RuntimeError('send_msg is not available in low-level MT auth transport')
        elif act == 'del_msg':
            raise RuntimeError('del_msg is not available in low-level MT auth transport')
        else:
            raise NotImplementedError(act)
        msg_id=req_msg_id if req_msg_id is not None else self.msg_ids.next()
        self.seq += 1; seq_no = self.seq * 2 - 1
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
        payload={"chat_id": chat_id, "text": text}
        payload.update({k:v for k,v in kw.items() if v is not None})
        return await self.call('send_msg', **payload)

    async def del_msg(self, chat_id:int|str, msg_id:int)->dict[str,Any]:
        return await self.call('del_msg', chat_id=chat_id, msg_id=msg_id)

    async def call(self, act:str, **kw:Any)->dict[str,Any]:
        loop = asyncio.get_running_loop()
        fut:asyncio.Future[dict[str,Any]] = loop.create_future()
        req_msg_id = self.msg_ids.next()
        self.pending[req_msg_id] = fut
        obj={'act':act}; obj.update({k:v for k,v in kw.items() if v is not None})
        try:
            await self.send(obj, req_msg_id=req_msg_id)
            return await asyncio.wait_for(fut, timeout=30.0)
        except asyncio.TimeoutError:
            self.pending.pop(req_msg_id, None)
            raise TimeoutError(f'no response for act={act} msg_id={req_msg_id}')

    async def spin(self)->None:
        while not self.stop_ev.is_set():
            try:
                pkt = await self.read_packet()
                self._handle_encrypted_packet(pkt)
            except ConnectionError as exc:
                for fut in self.pending.values():
                    if not fut.done():
                        fut.set_exception(exc)
                self.pending.clear()
                raise
