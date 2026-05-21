# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
# Contains elements of Aiogram (MIT) / Pyrogram (LGPL-3.0)
from __future__ import annotations
import asyncio, hashlib, os, secrets, struct, urllib.parse, logging
from hashlib import sha1, sha256
from typing import Any

log = logging.getLogger("goygram.mtproto")

from .tl_core import IntermediateTransport, MTCodec, MTMessage, MsgIdGen, Reader, factorize, kdf, kdf_msg, rsa_pad_encrypt

try:
    from goygram import ext as rx
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


def _btoi(b:bytes)->int:
    return int.from_bytes(b, "big")


def _itob(i:int)->bytes:
    return i.to_bytes(256, "big")


def _xor(a:bytes, b:bytes)->bytes:
    return bytes(i ^ j for i, j in zip(a, b))


def _compute_password_hash(algo:dict[str,Any], password:str)->bytes:
    salt1 = bytes(algo["salt1"])
    salt2 = bytes(algo["salt2"])
    hash1 = sha256(salt1 + password.encode() + salt1).digest()
    hash2 = sha256(salt2 + hash1 + salt2).digest()
    hash3 = hashlib.pbkdf2_hmac("sha512", hash2, salt1, 100000)
    return sha256(salt2 + hash3 + salt2).digest()


def _compute_password_check(state:dict[str,Any], password:str)->tuple[int,bytes,bytes]:
    algo = dict(state["current_algo"])
    p_bytes = bytes(algo["p"])
    p = _btoi(p_bytes)
    g = int(algo["g"])
    g_bytes = _itob(g)
    b_bytes = bytes(state["srp_B"])
    b = _btoi(b_bytes)
    srp_id = int(state["srp_id"])
    x_bytes = _compute_password_hash(algo, password)
    x = _btoi(x_bytes)
    g_x = pow(g, x, p)
    k = _btoi(sha256(p_bytes + g_bytes).digest())
    kg_x = (k * g_x) % p
    while True:
        a_bytes = secrets.token_bytes(256)
        a = _btoi(a_bytes)
        a_pub = pow(g, a, p)
        a_pub_bytes = _itob(a_pub)
        u = _btoi(sha256(a_pub_bytes + b_bytes).digest())
        if u > 0:
            break
    g_b = (b - kg_x) % p
    s = pow(g_b, a + (u * x), p)
    k_bytes = sha256(_itob(s)).digest()
    m1_bytes = sha256(
        _xor(sha256(p_bytes).digest(), sha256(g_bytes).digest())
        + sha256(bytes(algo["salt1"])).digest()
        + sha256(bytes(algo["salt2"])).digest()
        + a_pub_bytes
        + b_bytes
        + k_bytes
    ).digest()
    return srp_id, a_pub_bytes, m1_bytes


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
    # known user constructors (Telegram layers 150+)
    if cid in {0x020b1422, 0x8f97c628, 0x5c0d0a2a, 0xd8576e2a, 0x7fe4ab4, 0x2e13f2c3, 0xebe8e785}:
        return _parse_user_obj_v4(b, cid)
    log.warning("Unsupported user constructor 0x%08x, raw=%s", cid, b[:64].hex())
    return None


def _parse_user_obj_v4(b:bytes, cid:int)->dict[str,Any]|None:
    try:
        p = 4
        if cid in {0x8f97c628, 0x5c0d0a2a, 0xd8576e2a, 0x7fe4ab4, 0x2e13f2c3, 0xebe8e785}:
            p = 4
            flags = int.from_bytes(b[p:p+4], "little", signed=True); p += 4
            _flags2 = int.from_bytes(b[p:p+4], "little", signed=True); p += 4
        else:
            flags = int.from_bytes(b[p:p+4], "little", signed=True); p += 4
        user_id = int.from_bytes(b[p:p+8], "little", signed=True); p += 8
        access_hash = None
        if flags & (1 << 0):
            access_hash = int.from_bytes(b[p:p+8], "little", signed=True); p += 8
        first_name = None
        if flags & (1 << 1):
            raw, p = _tl_bytes_at(b, p)
            first_name = raw.decode("utf-8", errors="ignore")
        last_name = None
        if flags & (1 << 2):
            raw, p = _tl_bytes_at(b, p)
            last_name = raw.decode("utf-8", errors="ignore")
        username = None
        if flags & (1 << 3) or flags & (1 << 6):  # flag 6 = usernames vector in newer layers
            raw, p = _tl_bytes_at(b, p)
            username = raw.decode("utf-8", errors="ignore")
        phone = None
        if flags & (1 << 4):
            raw, p = _tl_bytes_at(b, p)
            phone = raw.decode("utf-8", errors="ignore")
        out = {"id": user_id}
        if access_hash is not None:
            out["access_hash"] = access_hash
        if first_name:
            out["first_name"] = first_name
        if last_name:
            out["last_name"] = last_name
        if username:
            out["username"] = username
        if phone:
            out["phone"] = phone
        return out
    except Exception:
        log.warning("User parse failed for cid=0x%08x: %s", cid, b[:128].hex())
        return None

class ProxyCfg:
    def __init__(self, scheme:str, host:str, port:int, user:str|None=None, pwd:str|None=None)->None:
        self.scheme, self.host, self.port, self.user, self.pwd = scheme, host, port, user, pwd

class MTNet:
    def __init__(
        self,
        host:str,
        port:int,
        bus:Any,
        key:bytes|None=None,
        iv:bytes|None=None,
        *,
        app_name:str|None=None,
        app_version:str|None=None,
        device_model:str|None=None,
        system_version:str|None=None,
        system_lang_code:str="en",
        lang_pack:str="",
        lang_code:str="en",
    )->None:
        self.host=host; self.port=port; self.bus=bus; self.key=key; self.iv=iv
        self.rd=None; self.wr=None; self.buf=bytearray(); self.stop_ev=asyncio.Event(); self.seq=0
        self.pending:dict[int,asyncio.Future[dict[str,Any]]]={}
        self.transport=IntermediateTransport(); self.codec=MTCodec(
            app_name=app_name,
            app_version=app_version,
            device_model=device_model,
            system_version=system_version,
            system_lang_code=system_lang_code,
            lang_pack=lang_pack,
            lang_code=lang_code,
        ); self.msg_ids=MsgIdGen(); self.wrote_tag=False
        self.auth_key:bytes|None=None; self.server_salt:bytes=b'\x00'*8; self.session_id=secrets.token_bytes(8)
        self.auth_ready=asyncio.Event()
        self.qr_update_ev=asyncio.Event()
        self._init_done=False
        self._api_id:int|None=None

    def pick(self,obj:dict[str,Any],*keys:str)->Any:
        for k in keys:
            if k in obj: return obj[k]
        return None

    def pack(self, raw:bytes)->bytes: return self.transport.pack(raw)

    def proxy_cfg(self)->ProxyCfg|None:
        raw = (
            os.getenv("ALL_PROXY") or os.getenv("all_proxy")
            or os.getenv("HTTPS_PROXY") or os.getenv("https_proxy")
            or os.getenv("HTTP_PROXY") or os.getenv("http_proxy")
        )
        if not raw:
            return None
        p = urllib.parse.urlparse(raw)
        scheme = p.scheme.lower()
        if scheme not in {"socks5", "socks5h", "http"}:
            return None
        if not p.hostname or not p.port:
            return None
        user = urllib.parse.unquote(p.username) if p.username else None
        pwd = urllib.parse.unquote(p.password) if p.password else None
        return ProxyCfg(scheme, p.hostname, p.port, user, pwd)

    async def open_via_proxy(self, px:ProxyCfg)->tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        rd, wr = await asyncio.open_connection(px.host, px.port)
        if px.scheme in {"socks5", "socks5h"}:
            await self.socks5_handshake(rd, wr, px, self.host, self.port)
        elif px.scheme == "http":
            await self.http_connect_handshake(rd, wr, px, self.host, self.port)
        else:
            raise ConnectionError(f"Unsupported proxy scheme: {px.scheme}")
        return rd, wr

    async def _read_http_headers(self, rd:asyncio.StreamReader, limit:int=65536)->bytes:
        data = bytearray()
        while b"\r\n\r\n" not in data:
            chunk = await rd.read(4096)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > limit:
                raise ConnectionError("HTTP proxy response headers are too large")
        return bytes(data)

    async def http_connect_handshake(self, rd:asyncio.StreamReader, wr:asyncio.StreamWriter, px:ProxyCfg, dst_host:str, dst_port:int)->None:
        auth = ""
        if px.user is not None or px.pwd is not None:
            import base64
            token = f"{px.user or ''}:{px.pwd or ''}".encode("utf-8")
            auth = f"Proxy-Authorization: Basic {base64.b64encode(token).decode('ascii')}\r\n"
        req = (
            f"CONNECT {dst_host}:{dst_port} HTTP/1.1\r\n"
            f"Host: {dst_host}:{dst_port}\r\n"
            f"{auth}"
            "Proxy-Connection: Keep-Alive\r\n\r\n"
        ).encode("ascii", errors="ignore")
        wr.write(req); await wr.drain()
        resp = await self._read_http_headers(rd)
        if not resp:
            raise ConnectionError("HTTP proxy closed connection during CONNECT")
        head = resp.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="ignore")
        parts = head.split(" ", 2)
        if len(parts) < 2:
            raise ConnectionError(f"Malformed HTTP proxy response: {head}")
        try:
            status = int(parts[1])
        except Exception:
            raise ConnectionError(f"Malformed HTTP proxy status line: {head}")
        if status != 200:
            raise ConnectionError(f"HTTP proxy CONNECT failed with status {status}: {head}")

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
            log.debug(f"[RX] Socket closed. Left in buffer: {self.buf.hex()}")
            if len(self.buf) >= 4:
                err = int.from_bytes(self.buf[:4], 'little', signed=True)
                log.debug(f"[RX] Possible Telegram int32 error: {err}")

    async def read_packet(self)->bytes:
        while True:
            for p in self.cut(): return p
            raw=await self.rd.read(65536)
            if not raw:
                self._log_socket_close()
                raise ConnectionError('mt socket closed')
            log.debug(f"[RX] <<< {raw.hex()}")
            self.buf.extend(raw)

    async def invoke_unencrypted(self, body:bytes)->bytes:
        await self.boot(); assert self.wr
        pkt=self.pack(MTMessage.unencrypted(self.msg_ids.next(), body))
        log.debug(f"[TX] >>> {pkt.hex()}")
        self.wr.write(pkt); await self.wr.drain()
        resp=await self.read_packet(); return resp

    def _read_unencrypted_body(self, pkt:bytes)->bytes:
        r=Reader(pkt); _=r.i64(); _=r.i64(); ln=r.i32(); return r.take(ln)

    async def ensure_auth_key(self)->None:
        await self.boot()
        if self.auth_key is not None:
            self.auth_ready.set()
            return
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
        inner=self.codec.p_q_inner_data(pq=pq,p=p.to_bytes(4,'big'),q=q.to_bytes(4,'big'),nonce=nonce,server_nonce=server_nonce,new_nonce=new_nonce)
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
        log.debug(f'[DH] server_DH_inner_data cid={aid:#010x} (expected 0xb5890dba), dec_first32={dec[:32].hex()}')
        if aid!=0xb5890dba: raise RuntimeError(f'unexpected server_DH_inner_data cid={aid:#010x}')
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
        self._init_done=False
        self.auth_ready.set()

    def _parse_phone_code_hash(self, result:bytes)->str|None:
        try:
            r = Reader(result)
            cid = r.u32()
            if cid != 0x5e002502:
                return None
            _flags = r.i32()
            st = r.u32()
            if st in {0x3dbb5986, 0xc000bba2, 0x5353e5a7, 0xab03c6d9, 0xe57b1432, 0x82006484, 0xa5491dea, 0xd9565c39}:
                if st in {0x3dbb5986, 0xc000bba2, 0xab03c6d9}:
                    _ = r.i32()
                elif st == 0x5353e5a7:
                    _ = r.tl_bytes()
                elif st == 0xe57b1432:
                    _, _ = r.tl_bytes(), r.tl_bytes()
                    _ = r.i32()
                elif st == 0x82006484:
                    _ = r.tl_bytes()
                    _ = r.i32()
                elif st == 0xa5491dea:
                    _, _ = r.i32(), r.i32()
                elif st == 0xd9565c39:
                    _ = r.i32()
            v = r.tl_bytes().decode("utf-8", errors="ignore")
            if v:
                return v
        except Exception:
            pass
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

        def _consume(inner: bytes) -> None:
            if len(inner) < 4:
                return
            rm = Reader(inner)
            cid = rm.u32()
            if b'\x91\xe6\x4f\x56' in inner:
                self.qr_update_ev.set()
            if cid == 0xf35c6d01:
                if len(inner) < 12:
                    return
                req_msg_id = rm.i64()
                result = inner[12:]
                fut = self.pending.pop(req_msg_id, None)
                if not fut or fut.done():
                    return
                try:
                    parsed = self._parse_rpc_result(result)
                except Exception as exc:
                    import traceback; traceback.print_exc()
                    parsed = {"ok": True, "raw_result_hex": result.hex(), "_parse_error": str(exc)}
                fut.set_result(parsed)
                return
            if cid == 0x73f1f8dc:
                try:
                    cnt = rm.i32()
                except Exception:
                    return
                for _ in range(max(cnt, 0)):
                    try:
                        _m_id = rm.i64(); _seqno = rm.i32(); mlen = rm.i32()
                        chunk = rm.take(mlen)
                    except Exception:
                        return
                    _consume(chunk)
                return

        _consume(msg)

    def _parse_auth_result(self, result:bytes)->dict[str,Any]|None:
        if len(result) < 8:
            return None
        cid = int.from_bytes(result[:4], "little")
        if cid == 0x44747e9a:
            return {"ok": True, "auth_key": self.auth_key or b""}
        if cid in {0xb5757299, 0x922169ae}:
            p = 4
            flags = int.from_bytes(result[p:p+4], "little", signed=True); p += 4
            if flags & (1 << 4):
                p += 4
            if flags & (1 << 0):
                p += 4
            if flags & (1 << 7):
                _, p = _tl_bytes_at(result, p)
            user = _parse_user_obj(result[p:])
            out = {"ok": True, "auth_key": self.auth_key or b""}
            if user is not None:
                out["user"] = user
            if user is None:
                log.warning("auth result: user parse failed, result[%d:]=%s", p, result[p:p+64].hex())
            return out
        if cid != 0x2ea2c0d4:
            return None
        p = 4
        flags = int.from_bytes(result[p:p+4], "little", signed=True); p += 4
        if flags & (1 << 1):
            p += 4
        if flags & (1 << 0):
            p += 4
        if flags & (1 << 2):
            _, p = _tl_bytes_at(result, p)
        user = _parse_user_obj(result[p:])
        out = {"ok": True, "auth_key": self.auth_key or b""}
        if user is not None:
            out["user"] = user
        return out

    def _parse_account_password(self, result:bytes)->dict[str,Any]|None:
        if len(result) < 8:
            return None
        if int.from_bytes(result[:4], "little") != 0x957b50fb:
            return None
        p = 4
        flags = int.from_bytes(result[p:p+4], "little", signed=True); p += 4
        out:dict[str,Any] = {
            "ok": True,
            "has_recovery": bool(flags & (1 << 0)),
            "has_secure_values": bool(flags & (1 << 1)),
            "has_password": bool(flags & (1 << 2)),
        }
        if flags & (1 << 2):
            if p + 4 > len(result):
                return None
            algo_cid = int.from_bytes(result[p:p+4], "little"); p += 4
            if algo_cid != 0x3a912d4a:
                return {
                    "ok": False,
                    "error": f"UNSUPPORTED_PASSWORD_ALGO_{algo_cid:x}",
                    "error_message": f"UNSUPPORTED_PASSWORD_ALGO_{algo_cid:x}",
                }
            salt1, p = _tl_bytes_at(result, p)
            salt2, p = _tl_bytes_at(result, p)
            g = int.from_bytes(result[p:p+4], "little", signed=True); p += 4
            prime, p = _tl_bytes_at(result, p)
            srp_b, p = _tl_bytes_at(result, p)
            srp_id = int.from_bytes(result[p:p+8], "little", signed=True); p += 8
            out["current_algo"] = {"salt1": salt1, "salt2": salt2, "g": g, "p": prime}
            out["srp_B"] = srp_b
            out["srp_id"] = srp_id
        if flags & (1 << 3):
            hint, p = _tl_bytes_at(result, p)
            out["hint"] = hint.decode("utf-8", errors="ignore")
        return out

    def _parse_login_token(self, result:bytes)->dict[str,Any]|None:
        if len(result) < 4: return None
        cid = int.from_bytes(result[:4], "little")
        if cid == 0x629f1980:
            r = Reader(result)
            r.u32()
            expires = r.i32()
            token = r.tl_bytes()
            return {"ok": True, "type": "loginToken", "expires": expires, "token": token}
        if cid == 0x068e9916:
            r = Reader(result)
            r.u32()
            dc_id = r.i32()
            token = r.tl_bytes()
            return {"ok": True, "type": "loginTokenMigrateTo", "dc_id": dc_id, "token": token}
        if cid == 0x390d5c5e:
            r = Reader(result)
            r.u32()
            auth_bytes = result[r.p:]
            parsed = self._parse_auth_result(auth_bytes)
            if parsed:
                parsed["type"] = "loginTokenSuccess"
                return parsed
            return {"ok": True, "type": "loginTokenSuccess", "raw": auth_bytes.hex()}
        return None

    def _parse_rpc_result(self, result:bytes)->dict[str,Any]:
        if len(result) >= 4:
            cid = int.from_bytes(result[:4], "little")
            if cid == 0x2144ca19:
                r = Reader(result)
                _ = r.u32()
                ec = r.i32()
                em = r.tl_bytes().decode("utf-8", errors="ignore")
                return {"ok": False, "error_code": ec, "error": em, "error_message": em}
            if cid == 0x3072cfa1:
                import gzip as _gz
                try:
                    packed = Reader(result)
                    packed.u32()
                    compressed = packed.tl_bytes()
                    result = _gz.decompress(compressed)
                except Exception:
                    pass
        auth = self._parse_auth_result(result)
        if auth is not None:
            return auth
        pwd = self._parse_account_password(result)
        if pwd is not None:
            return pwd
        phone_code_hash = self._parse_phone_code_hash(result)
        if phone_code_hash:
            return {"ok": True, "phone_code_hash": phone_code_hash}
        login_token = self._parse_login_token(result)
        if login_token is not None:
            return login_token
        return {"ok": True, "raw_result_hex": result.hex()}

    def _resolve_peer(self, obj:dict[str,Any])->bytes:
        chat_id = obj.get('chat_id') or obj.get('peer')
        access_hash = obj.get('access_hash', 0)
        if chat_id is None:
            return self.codec.input_peer_self()
        if isinstance(chat_id, bytes):
            return chat_id
        if isinstance(chat_id, str):
            if chat_id in ('self', 'me'):
                return self.codec.input_peer_self()
            if chat_id.lstrip('-').isdigit():
                chat_id = int(chat_id)
            else:
                return self.codec.input_peer_self()
        if isinstance(chat_id, int):
            if chat_id == 0:
                return self.codec.input_peer_self()
            if chat_id > 0:
                return self.codec.input_peer_user(chat_id, int(access_hash))
            raw = -chat_id
            if raw > 1000000000000:
                channel_id = raw - 1000000000000
                return self.codec.input_peer_channel(channel_id, int(access_hash))
            return self.codec.input_peer_chat(raw)
        return self.codec.input_peer_self()

    def _resolve_channel(self, obj:dict[str,Any])->bytes:
        chat_id = obj.get('chat_id') or obj.get('channel')
        access_hash = obj.get('access_hash', 0)
        if isinstance(chat_id, bytes):
            return chat_id
        if isinstance(chat_id, int):
            if chat_id < 0:
                raw = -chat_id
                if raw > 1000000000000:
                    channel_id = raw - 1000000000000
                else:
                    channel_id = raw
            else:
                channel_id = chat_id
            return self.codec.input_channel(channel_id, int(access_hash))
        return self.codec.input_channel(0, 0)

    def _resolve_user(self, obj:dict[str,Any])->bytes:
        user_id = obj.get('user_id')
        access_hash = obj.get('access_hash', 0)
        if user_id is None or (isinstance(user_id, str) and user_id in ('self', 'me')):
            return self.codec.input_user_self()
        if isinstance(user_id, bytes):
            return user_id
        return self.codec.input_user(int(user_id), int(access_hash))

    def _build_body(self, act:str, obj:dict[str,Any])->bytes:
        if act in {'auth.sendCode', 'auth_send_code'}:
            return self.codec.auth_send_code(str(obj.get('phone_number') or obj.get('phone')), int(obj['api_id']), str(obj['api_hash']))
        if act in {'auth.signIn', 'auth_sign_in'}:
            return self.codec.auth_sign_in(
                str(obj.get('phone_number') or obj.get('phone')),
                str(obj.get('phone_code_hash')),
                str(obj.get('phone_code') or obj.get('code')),
                int(obj['api_id'])
            )
        if act in {'account.getPassword', 'account_get_password'}:
            return self.codec.account_get_password(int(obj['api_id']))
        if act in {'auth.checkPasswordSrp', 'auth_check_password_srp'}:
            return self.codec.auth_check_password(
                srp_id=int(obj['srp_id']),
                A=bytes(obj['A']),
                M1=bytes(obj['M1']),
                api_id=int(obj['api_id'])
            )
        if act in {'auth.exportLoginToken', 'auth_export_login_token'}:
            return self.codec.auth_export_login_token(int(obj['api_id']), str(obj['api_hash']), obj.get('except_ids', []))
        if act in {'auth.importLoginToken', 'auth_import_login_token'}:
            return self.codec.auth_import_login_token(bytes(obj['token']), int(obj['api_id']))
        if act in {'auth.logOut', 'auth_log_out'}:
            return self.codec.auth_log_out()
        if act in {'messages.getDialogs', 'get_dialogs'}:
            return self.codec.messages_get_dialogs(
                limit=int(obj.get('limit', 100)),
                exclude_pinned=bool(obj.get('exclude_pinned', False)),
                folder_id=obj.get('folder_id'),
                offset_date=int(obj.get('offset_date', 0)),
                offset_id=int(obj.get('offset_id', 0)),
                offset_peer=obj.get('offset_peer'),
                hash=int(obj.get('hash', 0)),
            )
        if act in {'messages.getHistory', 'get_history'}:
            peer = obj.get('peer') or self._resolve_peer(obj)
            return self.codec.messages_get_history(
                peer=peer if isinstance(peer, bytes) else self._resolve_peer(obj),
                offset_id=int(obj.get('offset_id', 0)),
                offset_date=int(obj.get('offset_date', 0)),
                add_offset=int(obj.get('add_offset', 0)),
                limit=int(obj.get('limit', 100)),
                max_id=int(obj.get('max_id', 0)),
                min_id=int(obj.get('min_id', 0)),
                hash=int(obj.get('hash', 0)),
            )
        if act in {'messages.getMessages', 'get_messages'}:
            ids = obj.get('ids') or obj.get('id') or []
            if isinstance(ids, int):
                ids = [ids]
            return self.codec.messages_get_messages(ids=ids)
        if act in {'messages.readHistory', 'read_history', 'mark_read'}:
            return self.codec.messages_read_history(
                peer=self._resolve_peer(obj),
                max_id=int(obj.get('max_id', 0)),
            )
        if act in {'messages.search', 'search_messages'}:
            return self.codec.messages_search(
                peer=self._resolve_peer(obj),
                q=str(obj.get('q', '')),
                limit=int(obj.get('limit', 100)),
                offset_id=int(obj.get('offset_id', 0)),
            )
        if act in {'messages.forwardMessages', 'forward_messages'}:
            return self.codec.messages_forward_messages(
                from_peer=self._resolve_peer({**obj, 'chat_id': obj.get('from_chat_id') or obj.get('from_peer')}),
                to_peer=self._resolve_peer(obj),
                ids=list(obj.get('ids') or obj.get('id') or []),
                random_ids=[secrets.randbits(63) for _ in range(len(obj.get('ids') or obj.get('id') or []))],
                silent=bool(obj.get('silent', False)),
                drop_author=bool(obj.get('drop_author', False)),
            )
        if act in {'messages.sendMessage', 'send_msg'}:
            peer = self._resolve_peer(obj)
            reply_to = None
            if obj.get('reply_to'):
                reply_to = self.codec.input_reply_to_message(int(obj['reply_to']))
            return self.codec.messages_send_message(
                peer=peer,
                message=str(obj.get('text') or obj.get('message') or ''),
                random_id=secrets.randbits(63),
                reply_to=reply_to,
                no_webpage=bool(obj.get('no_webpage', False)),
            )
        if act in {'messages.editMessage', 'edit_msg'}:
            return self.codec.messages_edit_message(
                peer=self._resolve_peer(obj),
                msg_id=int(obj.get('msg_id') or obj.get('message_id', 0)),
                message=str(obj.get('text') or obj.get('message') or ''),
                no_webpage=bool(obj.get('no_webpage', False)),
            )
        if act in {'messages.deleteMessages', 'del_msg', 'delete_messages'}:
            ids = obj.get('ids') or obj.get('id')
            if isinstance(ids, int):
                ids = [ids]
            if obj.get('msg_id'):
                ids = [int(obj['msg_id'])]
            return self.codec.messages_delete_messages(ids=ids or [], revoke=bool(obj.get('revoke', True)))
        if act in {'channels.deleteMessages', 'channels_delete_messages'}:
            ids = obj.get('ids') or obj.get('id')
            if isinstance(ids, int):
                ids = [ids]
            return self.codec.channels_delete_messages(
                channel=self._resolve_channel(obj),
                ids=ids or [],
            )
        if act in {'messages.setTyping', 'send_typing'}:
            return self.codec.messages_set_typing(peer=self._resolve_peer(obj))
        if act in {'messages.getPinnedMessages', 'get_pinned_message', 'get_pinned_messages'}:
            return self.codec.messages_get_pinned_messages(peer=self._resolve_peer(obj))
        if act in {'messages.updatePinnedMessage', 'pin_message'}:
            return self.codec.messages_update_pinned_message(
                peer=self._resolve_peer(obj),
                msg_id=int(obj.get('msg_id') or obj.get('message_id', 0)),
                silent=bool(obj.get('silent', False)),
                unpin=bool(obj.get('unpin', False)),
            )
        if act in {'messages.unpinAllMessages', 'unpin_message', 'unpin_all'}:
            return self.codec.messages_update_pinned_message(
                peer=self._resolve_peer(obj),
                msg_id=int(obj.get('msg_id', 0)),
                unpin=True,
            )
        if act in {'messages.saveDraft', 'save_draft'}:
            return self.codec.messages_save_draft(
                peer=self._resolve_peer(obj),
                message=str(obj.get('message') or obj.get('text') or ''),
                reply_to_msg_id=obj.get('reply_to_msg_id'),
            )
        if act in {'messages.getAllDrafts', 'clear_draft', 'get_all_drafts'}:
            return self.codec.messages_get_all_drafts()
        if act in {'messages.getAllChats', 'get_all_chats'}:
            return self.codec.messages_get_all_chats(except_ids=obj.get('except_ids'))
        if act in {'users.getUsers', 'get_users'}:
            ids = obj.get('ids') or []
            if not ids:
                ids = [self.codec.input_user_self()]
            elif isinstance(ids[0], int):
                ids = [self.codec.input_user(uid, obj.get('access_hash', 0)) for uid in ids]
            return self.codec.users_get_users(ids=ids)
        if act in {'users.getFullUser', 'get_full_user', 'get_me'}:
            if act == 'get_me':
                user_id = self.codec.input_user_self()
            else:
                user_id = self._resolve_user(obj)
            return self.codec.users_get_full_user(user_id=user_id)
        if act in {'contacts.resolveUsername', 'resolve_peer', 'resolve_username'}:
            username = str(obj.get('username') or obj.get('peer') or '')
            if username.startswith('@'):
                username = username[1:]
            return self.codec.contacts_resolve_username(username=username)
        if act in {'channels.getFullChannel', 'get_full_channel'}:
            return self.codec.channels_get_full_channel(channel=self._resolve_channel(obj))
        if act in {'channels.getParticipants', 'get_participants'}:
            return self.codec.channels_get_participants(
                channel=self._resolve_channel(obj),
                offset=int(obj.get('offset', 0)),
                limit=int(obj.get('limit', 200)),
            )
        if act in {'channels.joinChannel', 'join_channel'}:
            return self.codec.channels_join_channel(channel=self._resolve_channel(obj))
        if act in {'channels.leaveChannel', 'leave_channel'}:
            return self.codec.channels_leave_channel(channel=self._resolve_channel(obj))
        if act in {'channels.inviteToChannel', 'invite_to_channel'}:
            users = obj.get('users') or []
            if isinstance(users[0], int) if users else False:
                users = [self.codec.input_user(uid, 0) for uid in users]
            return self.codec.channels_invite_to_channel(channel=self._resolve_channel(obj), users=users)
        if act in {'channels.editTitle', 'edit_title'}:
            return self.codec.channels_edit_title(channel=self._resolve_channel(obj), title=str(obj.get('title', '')))
        if act in {'channels.editAbout', 'edit_about'}:
            return self.codec.channels_edit_about(channel=self._resolve_channel(obj), about=str(obj.get('about', '')))
        if act in {'account.updateStatus', 'update_status'}:
            return self.codec.account_update_status(offline=bool(obj.get('offline', False)))
        if act in {'updates.getState', 'get_state'}:
            return self.codec.updates_get_state()
        if act in {'updates.getDifference', 'get_difference'}:
            return self.codec.updates_get_difference(
                pts=int(obj['pts']),
                date=int(obj['date']),
                qts=int(obj.get('qts', 0)),
            )
        raise NotImplementedError(f'MTProto method not implemented: {act}')

    async def send(self, obj:dict[str,Any], req_msg_id:int|None=None)->int:
        await self.ensure_auth_key()
        if rx is None: raise RuntimeError('rx (goygram.ext._ext) is not available; cannot encrypt')
        act = obj.get('act', '')
        api_id = obj.get('api_id') or self._api_id
        if api_id is not None:
            self._api_id = int(api_id)
        body = self._build_body(act, obj)
        if not self._init_done and self._api_id:
            body = self.codec.wrap_init(self._api_id, body)
            self._init_done = True
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
        log.debug(f"[TX] >>> {pkt.hex()}")
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

    async def _rpc_call(self, act:str, **kw:Any)->dict[str,Any]:
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

    async def _auth_check_password_flow(self, password:str, api_id:int)->dict[str,Any]:
        state = await self._rpc_call('account_get_password', api_id=api_id)
        if not isinstance(state, dict):
            return {"ok": False, "error": "UNEXPECTED_PASSWORD_STATE", "raw": state}
        if not state.get("ok", True):
            return state
        if not state.get("has_password"):
            return {"ok": False, "error": "PASSWORD_NOT_ENABLED", "error_message": "PASSWORD_NOT_ENABLED"}
        algo = state.get("current_algo")
        srp_b = state.get("srp_B")
        srp_id = state.get("srp_id")
        if not isinstance(algo, dict) or not isinstance(srp_b, (bytes, bytearray)) or srp_id is None:
            return {"ok": False, "error": "INVALID_PASSWORD_STATE", "error_message": "INVALID_PASSWORD_STATE"}
        try:
            srp_id, a_pub, m1 = _compute_password_check(state, password)
        except Exception as exc:
            import traceback; traceback.print_exc()
            return {"ok": False, "error": "PASSWORD_SRP_BUILD_FAILED", "error_message": str(exc)}
        return await self._rpc_call('auth_check_password_srp', srp_id=srp_id, A=a_pub, M1=m1, api_id=api_id)

    async def call(self, act:str, **kw:Any)->dict[str,Any]:
        if act in {'auth.checkPassword', 'auth_check_password'} and 'srp_id' not in kw:
            return await self._auth_check_password_flow(str(kw.get('password') or ''), int(kw['api_id']))
        return await self._rpc_call(act, **kw)

    async def spin(self)->None:
        await self.auth_ready.wait()
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
