# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
from __future__ import annotations
import asyncio, hashlib, json, os, secrets, struct, tempfile, urllib.parse, logging
from hashlib import sha1, sha256
from pathlib import Path
from typing import Any
from goygram.errors import ConnectionClosedError, FloodWaitError, GoyGramError, RPCError

import re as _re

def _html_to_entities(text:str)->tuple[str, list[tuple[int,int,int,str|None]]]:
    tags = {
        'b': 1, 'strong': 1,
        'i': 2, 'em': 2,
        'u': 3, 'ins': 3,
        's': 4, 'strike': 4, 'del': 4,
        'code': 5,
        'pre': 6,
    }
    entities: list[tuple[int,int,int,str|None]] = []
    stack: list[tuple[int,str,str|None]] = []
    result: list[str] = []
    pos = 0
    it = _re.finditer(r'</?([a-zA-Z][a-zA-Z0-9]*)(?:\s+[^>]*)?>', text)
    last_end = 0
    for m in it:
        tag = m.group(1).lower()
        is_close = m.group(0).startswith('</')
        result.append(text[last_end:m.start()])
        written = len(''.join(result))
        if is_close:
            while stack:
                start, otag, url = stack.pop()
                if otag == tag:
                    length = written - start
                    if length > 0:
                        if otag in tags:
                            entities.append((start, length, tags[otag], None))
                        elif otag == 'a':
                            if url:
                                entities.append((start, length, 7, url))
                    break
        else:
            if tag in tags:
                stack.append((written, tag, None))
            elif tag == 'a':
                href = _re.search(r'href=["\']([^"\']*)["\']', m.group(0))
                url = href.group(1) if href else None
                stack.append((written, 'a', url))
        last_end = m.end()
        pos = written
    result.append(text[last_end:])
    cleaned = ''.join(result)

    written = len(cleaned)
    while stack:
        start, otag, url = stack.pop()
        length = written - start
        if length > 0:
            if otag in tags:
                entities.append((start, length, tags[otag], None))
            elif otag == 'a' and url:
                entities.append((start, length, 7, url))
    return cleaned, entities

log = logging.getLogger("goygram.mtproto")

from goygram.protocol.tl_core import IntermediateTransport, MTCodec, MTMessage, MsgIdGen, Reader, build_msg_container, factorize, i32, i64, kdf, kdf_msg, rsa_pad_encrypt, tl_bytes, tl_str, u32

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
    if cid in {0x31774388, 0xd3bc4b7a, 0x44747e9a}:
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

    if cid in {0x020b1422, 0xb1b8cc83, 0x8f97c628, 0x5c0d0a2a, 0xd8576e2a, 0x7fe4ab4, 0x2e13f2c3, 0xebe8e785, 0x31774388, 0xd3bc4b7a}:
        return _parse_user_obj_v4(b, cid)
    log.warning("Unsupported user constructor 0x%08x, raw_length=%s", cid, len(b))
    return None


def _parse_user_obj_v4(b:bytes, cid:int)->dict[str,Any]|None:
    def _try_parse(with_flags2:bool)->dict[str,Any]|None:
        try:
            p = 4
            if with_flags2:
                flags = int.from_bytes(b[p:p+4], "little", signed=True); p += 4
                _flags2 = int.from_bytes(b[p:p+4], "little", signed=True); p += 4
            else:
                flags = int.from_bytes(b[p:p+4], "little", signed=True); p += 4
            user_id = int.from_bytes(b[p:p+8], "little", signed=False); p += 8
            if user_id == 0 or user_id > 10**12:
                return None
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
            if flags & (1 << 3) or flags & (1 << 6):
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
            return None
    try:
        result = _try_parse(True)
        if result is None:
            result = _try_parse(False)
        if result is None:
            log.warning("User parse: both modes failed for cid=0x%08x, raw_length=%s", cid, len(b))
        return result
    except Exception:
        log.warning("User parse exception for cid=0x%08x, raw_length=%s", cid, len(b))
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
        proxy:str|None=None,
        app_name:str|None=None,
        app_version:str|None=None,
        device_model:str|None=None,
        system_version:str|None=None,
        system_lang_code:str="en",
        lang_pack:str="",
        lang_code:str="en",
        cursor_path: str | Path | None = None,
    )->None:
        self.host=host; self.port=port; self.bus=bus; self.key=key; self.iv=iv
        self.proxy_url = proxy
        self.app_name = app_name
        self.app_version = app_version
        self.device_model = device_model
        self.system_version = system_version
        self.system_lang_code = system_lang_code
        self.lang_pack = lang_pack
        self.lang_code = lang_code
        self.rd=None; self.wr=None; self.buf=bytearray(); self.stop_ev=asyncio.Event(); self.seq=0
        self.pending:dict[int,tuple[asyncio.Future[dict[str,Any]],dict[str,Any]]]={}
        self.transport=IntermediateTransport(); self.msg_ids=MsgIdGen(); self.wrote_tag=False
        self.auth_key:bytes|None=None; self.server_salt:bytes=b'\x00'*8; self.session_id=secrets.token_bytes(8)
        self._seen_server_msg_ids: set[int] = set()
        self.entities: dict[tuple[str, int], dict[str, Any]] = {}
        self.entity_usernames: dict[str, dict[str, Any]] = {}
        self.cursor_path = Path(cursor_path) if cursor_path is not None else None
        self.cursor: dict[str, int] = {}
        self._difference_lock = asyncio.Lock()
        if self.cursor_path is not None:
            try:
                loaded = json.loads(self.cursor_path.read_text())
                if isinstance(loaded, dict):
                    self.cursor = {key: int(value) for key, value in loaded.items() if key in {"pts", "qts", "date", "seq"}}
            except (OSError, TypeError, ValueError):
                self.cursor = {}
        self.auth_ready=asyncio.Event()
        self.qr_update_ev=asyncio.Event()
        self._init_done=False
        self._api_id:int|None=None
        try:
            from goygram.schema_manager import _cached_layer, CURRENT_LAYER_FLOOR
            self.layer = _cached_layer() or CURRENT_LAYER_FLOOR
        except Exception:
            from goygram.schema_manager import CURRENT_LAYER_FLOOR
            self.layer = CURRENT_LAYER_FLOOR
        self._preferred_dc: int | None = None
        self._reader_task: asyncio.Task[None] | None = None
        self._reader_lock = asyncio.Lock()
        self._auth_lock = asyncio.Lock()

    def update_layer(self, layer: int) -> None:
        self.layer = int(layer)
        self._init_done = False

    def get_cursor(self) -> dict[str, int]:
        return dict(self.cursor)

    def update_cursor(self, cursor: dict[str, Any]) -> None:
        changed = False
        for key in ("pts", "qts", "date", "seq"):
            value = cursor.get(key)
            if isinstance(value, int) and value > self.cursor.get(key, -1):
                self.cursor[key] = value
                changed = True
        if not changed or self.cursor_path is None:
            return
        self.cursor_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", dir=self.cursor_path.parent, delete=False) as handle:
            json.dump(self.cursor, handle, separators=(",", ":"))
            temp_path = Path(handle.name)
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, self.cursor_path)

    def pick(self,obj:dict[str,Any],*keys:str)->Any:
        for k in keys:
            if k in obj: return obj[k]
        return None

    def pack(self, raw:bytes)->bytes: return self.transport.pack(raw)

    def proxy_cfg(self)->ProxyCfg|None:
        if self.proxy_url:
            raw = self.proxy_url
        else:
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
            log.debug(f"[RX] Socket closed. Left in buffer: {len(self.buf)} bytes")
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
            log.debug(f"[RX] <<< {len(raw)} bytes")
            self.buf.extend(raw)

    async def invoke_unencrypted(self, body:bytes)->bytes:
        await self.boot(); assert self.wr
        pkt=self.pack(MTMessage.unencrypted(self.msg_ids.next(), body))
        log.debug(f"[TX] >>> {len(pkt)} bytes")
        self.wr.write(pkt); await self.wr.drain()
        resp=await self.read_packet(); return resp

    def _read_unencrypted_body(self, pkt:bytes)->bytes:
        r=Reader(pkt); _=r.i64(); _=r.i64(); ln=r.i32(); return r.take(ln)

    async def ensure_auth_key(self)->None:
        if self.auth_key is not None and self.auth_ready.is_set():
            self.auth_ready.set()
            return
        async with self._auth_lock:
            if self.auth_key is not None and self.auth_ready.is_set():
                return
            await self._ensure_auth_key_inner()
            self.auth_ready.set()

    async def _ensure_auth_key_inner(self)->None:
        await self.boot()
        if self.auth_key is not None:
            return
        if rx is None: raise RuntimeError('rx (goygram.ext) is not available')
        nonce=secrets.token_bytes(16)
        codec = MTCodec()
        req_pq=codec.req_pq_multi(nonce)
        res=self._read_unencrypted_body(await self.invoke_unencrypted(req_pq))
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
        inner=codec.p_q_inner_data(
            pq=pq,
            p=p.to_bytes(4,'big'),
            q=q.to_bytes(4,'big'),
            nonce=nonce,
            server_nonce=server_nonce,
            new_nonce=new_nonce,
        )
        enc=rsa_pad_encrypt(inner,n_mod,e)
        dh_req=codec.req_dh_params(
            nonce=nonce,
            server_nonce=server_nonce,
            p=p.to_bytes(4,'big'),
            q=q.to_bytes(4,'big'),
            fp=fp,
            encrypted_data=enc,
        )
        dh=self._read_unencrypted_body(await self.invoke_unencrypted(dh_req))
        rd=Reader(dh); dcid=rd.u32()
        if dcid!=0xd0e8075c: raise RuntimeError(f'unexpected dh params cid={dcid:x}')
        _=rd.take(16); _=rd.take(16); encrypted_answer=rd.tl_bytes()
        tmp_key,tmp_iv=kdf(new_nonce,server_nonce)
        dec=bytes(rx.aes_ige_dec_raw(encrypted_answer,tmp_key,tmp_iv))
        answer=dec[20:]
        ra=Reader(answer); aid=ra.u32()
        log.debug(f'[DH] server_DH_inner_data cid={aid:#010x} (expected 0xb5890dba), dec_first32={dec[:32].hex()}')
        if aid!=0xb5890dba: raise RuntimeError(f'unexpected server_DH_inner_data cid={aid:#010x}')
        _=ra.take(16); _=ra.take(16); g=ra.i32(); dh_prime=int.from_bytes(ra.tl_bytes(),'big'); g_a=int.from_bytes(ra.tl_bytes(),'big'); _=ra.i32(); _=ra.i32()
        b=int.from_bytes(secrets.token_bytes(256),'big'); g_b=pow(g,b,dh_prime).to_bytes(256,'big')
        cli=codec.client_dh_inner(
            nonce=nonce,
            server_nonce=server_nonce,
            retry_id=0,
            g_b=g_b,
        )
        payload=sha1(cli).digest()+cli; payload+=b'\x00'*((16-len(payload)%16)%16)
        enc2=bytes(rx.aes_ige_enc_raw(payload,tmp_key,tmp_iv))
        ans_req=codec.set_client_dh_params(
            nonce=nonce,
            server_nonce=server_nonce,
            encrypted_data=enc2,
        )
        ans=self._read_unencrypted_body(await self.invoke_unencrypted(ans_req))
        c=Reader(ans).u32()
        if c!=0x3bcbf734: raise RuntimeError(f'dh_gen not ok: {c:x}')
        self.auth_key=pow(g_a,b,dh_prime).to_bytes(256,'big')
        self.server_salt=bytes(a^b for a,b in zip(new_nonce[:8],server_nonce[:8]))
        self._init_done=False

    def _dispatch_update(self, update: Any) -> None:
        if not isinstance(update, dict):
            return
        update_type = str(update.get("_", "unknown"))
        raw = update.get("raw")
        if isinstance(raw, str):
            try:
                raw = bytes.fromhex(raw)
            except ValueError:
                raw = None
        if update_type in {"updateChatParticipant", "updateChannelParticipant"}:
            chat_id = update.get("chat_id")
            if update_type == "updateChannelParticipant" and chat_id is None:
                channel_id = update.get("channel_id")
                chat_id = -1000000000000 - int(channel_id) if channel_id is not None else None
            member = {
                "kind": "member",
                "chat_id": chat_id,
                "from_id": update.get("actor_id"),
                "user_id": update.get("user_id"),
                "old_status": update.get("prev_participant"),
                "new_status": update.get("new_participant"),
                "invite": update.get("invite"),
                "date": update.get("date"),
                "qts": update.get("qts"),
                "via_chatlist": update.get("via_chatlist", False),
                "update_type": update_type,
                "raw_update": update,
            }
            asyncio.create_task(self.bus.push("mt", member))
            return
        if update_type in {"updateBotCallbackQuery", "updateInlineBotCallbackQuery"}:
            peer = update.get("peer") or {}
            peer_kind = peer.get("_") if isinstance(peer, dict) else None
            chat_id = peer.get("user_id") if peer_kind == "peerUser" else -(peer.get("chat_id") or 0) if peer_kind == "peerChat" else -1000000000000 - peer.get("channel_id", 0) if peer_kind == "peerChannel" else None
            cb = {
                "kind": "cb",
                "src": "mt",
                "update_type": update_type,
                "query_id": update.get("query_id"),
                "msg_id": update.get("msg_id"),
                "chat_id": chat_id,
                "from_id": update.get("user_id"),
                "data": bytes.fromhex(update["data"]).decode("utf-8", "replace") if isinstance(update.get("data"), str) else update.get("data"),
                "chat_instance": update.get("chat_instance"),
                "raw_update": update,
            }
            asyncio.create_task(self.bus.push("mt", cb))
            return
        if update_type == "updateBotInlineQuery":
            inline = {
                "kind": "inline",
                "src": "mt",
                "update_type": update_type,
                "query_id": update.get("query_id"),
                "from_id": update.get("user_id"),
                "query": update.get("query", ""),
                "offset": update.get("offset", ""),
                "raw_update": update,
            }
            asyncio.create_task(self.bus.push("mt", inline))
            return
        if update_type == "updateBotInlineSend":
            sent = {
                "kind": "update",
                "src": "mt",
                "update_type": update_type,
                "result_id": update.get("id"),
                "from_id": update.get("user_id"),
                "query": update.get("query", ""),
                "msg_id": update.get("msg_id"),
                "raw_update": update,
            }
            asyncio.create_task(self.bus.push("mt", sent))
            return
        if update_type in {"updateNewMessage", "updateNewChannelMessage", "updateEditMessage", "updateEditChannelMessage", "updateShortMessage", "updateShortChatMessage", "updateShortSentMessage"}:
            message = update.get("message")
            if update_type in {"updateShortMessage", "updateShortChatMessage", "updateShortSentMessage"}:
                parsed = self._parse_new_message(update)
            elif isinstance(raw, bytes):
                parsed = self._parse_new_message(raw)
            elif isinstance(message, dict):
                parsed = self._parse_new_message(bytes.fromhex(message["raw"])) if isinstance(message.get("raw"), str) else None
                if parsed is None:
                    peer = message.get("peer_id", {})
                    peer_kind = peer.get("_") if isinstance(peer, dict) else None
                    peer_id = peer.get("user_id") if peer_kind == "peerUser" else peer.get("chat_id") if peer_kind == "peerChat" else peer.get("channel_id") if peer_kind == "peerChannel" else None
                    if peer_id is not None:
                        from_peer = message.get("from_id")
                        if isinstance(from_peer, dict):
                            from_id = from_peer.get("user_id")
                        else:
                            from_id = from_peer if isinstance(from_peer, int) else None
                        is_out = bool(message.get("out")) or from_id == self.self_id or (peer_kind == "peerUser" and int(peer_id) == self.self_id)
                        parsed = {
                            "kind": "msg",
                            "msg_id": message.get("id"),
                            "chat_id": int(peer_id) if peer_kind == "peerUser" else -int(peer_id) if peer_kind == "peerChat" else -1000000000000 - int(peer_id),
                            "from_id": self.self_id if is_out else from_id,
                            "text": message.get("message", ""),
                            "is_me": is_out,
                            "media": message.get("media"),
                            "reply_to": message.get("reply_to"),
                        }
            else:
                parsed = None
            if parsed:
                parsed["kind"] = "edit" if update_type.startswith("updateEdit") else "msg"
                parsed["update_type"] = update_type
                parsed["raw_update"] = update
                asyncio.create_task(self.bus.push("mt", parsed))
                return
        asyncio.create_task(self.bus.push("mt", {"kind": "update", "update_type": update_type, "raw": update}))

    def _dispatch_updates(self, result: Any) -> None:
        if not isinstance(result, dict):
            return
        self.update_cursor(result)
        state = result.get("state")
        if isinstance(state, dict):
            self.update_cursor(state)
        self._ingest_entities(result)
        recovered = result.get("new_messages")
        if isinstance(recovered, list):
            for message in recovered:
                if not isinstance(message, dict):
                    continue
                parsed = self._parse_new_message(message)
                if parsed is None:
                    continue
                parsed["update_type"] = "updateNewMessage"
                parsed["raw_update"] = message
                asyncio.create_task(self.bus.push("mt", parsed))
        other = result.get("other_updates")
        if isinstance(other, list):
            for update in other:
                self._dispatch_update(update)
        if result.get("_") == "updatesTooLong":
            asyncio.create_task(self._recover_difference())
            return
        nested = result.get("result")
        if isinstance(nested, dict):
            self._dispatch_updates(nested)
            return
        updates = result.get("updates")
        if isinstance(updates, list):
            for update in updates:
                self._dispatch_update(update)
            return
        if result.get("_") == "updateShort" and isinstance(result.get("update"), dict):
            self._dispatch_update(result["update"])
            return
        if str(result.get("_", "")).startswith("update"):
            self._dispatch_update(result)

    async def _post_reconnect_recovery(self) -> None:
        try:
            await asyncio.sleep(0.5)
            if self._difference_lock.locked():
                return
            if "pts" in self.cursor:
                await self._recover_difference()
                return
            state = await self.call("updates.getState")
            if isinstance(state, dict):
                self.update_cursor(state)
        except Exception as exc:
            log.error("MTProto post-reconnect recovery failed: %s: %s", type(exc).__name__, exc)

    async def _recover_difference(self) -> None:
        if self._difference_lock.locked():
            return
        async with self._difference_lock:
            kwargs = {key: self.cursor[key] for key in ("pts", "qts", "date", "seq") if key in self.cursor}
            if "pts" not in kwargs:
                return
            try:
                result = await self.call("updates.getDifference", **kwargs)
                self._dispatch_updates(result)
            except Exception as exc:
                log.warning("MTProto update difference recovery failed: %s", exc)

    def _ingest_entities(self, result: dict[str, Any]) -> None:
        for key, kind in (("users", "user"), ("chats", "chat")):
            values = result.get(key)
            if not isinstance(values, list):
                continue
            for entity in values:
                if not isinstance(entity, dict) or not isinstance(entity.get("id"), int):
                    continue
                item = dict(entity)
                self.entities[(kind, int(item["id"]))] = item
                username = item.get("username")
                if isinstance(username, str) and username:
                    self.entity_usernames[username.casefold()] = item

    def _parse_phone_code_hash(self, result:bytes)->str|None:
        try:
            r = Reader(result)
            cid = r.u32()
            if cid == 0xf8827ebf:
                _ = r.tl_bytes()
                return r.tl_string()
            if cid == 0xd7cef980:
                _ = r.tl_bytes()
                return r.tl_string()
            if cid != 0x5e002502:
                return None
            flags = r.u32()
            st = r.u32()

            if st in {0x3dbb5986, 0xc000bba2, 0x5353e5a7}:
                _ = r.i32()
            elif st == 0xab03c6d9:
                _ = r.tl_string()
            elif st == 0x82006484:
                _ = r.tl_bytes()
                _ = r.i32()
            elif st == 0xf450f59b:
                type_flags = r.u32()
                if type_flags & (1 << 0) or type_flags & (1 << 1):
                    pass
                _ = r.tl_string()
                _ = r.i32()
                if type_flags & (1 << 3):
                    _ = r.i32()
                if type_flags & (1 << 4):
                    _ = r.i32()
            elif st == 0xa5491dea:
                _ = r.u32()
            elif st == 0xd9565c39:
                _ = r.tl_string()
                _ = r.i32()
            elif st == 0x9fd736:
                type_flags = r.u32()
                if type_flags & (1 << 0):
                    _ = r.tl_bytes()
                if type_flags & (1 << 2):
                    _ = r.i64()
                    _ = r.tl_bytes()
                if type_flags & (1 << 1):
                    _ = r.tl_string()
                    _ = r.i32()
                _ = r.i32()
            elif st in {0xa416ac81, 0xb37794af}:
                type_flags = r.u32()
                if type_flags & 1:
                    _ = r.tl_string()
            else:
                return None
            if flags & (1 << 1):
                _ = r.u32()
            if flags & (1 << 2):
                _ = r.i32()
            return r.tl_string()
        except (IndexError, struct.error, UnicodeError, ValueError):
            return None

    def _handle_encrypted_packet(self, pkt:bytes)->None:
        if not self.auth_key or rx is None:
            return
        if len(pkt) < 24:
            return
        expected_key_id = sha1(self.auth_key).digest()[-8:]
        if pkt[:8] != expected_key_id:
            log.warning("MTProto packet rejected: auth key id mismatch")
            return
        msg_key = pkt[8:24]
        enc = pkt[24:]
        if len(enc) % 16:
            log.warning("MTProto packet rejected: encrypted length is not aligned")
            return
        try:
            aes_key, aes_iv = kdf_msg(self.auth_key, msg_key, False)
            dec = bytes(rx.aes_ige_dec_raw(enc, aes_key, aes_iv))
            r = Reader(dec)
            salt = r.take(8); sid = r.take(8); msg_id = r.i64(); _seq = r.i32(); ln = r.i32()
            msg = r.take(ln)
        except Exception as exc:
            log.warning("MTProto packet rejected: %s", exc)
            return
        if sid != self.session_id:
            log.warning("MTProto packet rejected: session id mismatch")
            return
        if msg_id in self._seen_server_msg_ids:
            return
        self._seen_server_msg_ids.add(msg_id)
        if len(self._seen_server_msg_ids) > 4096:
            self._seen_server_msg_ids = set(list(self._seen_server_msg_ids)[-2048:])

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
                entry = self.pending.pop(req_msg_id, None)
                fut = entry[0] if isinstance(entry, tuple) else entry
                if not fut or fut.done():
                    return
                try:
                    parsed = self._parse_rpc_result(result)
                    dispatch_chat_id = entry[2] if isinstance(entry, tuple) and len(entry) > 2 else None
                    dispatch_message_text = entry[3] if isinstance(entry, tuple) and len(entry) > 3 else None
                    if dispatch_chat_id is not None or dispatch_message_text is not None:
                        self._annotate_short_sent(parsed, dispatch_chat_id, dispatch_message_text)
                    self._dispatch_updates(parsed)
                    fut.set_result(parsed)
                    for container_id, container in list(self.pending.items()):
                        if isinstance(container, dict) and container.get("type") == "container":
                            if all(sub_id not in self.pending for sub_id in container.get("msg_ids", [])):
                                self.pending.pop(container_id, None)
                except GoyGramError as exc:
                    fut.set_exception(exc)
                except Exception as exc:
                    fut.set_exception(exc)
                return
            try:
                import json
                decoded = json.loads(rx.deserialize_constructor(inner))
                if isinstance(decoded, dict):
                    decoded_type = str(decoded.get("_", ""))
                    if decoded_type in {"updates", "updatesCombined", "updateShort", "updatesTooLong"}:
                        self._dispatch_updates(decoded)
                        return
                    if decoded_type.startswith("update"):
                        self._dispatch_update(decoded)
                        return
            except Exception:
                pass
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
            if cid in {0x313bc7f8, 0x4d6deea5, 0x9015e101}:
                try:
                    import json
                    decoded = json.loads(rx.deserialize_constructor(inner))
                    if isinstance(decoded, dict):
                        self._dispatch_update(decoded)
                except Exception:
                    pass
                return
            if cid in {0x74ae4240, 0x725b04c3}:
                try:
                    import json
                    decoded = json.loads(rx.deserialize_constructor(inner))
                    if isinstance(decoded, dict) and (
                        isinstance(decoded.get("updates"), list)
                        or str(decoded.get("_", "")).startswith("update")
                    ):
                        self._dispatch_updates(decoded)
                        return
                except Exception:
                    pass
                return
            if cid in {0x1f2b0afd, 0x62ba04d9}:
                try:
                    import json
                    decoded = json.loads(rx.deserialize_constructor(inner))
                    if isinstance(decoded, dict):
                        self._dispatch_update(decoded)
                except Exception:
                    pass
                return
            if cid == 0x78d4dec1:
                try:
                    import json
                    decoded = json.loads(rx.deserialize_constructor(inner))
                    if isinstance(decoded, dict):
                        self._dispatch_updates(decoded)
                except Exception:
                    pass
                return
            if cid == 0x3072cfa1:
                try:
                    import gzip as _gz
                    packed = rm.tl_bytes()
                    decompressed = _gz.decompress(packed)
                    _consume(decompressed)
                except Exception:
                    pass
                return
            if cid in {0xf2ebdb4e, 0xe5bdf8de, 0xc32d5b12, 0xc01e857f}:
                try:
                    import json
                    decoded = json.loads(rx.deserialize_constructor(inner))
                    if isinstance(decoded, dict):
                        self._dispatch_update(decoded)
                except Exception:
                    pass
                return
            if cid == 0xedab447b:
                try:
                    bad_msg_id = rm.i64()
                    _bad_seq = rm.i32()
                    _error_code = rm.i32()
                    new_salt = int.from_bytes(rm.take(8), 'little', signed=False)
                    self.server_salt = new_salt.to_bytes(8, 'little')
                    self._init_done = False
                    log.info('Server salt updated to 0x%x, retrying msg %s', new_salt, bad_msg_id)
                    entry = self.pending.pop(bad_msg_id, None)
                    if entry is None:
                        return
                    if isinstance(entry, dict) and entry.get('type') == 'container':
                        new_sub_ids = []
                        saved_objs = []
                        for old_sub_id in entry['msg_ids']:
                            sub_entry = self.pending.pop(old_sub_id, None)
                            if sub_entry is None:
                                continue
                            if isinstance(sub_entry, tuple):
                                fut2, saved_obj2 = sub_entry[0], sub_entry[1]
                            else:
                                continue
                            if fut2.done():
                                continue
                            new_id = self.msg_ids.next()
                            self.pending[new_id] = (fut2, saved_obj2)
                            new_sub_ids.append(new_id)
                            saved_objs.append(saved_obj2)
                        if new_sub_ids:
                            new_container_id = self.msg_ids.next()
                            self.pending[new_container_id] = {'type': 'container', 'msg_ids': new_sub_ids}
                            asyncio.create_task(self._resend_container(new_container_id, saved_objs, new_sub_ids))
                    else:
                        if isinstance(entry, tuple):
                            fut, saved_obj = entry[0], entry[1]
                        else:
                            return
                        if not fut.done():
                            new_msg_id = self.msg_ids.next()
                            self.pending[new_msg_id] = (fut, saved_obj)
                            asyncio.create_task(self._resend(new_msg_id, saved_obj))
                except Exception as exc:
                    log.error('bad_server_salt handler error: %r', exc)
                return
            if cid == 0xa7eff811:
                try:
                    bad_msg_id = rm.i64()
                    _bad_seq = rm.i32()
                    _error_code = rm.i32()
                    log.warning('bad_msg_notification for msg_id=%s code=%s', bad_msg_id, _error_code)
                    fut = self.pending.pop(bad_msg_id, None)
                    if isinstance(fut, tuple):
                        fut = fut[0]
                    if fut is not None and not fut.done():
                        fut.set_exception(ConnectionError(f'bad_msg_notification code={_error_code}'))
                except Exception:
                    pass
                return
            if cid == 0x9ec20908:
                try:
                    _first_msg_id = rm.i64()
                    _unique_id = rm.i64()
                    new_salt = int.from_bytes(rm.take(8), 'little', signed=False)
                    self.server_salt = new_salt.to_bytes(8, 'little')
                    self._init_done = False
                    log.info('New session created, salt=0x%x', new_salt)
                except Exception:
                    pass
                return
            if cid in {0xd087663a, 0x985d3abb}:
                try:
                    import json
                    decoded = json.loads(rx.deserialize_constructor(inner))
                    if isinstance(decoded, dict):
                        self._dispatch_update(decoded)
                except Exception:
                    pass
                return
            if cid == 0x62d6b459:
                return
                try:
                    _flags = rm.i32()
                    _msg_id = rm.i32()
                    _pts = rm.i32()
                    _pts_count = rm.i32()
                    _date = rm.i32()
                    if _flags & (1 << 2):
                        _ = rm.tl_bytes()
                    if _flags & (1 << 9):
                        _cnt = rm.i32()
                        for _ in range(_cnt):
                            _ = rm.i32() if rm.i32() else None
                except Exception:
                    pass
                return
            try:
                import json
                decoded = json.loads(rx.deserialize_constructor(inner))
                if isinstance(decoded, dict) and str(decoded.get("_", "")).startswith("update"):
                    self._dispatch_update(decoded)
                    return
            except Exception:
                pass
            log.debug("Unhandled update cid=0x%08x", cid)
            return

        _consume(msg)

    def _parse_auth_result(self, result:bytes)->dict[str,Any]|None:
        if len(result) < 8:
            return None
        cid = int.from_bytes(result[:4], "little")
        if cid == 0x44747e9a:
            return {"ok": True, "auth_key": self.auth_key or b""}
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
                from goygram.errors import rpc_error
                raise rpc_error(ec, em)
            if cid == 0x3072cfa1:
                import gzip as _gz
                try:
                    packed = Reader(result)
                    packed.u32()
                    compressed = packed.tl_bytes()
                    result = _gz.decompress(compressed)
                except Exception:
                    pass
        try:
            deserializer = getattr(rx, "deserialize_constructor", None)
            if deserializer is None:
                raise RuntimeError("structured TL deserializer is unavailable")
            structured = json.loads(deserializer(result))
            payload = structured.get("result", structured) if isinstance(structured, dict) else None
            if isinstance(payload, dict) and payload.get("_") in {
                "auth.sentCode",
                "auth.sentCodeSuccess",
                "auth.sentCodePaymentRequired",
            }:
                phone_code_hash = payload.get("phone_code_hash")
                if phone_code_hash:
                    return {"ok": True, "phone_code_hash": str(phone_code_hash)}
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
        updates = self._parse_updates(result)
        if updates.get("id") or updates.get("updates"):
            return updates
        try:
            parsed = json.loads(rx.deserialize_constructor(result))
            if parsed.get("_") == "rpc_result":
                return {"ok": True, "result": parsed.get("result", parsed)}
            return {"ok": True, "result": parsed}
        except Exception as exc:
            log.warning("MTProto schema decode failed: %s", exc)
            return {"ok": False, "error": "SCHEMA_DECODE_FAILED", "error_message": str(exc), "raw_result_hex": result.hex()}

    def _parse_updates(self, result:bytes)->dict[str,Any]:
        return {"ok": False, "error": "SCHEMA_DECODE_FAILED", "error_message": "structured update decoding failed", "raw_result_hex": result.hex()}
    def _resolve_peer(self, obj:dict[str,Any])->bytes:
        chat_id = obj.get('chat_id') or obj.get('peer')
        access_hash = obj.get('access_hash', 0)
        if chat_id is None:
            return bytes(rx.serialize_constructor('inputPeerSelf', '{}'))
        if isinstance(chat_id, bytes):
            return chat_id
        if isinstance(chat_id, str):
            if chat_id in ('self', 'me'):
                return bytes(rx.serialize_constructor('inputPeerSelf', '{}'))
            if chat_id.lstrip('-').isdigit():
                chat_id = int(chat_id)
            else:
                entity = self.entity_usernames.get(chat_id.casefold())
                if entity is None:
                    raise ValueError('username peer requires explicit entity resolution')
                chat_id = int(entity["id"])
                access_hash = entity.get("access_hash", 0)
        if isinstance(chat_id, int):
            if chat_id == 0:
                return bytes(rx.serialize_constructor('inputPeerSelf', '{}'))
            if chat_id > 0:
                if chat_id == getattr(self, 'self_id', None):
                    return bytes(rx.serialize_constructor('inputPeerSelf', '{}'))
                entity = self.entities.get(("user", chat_id))
                if entity is not None:
                    access_hash = access_hash or entity.get("access_hash", 0)
                if not access_hash:
                    raise ValueError('user peer requires a non-zero access_hash')
                return bytes(rx.serialize_constructor('inputPeerUser', json.dumps({'user_id': chat_id, 'access_hash': int(access_hash)})))
            raw = -chat_id
            if raw > 1000000000000:
                channel_id = raw - 1000000000000
                entity = self.entities.get(("chat", channel_id))
                if entity is not None:
                    access_hash = access_hash or entity.get("access_hash", 0)
                if not access_hash:
                    raise ValueError('channel peer requires a non-zero access_hash')
                return bytes(rx.serialize_constructor('inputPeerChannel', json.dumps({'channel_id': channel_id, 'access_hash': int(access_hash)})))
            return bytes(rx.serialize_constructor('inputPeerChat', json.dumps({'chat_id': raw})))
        return bytes(rx.serialize_constructor('inputPeerSelf', '{}'))

    async def resolve_peer(self, value: Any) -> bytes:
        if isinstance(value, (bytes, bytearray, memoryview)):
            return bytes(value)
        obj = value if isinstance(value, dict) else {"chat_id": value}
        chat_id = obj.get("chat_id") or obj.get("peer")
        if isinstance(chat_id, str) and not chat_id.lstrip("-").isdigit() and chat_id not in {"self", "me"}:
            username = chat_id.lstrip("@").casefold()
            entity = self.entity_usernames.get(username)
            if entity is None:
                result = await self.call("contacts.resolveUsername", username=username, api_id=self._api_id)
                self._ingest_entities(result.get("result", result) if isinstance(result, dict) else {})
                entity = self.entity_usernames.get(username)
            if entity is None:
                raise ValueError('username resolution returned no entity')
            obj = dict(obj)
            obj["chat_id"] = int(entity["id"])
            obj["access_hash"] = entity.get("access_hash", 0)
        if isinstance(chat_id, int) and chat_id > 0 and chat_id != getattr(self, "self_id", None):
            entity = self.entities.get(("user", chat_id))
            if entity is None:
                refreshed = await self.call(
                    "messages.getDialogs",
                    limit=100,
                    offset_date=0,
                    offset_id=0,
                    offset_peer={"_": "inputPeerEmpty"},
                    hash=0,
                )
                self._ingest_entities(refreshed.get("result", refreshed) if isinstance(refreshed, dict) else {})
                entity = self.entities.get(("user", chat_id))
            if entity is not None:
                obj = dict(obj)
                obj["access_hash"] = obj.get("access_hash") or entity.get("access_hash", 0)
        return self._resolve_peer(obj)

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
            return bytes(rx.serialize_constructor('inputChannel', json.dumps({'channel_id': channel_id, 'access_hash': int(access_hash)})))
        raise ValueError('channel peer requires an integer channel_id and a non-zero access_hash')

    def _resolve_user(self, obj:dict[str,Any])->bytes:
        user_id = obj.get('user_id')
        access_hash = obj.get('access_hash', 0)
        if user_id is None or (isinstance(user_id, str) and user_id in ('self', 'me')):
            return bytes(rx.serialize_constructor('inputUserSelf', '{}'))
        if isinstance(user_id, bytes):
            return user_id
        return bytes(rx.serialize_constructor('inputUser', json.dumps({'user_id': int(user_id), 'access_hash': int(access_hash)})))

    def _wrap_init_query(self, api_id:int, query:bytes)->bytes:
        if rx is None: raise RuntimeError('rx (goygram.ext) is not available')
        inner = bytes(rx.serialize_method('initConnection', json.dumps({
            'flags': 0,
            'api_id': api_id,
            'device_model': self.device_model or 'Unknown',
            'system_version': self.system_version or 'Unknown',
            'app_version': self.app_version or '1.0',
            'system_lang_code': self.system_lang_code,
            'lang_pack': self.lang_pack,
            'lang_code': self.lang_code,
            'query': query.hex(),
        })))
        return bytes(rx.serialize_method('invokeWithLayer', json.dumps({
            'layer': self.layer,
            'query': inner.hex(),
        })))

    def _norm_act(self, name:str)->str:
        if '.' in name:
            return name
        parts = name.split('_')
        if len(parts) < 2:
            return name
        ns = parts[0]
        rest = parts[1:]
        return ns + '.' + rest[0] + ''.join(p[:1].upper() + p[1:] for p in rest[1:])

    def _build_body(self, act:str, obj:dict[str,Any])->bytes:
        import json
        from goygram import ext as _ext
        if _ext is None:
            raise RuntimeError('rx (goygram.ext._ext) is not available')
        def _resolve_val(v: Any) -> Any:
            if isinstance(v, (list, tuple)):
                return [_resolve_val(item) for item in v]
            if isinstance(v, dict) and '_' in v:
                ctor_name = v.get('_')
                inner = {k: _resolve_val(v2) for k, v2 in v.items() if k != '_'}
                return _ext.serialize_constructor(ctor_name, json.dumps(inner)).hex()
            if isinstance(v, dict) and len(v) == 1:
                ctor_name = list(v.keys())[0]
                inner = v[ctor_name]
                if isinstance(inner, dict):
                    inner = {k: _resolve_val(v2) for k, v2 in inner.items()}
                else:
                    inner = {}
                return _ext.serialize_constructor(ctor_name, json.dumps(inner)).hex()
            if isinstance(v, (bytes, bytearray)):
                return v.hex()
            if isinstance(v, memoryview):
                return bytes(v).hex()
            return v
        data = {}
        for k, v in obj.items():
            if k == 'act' or v is None:
                continue
            data[k] = _resolve_val(v)
        tl_name = self._norm_act(act)
        if tl_name == "auth.sendCode" and "settings" not in data:
            data["settings"] = _ext.serialize_constructor("codeSettings", json.dumps({"flags": 0})).hex()
        return bytes(_ext.serialize_method(tl_name, json.dumps(data)))

    def _parse_new_message(self, data:bytes|dict[str,Any])->dict[str,Any]|None:
        try:
            import json
            decoded = data if isinstance(data, dict) else json.loads(rx.deserialize_constructor(data))
            kind = decoded.get("_")
            if kind in {"updateNewMessage", "updateNewChannelMessage", "updateEditMessage", "updateEditChannelMessage"}:
                decoded = decoded.get("message", {})
                kind = decoded.get("_")
            is_out = bool(decoded.get("out"))
            self_id = getattr(self, "self_id", 0) or 0
            if kind == "updateShortSentMessage":
                return {
                    "kind": "msg", "msg_id": decoded["id"], "chat_id": decoded.get("chat_id", self_id),
                    "from_id": self_id, "text": decoded.get("message", ""),
                    "is_me": True, "media": decoded.get("media"), "reply_to": decoded.get("reply_to"),
                }
            if kind == "updateShortMessage":
                peer_id = decoded.get("user_id")
                is_out = is_out or bool(int(decoded.get("flags") or 0) & 2)
                return {
                    "kind": "msg", "msg_id": decoded["id"], "chat_id": peer_id,
                    "from_id": self_id if is_out else peer_id, "text": decoded.get("message", ""),
                    "is_me": is_out or peer_id == self_id,
                }
            if kind == "updateShortChatMessage":
                chat_id = decoded.get("chat_id")
                return {
                    "kind": "msg", "msg_id": decoded["id"], "chat_id": -int(chat_id),
                    "from_id": self_id if is_out else decoded.get("from_id"), "text": decoded.get("message", ""),
                    "is_me": is_out or decoded.get("from_id") == self_id,
                }
            if kind == "message":
                peer = decoded.get("peer_id", {})
                peer_kind = peer.get("_")
                peer_id = peer.get("user_id") if peer_kind == "peerUser" else peer.get("chat_id") if peer_kind == "peerChat" else peer.get("channel_id")
                if peer_id is None:
                    return None
                chat_id = int(peer_id) if peer_kind == "peerUser" else -int(peer_id) if peer_kind == "peerChat" else -1000000000000 - int(peer_id)
                from_peer = decoded.get("from_id")
                if isinstance(from_peer, dict):
                    from_id = from_peer.get("user_id")
                else:
                    from_id = from_peer if isinstance(from_peer, int) else None
                is_out = is_out or from_id == self_id or (peer_kind == "peerUser" and int(peer_id) == self_id)
                return {
                    "kind": "msg", "msg_id": decoded["id"], "chat_id": chat_id,
                    "from_id": self_id if is_out else from_id, "text": decoded.get("message", ""),
                    "is_me": is_out, "media": decoded.get("media"), "reply_to": decoded.get("reply_to"),
                }
        except Exception:
            pass
        return None

    def _annotate_short_sent(self, value: Any, chat_id: int | str | None, message_text: str | None) -> None:
        if isinstance(value, list):
            for item in value:
                self._annotate_short_sent(item, chat_id, message_text)
            return
        if not isinstance(value, dict):
            return
        if value.get("_") == "updateShortSentMessage":
            if chat_id is not None:
                value["chat_id"] = chat_id
            if message_text is not None:
                value["message"] = message_text
        for item in value.values():
            self._annotate_short_sent(item, chat_id, message_text)

    async def upload_file(self, source: Any, *, file_name: str | None = None, part_size: int = 524288) -> dict[str, Any]:
        if part_size < 1024 or part_size > 524288 or part_size % 1024:
            raise ValueError("part_size must be a multiple of 1024 between 1024 and 524288")
        close_source = False
        if isinstance(source, (str, os.PathLike)):
            path = Path(source)
            handle = path.open("rb")
            close_source = True
            file_name = file_name or path.name
        else:
            handle = source
            file_name = file_name or "file"
        file_id = secrets.randbits(63)
        parts = 0
        try:
            while True:
                chunk = handle.read(part_size)
                if not chunk:
                    break
                result = await self.call("upload.saveFilePart", file_id=file_id, file_part=parts, bytes=chunk)
                if result is False or (isinstance(result, dict) and result.get("ok") is False):
                    raise RuntimeError("upload.saveFilePart failed")
                parts += 1
        finally:
            if close_source:
                handle.close()
        return {"id": file_id, "parts": parts, "name": file_name}

    async def download_file(self, location: Any, destination: Any, *, offset: int = 0, limit: int = 524288) -> int:
        if limit < 1024 or limit > 524288 or limit % 1024:
            raise ValueError("limit must be a multiple of 1024 between 1024 and 524288")
        close_target = False
        temp_path: Path | None = None
        if isinstance(destination, (str, os.PathLike)):
            target = Path(destination)
            target.parent.mkdir(parents=True, exist_ok=True)
            handle = tempfile.NamedTemporaryFile(dir=target.parent, delete=False)
            temp_path = Path(handle.name)
            close_target = True
        else:
            target = None
            handle = destination
        total = 0
        migration_attempted = False
        try:
            while True:
                try:
                    response = await self.call("upload.getFile", location=location, offset=offset + total, limit=limit)
                except GoyGramError as exc:
                    match = _re.search(r"FILE_MIGRATE_(\d+)", str(exc).upper())
                    if match is None or migration_attempted:
                        raise
                    from goygram.dc_fetcher import get_dynamic_dc_config, pick_dc_endpoint
                    endpoint = pick_dc_endpoint(get_dynamic_dc_config(), preferred_dc=int(match.group(1)))
                    await self.close()
                    self.stop_ev.clear()
                    self.host, self.port = endpoint.host, endpoint.port
                    self._preferred_dc = endpoint.dc_id
                    self.auth_key = None
                    self.seq = 0
                    self._init_done = False
                    await self.boot()
                    await self.ensure_auth_key()
                    migration_attempted = True
                    continue
                body = response.get("result") if isinstance(response, dict) and isinstance(response.get("result"), dict) else response
                payload = body.get("bytes") if isinstance(body, dict) else None
                if isinstance(payload, str):
                    try:
                        payload = bytes.fromhex(payload)
                    except ValueError:
                        payload = None
                if not isinstance(payload, (bytes, bytearray)):
                    raise RuntimeError("upload.getFile returned no bytes")
                chunk = bytes(payload)
                if not chunk:
                    break
                handle.write(chunk)
                total += len(chunk)
                if len(chunk) < limit:
                    break
        except Exception:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
            raise
        finally:
            if close_target:
                handle.close()
        if temp_path is not None and target is not None:
            os.chmod(temp_path, 0o600)
            os.replace(temp_path, target)
        return total

    async def send_container(self, calls:list[tuple[str,dict[str,Any]]])->int:
        await self.ensure_auth_key()
        if rx is None:
            raise RuntimeError('rx (goygram.ext._ext) is not available; cannot encrypt')
        loop = asyncio.get_running_loop()
        sub_ids:list[int] = []
        saved_objs:list[dict[str,Any]] = []
        bodies:list[bytes] = []
        for act, kw in calls:
            obj:dict[str,Any] = {'act': act}
            obj.update({k: v for k, v in kw.items() if v is not None})
            sub_id = self.msg_ids.next()
            fut:asyncio.Future[dict[str,Any]] = loop.create_future()
            self.pending[sub_id] = (fut, obj)
            sub_ids.append(sub_id)
            saved_objs.append(obj)
        for obj in saved_objs:
            body = self._build_body(obj.get('act', ''), obj)
            bodies.append(body)
        seq_list:list[int] = []
        for _ in bodies:
            self.seq += 1
            seq_list.append(self.seq * 2 - 1)
        container_body = build_msg_container([(sid, seq, bd) for (sid, seq), bd in zip(sub_ids, seq_list, bodies)])
        api_id = None
        for _, kw in calls:
            if kw.get('api_id'):
                api_id = int(kw['api_id'])
                break
        if api_id is None:
            api_id = self._api_id
        if api_id is not None:
            self._api_id = int(api_id)
        if not self._init_done and self._api_id:
            container_body = self._wrap_init_query(self._api_id, container_body)
            self._init_done = True
        self.seq += 1
        outer_seq_no = self.seq * 2 - 1
        container_msg_id = self.msg_ids.next()
        m = b''
        m += self.server_salt + self.session_id + container_msg_id.to_bytes(8, 'little', signed=True) + outer_seq_no.to_bytes(4, 'little', signed=True)
        m += len(container_body).to_bytes(4, 'little', signed=True) + container_body
        pad = secrets.token_bytes((16 - (len(m) + 12) % 16) % 16 + 12)
        msg_key_large = sha256(self.auth_key[88:120] + m + pad).digest()
        msg_key = msg_key_large[8:24]
        aes_key, aes_iv = kdf_msg(self.auth_key, msg_key, True)
        enc = bytes(rx.aes_ige_enc_raw(m + pad, aes_key, aes_iv))
        pkt = self.pack(int.from_bytes(sha1(self.auth_key).digest()[-8:], 'little').to_bytes(8, 'little') + msg_key + enc)
        log.debug('[TX] container packet sent, message_count=%s', len(sub_ids))
        self.wr.write(pkt)
        await self.wr.drain()
        self.pending[container_msg_id] = {'type': 'container', 'msg_ids': sub_ids}
        return container_msg_id

    async def _resend_container(self, container_msg_id:int, saved_objs:list[dict[str,Any]], sub_msg_ids:list[int])->None:
        try:
            await self.ensure_auth_key()
            if rx is None:
                raise RuntimeError('rx (goygram.ext._ext) is not available; cannot encrypt')
            bodies:list[bytes] = []
            for obj in saved_objs:
                body = self._build_body(obj.get('act', ''), obj)
                bodies.append(body)
            seq_list:list[int] = []
            for _ in bodies:
                self.seq += 1
                seq_list.append(self.seq * 2 - 1)
            container_body = build_msg_container([(sid, seq, bd) for (sid, seq), bd in zip(sub_msg_ids, seq_list, bodies)])
            if not self._init_done and self._api_id:
                container_body = self._wrap_init_query(self._api_id, container_body)
                self._init_done = True
            self.seq += 1
            outer_seq_no = self.seq * 2 - 1
            m = b''
            m += self.server_salt + self.session_id + container_msg_id.to_bytes(8, 'little', signed=True) + outer_seq_no.to_bytes(4, 'little', signed=True)
            m += len(container_body).to_bytes(4, 'little', signed=True) + container_body
            pad = secrets.token_bytes((16 - (len(m) + 12) % 16) % 16 + 12)
            msg_key_large = sha256(self.auth_key[88:120] + m + pad).digest()
            msg_key = msg_key_large[8:24]
            aes_key, aes_iv = kdf_msg(self.auth_key, msg_key, True)
            enc = bytes(rx.aes_ige_enc_raw(m + pad, aes_key, aes_iv))
            pkt = self.pack(int.from_bytes(sha1(self.auth_key).digest()[-8:], 'little').to_bytes(8, 'little') + msg_key + enc)
            log.debug('[TX] resend container msg_ids=%s', sub_msg_ids)
            self.wr.write(pkt)
            await self.wr.drain()
        except Exception as e:
            log.error('Resend container failed for container_msg_id=%s: %r', container_msg_id, e)
            self.pending.pop(container_msg_id, None)
            for sub_id in sub_msg_ids:
                entry = self.pending.pop(sub_id, None)
                if entry is None:
                    continue
                fut = entry[0] if isinstance(entry, tuple) else entry
                if fut and not fut.done():
                    fut.set_exception(e)

    async def _resend(self, msg_id:int, obj:dict[str,Any])->None:
        try:
            await self.send(obj, req_msg_id=msg_id)
        except Exception as e:
            log.error('Resend failed for msg_id=%s: %r', msg_id, e)
            fut = self.pending.pop(msg_id, None)
            if isinstance(fut, tuple):
                fut = fut[0]
            if fut and not fut.done():
                fut.set_exception(e)

    async def send(self, obj:dict[str,Any], req_msg_id:int|None=None)->int:
        await self.ensure_auth_key()
        if rx is None: raise RuntimeError('rx (goygram.ext._ext) is not available; cannot encrypt')
        act = obj.get('act', '')
        api_id = obj.get('api_id') or self._api_id
        if api_id is not None:
            self._api_id = int(api_id)
        body = self._build_body(act, obj)
        if not self._init_done and self._api_id:
            body = self._wrap_init_query(self._api_id, body)
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
        log.debug(f"[TX] >>> {len(pkt)} bytes")
        self.wr.write(pkt); await self.wr.drain()
        return msg_id

    async def close(self)->None:
        self.stop_ev.set()
        task = self._reader_task
        if getattr(self, "_keepalive_task", None) is not None:
            self._keepalive_task.cancel()
            await asyncio.gather(self._keepalive_task, return_exceptions=True)
            self._keepalive_task = None
        if task is not None and task is not asyncio.current_task() and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        self._reader_task = None
        if self.wr:
            self.wr.close(); await self.wr.wait_closed()
            self.wr=None; self.rd=None
        for entry in self.pending.values():
            if isinstance(entry, tuple):
                future = entry[0]
                if not future.done():
                    future.cancel()
        self.pending.clear()

    async def _ensure_reader(self) -> None:
        async with self._reader_lock:
            if self._reader_task is None or self._reader_task.done():
                self.stop_ev.clear()
                self._reader_task = asyncio.create_task(self.spin(), name="goygram-mt-reader")

    async def start(self) -> None:
        if self.auth_key is None:
            await self.ensure_auth_key()
        await self._ensure_reader()

    async def _rpc_call(self, act:str, **kw:Any)->dict[str,Any]:
        if self.auth_key is None:
            await self.ensure_auth_key()
        await self._ensure_reader()
        loop = asyncio.get_running_loop()
        fut:asyncio.Future[dict[str,Any]] = loop.create_future()
        req_msg_id = self.msg_ids.next()
        dispatch_chat_id = kw.pop("_dispatch_chat_id", None)
        dispatch_message_text = kw.pop("_dispatch_message_text", None)
        obj={'act':act}; obj.update({k:v for k,v in kw.items() if v is not None})
        self.pending[req_msg_id] = (fut, obj, dispatch_chat_id, dispatch_message_text)
        try:
            await self.send(obj, req_msg_id=req_msg_id)
            return await asyncio.wait_for(fut, timeout=30.0)
        except asyncio.TimeoutError:
            for pending_id, pending_entry in list(self.pending.items()):
                if isinstance(pending_entry, tuple) and pending_entry[0] is fut:
                    self.pending.pop(pending_id, None)
            raise TimeoutError(f"no response for act={act} msg_id={req_msg_id}")

    async def _auth_check_password_flow(self, password:str, api_id:int)->dict[str,Any]:
        state = await self._rpc_call('account.getPassword')
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
        from goygram.protocol.tl_core import u32, i64, tl_bytes
        srp = u32(0xd27ff082) + i64(srp_id) + tl_bytes(a_pub) + tl_bytes(m1)
        return await self._rpc_call('auth.checkPassword', password=srp)

    async def call(self, act:str, **kw:Any)->dict[str,Any]:
        normalized = self._norm_act(act)
        retry_budget = int(kw.pop("retry", 3))
        dispatch_chat_id = kw.pop("_dispatch_chat_id", None)
        dispatch_message_text = kw.pop("_dispatch_message_text", None)
        if normalized.startswith("messages.") and "peer" in kw and not isinstance(kw["peer"], (bytes, bytearray, memoryview, dict)):
            kw = dict(kw)
            kw["peer"] = await self.resolve_peer(kw["peer"])
        if normalized == 'auth.checkPassword' and 'srp_id' not in kw and 'password' in kw and isinstance(kw['password'], str):
            return await self._auth_check_password_flow(kw['password'], int(kw.get('api_id', 0)))
        attempt = 0
        while True:
            try:
                if dispatch_chat_id is not None:
                    kw["_dispatch_chat_id"] = dispatch_chat_id
                if dispatch_message_text is not None:
                    kw["_dispatch_message_text"] = dispatch_message_text
                return await self._rpc_call(act, **kw)
            except FloodWaitError as exc:
                if attempt >= retry_budget:
                    raise
                attempt += 1
                await asyncio.sleep(max(1, min(int(exc.seconds), 300)))

    async def _connect(self) -> None:
        from goygram.dc_fetcher import get_dynamic_dc_config, pick_dc_endpoint
        if self._preferred_dc is not None:
            try:
                dc_map = get_dynamic_dc_config()
                selected = pick_dc_endpoint(dc_map, preferred_dc=self._preferred_dc)
                self.host, self.port = selected.host, selected.port
            except Exception:
                pass
        self._init_done = False
        self.auth_ready.clear()
        await self.ensure_auth_key()

    async def _keepalive_loop(self) -> None:
        while not self.stop_ev.is_set():
            try:
                await asyncio.sleep(30.0)
                if self.stop_ev.is_set():
                    return
                await self._rpc_call("ping", ping_id=secrets.randbits(63))
            except asyncio.CancelledError:
                raise
            except Exception:
                pass

    async def spin(self) -> None:
        await self.auth_ready.wait()
        self._keepalive_task = asyncio.create_task(self._keepalive_loop(), name="goygram-mt-keepalive")
        backoff = 1.0
        max_backoff = 60.0
        while not self.stop_ev.is_set():
            try:
                pkt = await self.read_packet()
                self._handle_encrypted_packet(pkt)
                backoff = 1.0
            except ConnectionError:
                log.error("MTProto connection lost, reconnecting in %.1fs", backoff)
                for entry in self.pending.values():
                    if isinstance(entry, tuple):
                        fut = entry[0]
                        if not fut.done():
                            fut.set_exception(ConnectionClosedError("MTProto connection lost"))
                self.pending.clear()
                try:
                    if self.wr:
                        self.wr.close()
                except Exception:
                    pass
                self.wr = None
                self.rd = None
                await asyncio.sleep(backoff)
                if self.stop_ev.is_set():
                    break
                try:
                    await self._connect()
                    backoff = 1.0
                    asyncio.create_task(self._post_reconnect_recovery())
                except Exception as e:
                    log.error("MTProto reconnect failed: %r", e)
                    backoff = min(backoff * 2, max_backoff)
                    continue
            except Exception as exc:
                log.debug("MTProto packet handling failed: %s", type(exc).__name__)
                await asyncio.sleep(0.1)
