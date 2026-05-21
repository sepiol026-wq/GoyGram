# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
from __future__ import annotations
import os, platform, struct, secrets, sys, time
from dataclasses import dataclass
from hashlib import sha1, sha256
from importlib.metadata import PackageNotFoundError, version as pkg_version

VECTOR_ID = 0x1CB5C415


def i32(v:int)->bytes: return struct.pack('<i', v)
def u32(v:int)->bytes: return struct.pack('<I', v)
def i64(v:int)->bytes: return struct.pack('<q', v)

def tl_bytes(b:bytes)->bytes:
    n=len(b)
    if n<254:
        x=bytes([n])+b
    else:
        x=b'\xfe'+n.to_bytes(3,'little')+b
    return x + (b'\x00' * ((4-len(x)%4)%4))

def tl_str(s:str)->bytes: return tl_bytes(s.encode())

class Reader:
    def __init__(self,b:bytes): self.b=b; self.p=0
    def take(self,n:int)->bytes: x=self.b[self.p:self.p+n]; self.p+=n; return x
    def u32(self)->int: return struct.unpack('<I',self.take(4))[0]
    def i32(self)->int: return struct.unpack('<i',self.take(4))[0]
    def i64(self)->int: return struct.unpack('<q',self.take(8))[0]
    def tl_bytes(self)->bytes:
        n0=self.take(1)[0]
        if n0==254: n=int.from_bytes(self.take(3),'little'); head=4
        else: n=n0; head=1
        d=self.take(n); pad=(4-((head+n)%4))%4; self.take(pad); return d

@dataclass
class IntermediateTransport:
    def pack(self,payload:bytes)->bytes:
        return len(payload).to_bytes(4, 'little') + payload

class MsgIdGen:
    def __init__(self)->None:
        self.last_time=0
        self.offset=0
    def next(self)->int:
        now=int(time.time())
        self.offset = self.offset + 4 if now == self.last_time else 0
        self.last_time = now
        return (now * (2**32)) + self.offset

class MTMessage:
    @staticmethod
    def unencrypted(msg_id:int, body:bytes)->bytes: return i64(0)+i64(msg_id)+i32(len(body))+body


def _default_app_name()->str:
    return "GoyGram"


def _default_app_version()->str:
    try:
        return "GoyGram " + pkg_version("goygram")
    except PackageNotFoundError:
        return "GoyGram 0.5.3"


def _default_device_model()->str:
    return f"{platform.system()} {platform.machine()}"


def _default_system_version()->str:
    sys_name = platform.system().strip() or "UnknownOS"
    sys_rel = platform.release().strip()
    return f"{sys_name} {sys_rel}".strip()

class MTCodec:
    REQ_PQ_MULTI=0xbe7e8ef1
    REQ_DH_PARAMS=0xd712e4be
    SET_CLIENT_DH_PARAMS=0xf5045f1f
    P_Q_INNER_DATA=0x83c95aec
    P_Q_INNER_DATA_DC=0xa9f55f95
    CLIENT_DH_INNER=0x6643b654
    AUTH_SEND_CODE=0xa677244f

    AUTH_SIGN_IN=0x8d52a951
    AUTH_CHECK_PASSWORD=0xd18b4d16
    ACCOUNT_GET_PASSWORD=0x548a30f5
    INPUT_CHECK_PASSWORD_SRP=0xd27ff082
    AUTH_EXPORT_LOGIN_TOKEN=0xb7e085fe
    AUTH_IMPORT_LOGIN_TOKEN=0x95ac5ce4
    INPUT_PEER_EMPTY=0x7f3b18ea
    INPUT_PEER_SELF=0x7da07ec9
    INPUT_PEER_CHAT=0x35a95cb9
    INPUT_PEER_USER=0xdde8a54c
    INPUT_PEER_CHANNEL=0x27bcbbfc
    INPUT_CHANNEL=0xf35aec28
    INPUT_REPLY_TO_MESSAGE=0x869fbe10
    UPDATES_GET_STATE=0xedd4882a
    UPDATES_GET_DIFFERENCE=0x19c2f763
    MESSAGES_GET_DIALOGS=0xa0f4cb4f
    MESSAGES_SEND_MESSAGE=0xfe05dc9a
    MESSAGES_EDIT_MESSAGE=0xdfd14005
    MESSAGES_DELETE_MESSAGES=0xe58e95d2
    CHANNELS_DELETE_MESSAGES=0x84c1fd4e
    MESSAGES_GET_HISTORY=0x4423e6c5
    MESSAGES_GET_MESSAGES=0x63c66506
    MESSAGES_READ_HISTORY=0x0e306d3a
    MESSAGES_SEARCH=0x29ee847a
    MESSAGES_FORWARD_MESSAGES=0xd5039208
    MESSAGES_SEND_MEDIA=0x7852834e
    MESSAGES_GET_ALL_CHATS=0x875f74be
    MESSAGES_SET_TYPING=0x58943ee2
    MESSAGES_GET_PINNED_MESSAGES=0x22ddd30c
    MESSAGES_UPDATE_PINNED_MESSAGE=0xd2aaf7ec
    MESSAGES_UNPIN_ALL_MESSAGES=0xee22b9a8
    MESSAGES_SAVE_DRAFT=0x7ac3ac06
    MESSAGES_GET_ALL_DRAFTS=0x6a3f8d65
    USERS_GET_USERS=0x0d91a548
    USERS_GET_FULL_USER=0xb60f5918
    CONTACTS_RESOLVE_USERNAME=0xf93ccba3
    CHANNELS_GET_FULL_CHANNEL=0x08736a09
    CHANNELS_GET_PARTICIPANTS=0x77ced9d0
    CHANNELS_JOIN_CHANNEL=0x24b524c5
    CHANNELS_LEAVE_CHANNEL=0xf836aa95
    CHANNELS_EDIT_ADMIN=0xd33c8902
    CHANNELS_EDIT_BANNED=0x96e6cd81
    CHANNELS_INVITE_TO_CHANNEL=0xc9e33d54
    CHANNELS_CREATE_CHANNEL=0x91006707
    CHANNELS_EDIT_TITLE=0x566decd0
    CHANNELS_EDIT_PHOTO=0xf12e57c9
    CHANNELS_EDIT_ABOUT=0x13e27f1e
    AUTH_LOG_OUT=0x3e72ba19
    ACCOUNT_UPDATE_STATUS=0x6628562c
    MESSAGES_GET_DIALOGS_FILTERS=0xefd48c89
    INPUT_USER=0xf21158c6
    INPUT_USER_SELF=0x6727bce0
    MESSAGES_MARK_DIALOG_UNREAD=0xc286d98f
    MESSAGES_GET_UNREAD_MENTIONS=0xf107e790



    def auth_check_password(self, *, srp_id:int, A:bytes, M1:bytes, api_id:int)->bytes:
        return u32(self.AUTH_CHECK_PASSWORD)+u32(self.INPUT_CHECK_PASSWORD_SRP)+i64(srp_id)+tl_bytes(A)+tl_bytes(M1)
    def auth_sign_in(self, phone:str, phone_code_hash:str, code:str, api_id:int)->bytes:
        return u32(self.AUTH_SIGN_IN)+i32(1)+tl_str(phone)+tl_str(phone_code_hash)+tl_str(code)
    INIT_CONNECTION=0xc1cd5ea9
    INVOKE_WITH_LAYER=0xda9b0d0d
    CODE_SETTINGS=0xad253d78
    LAYER=214

    def __init__(
        self,
        *,
        app_name:str|None=None,
        app_version:str|None=None,
        device_model:str|None=None,
        system_version:str|None=None,
        system_lang_code:str="en",
        lang_pack:str="",
        lang_code:str="en",
    )->None:
        self.app_name = str(app_name or _default_app_name())
        self.app_version = str(app_version or _default_app_version())
        self.device_model = str(device_model or _default_device_model())
        self.system_version = str(system_version or _default_system_version())
        self.system_lang_code = str(system_lang_code or "en")
        self.lang_pack = str(lang_pack or "")
        self.lang_code = str(lang_code or "en")

    def wrap_init(self, api_id:int, req:bytes)->bytes:
        init = (
            u32(self.INIT_CONNECTION)
            + i32(0)
            + i32(api_id)
            + tl_str(self.device_model)
            + tl_str(self.system_version)
            + tl_str(self.app_version)
            + tl_str(self.system_lang_code)
            + tl_str(self.lang_pack)
            + tl_str(self.lang_code)
            + req
        )
        return u32(self.INVOKE_WITH_LAYER)+i32(self.LAYER)+init

    def req_pq_multi(self, nonce:bytes)->bytes:
        return u32(self.REQ_PQ_MULTI)+nonce

    def req_dh_params(self, *, nonce:bytes, server_nonce:bytes, p:bytes, q:bytes, fp:int, encrypted_data:bytes)->bytes:
        return u32(self.REQ_DH_PARAMS)+nonce+server_nonce+tl_bytes(p)+tl_bytes(q)+i64(fp)+tl_bytes(encrypted_data)

    def set_client_dh_params(self, *, nonce:bytes, server_nonce:bytes, encrypted_data:bytes)->bytes:
        return u32(self.SET_CLIENT_DH_PARAMS)+nonce+server_nonce+tl_bytes(encrypted_data)

    def p_q_inner_data(self, *, pq:bytes, p:bytes, q:bytes, nonce:bytes, server_nonce:bytes, new_nonce:bytes)->bytes:
        return u32(self.P_Q_INNER_DATA)+tl_bytes(pq)+tl_bytes(p)+tl_bytes(q)+nonce+server_nonce+new_nonce
    def p_q_inner_data_dc(self, *, pq:bytes, p:bytes, q:bytes, nonce:bytes, server_nonce:bytes, new_nonce:bytes, dc:int)->bytes:
        return u32(self.P_Q_INNER_DATA_DC)+tl_bytes(pq)+tl_bytes(p)+tl_bytes(q)+nonce+server_nonce+new_nonce+i32(dc)

    def client_dh_inner(self, *, nonce:bytes, server_nonce:bytes, retry_id:int, g_b:bytes)->bytes:
        return u32(self.CLIENT_DH_INNER)+nonce+server_nonce+i64(retry_id)+tl_bytes(g_b)

    def auth_send_code(self, phone:str, api_id:int, api_hash:str)->bytes:
        return u32(self.AUTH_SEND_CODE)+tl_str(phone)+i32(api_id)+tl_str(api_hash)+u32(self.CODE_SETTINGS)+i32(0)
    def account_get_password(self, api_id:int)->bytes:
        return u32(self.ACCOUNT_GET_PASSWORD)
    def auth_export_login_token(self, api_id:int, api_hash:str, except_ids:list[int])->bytes:
        vec=u32(0x1CB5C415)+i32(len(except_ids))+b''.join(i64(x) for x in except_ids)
        return u32(self.AUTH_EXPORT_LOGIN_TOKEN)+i32(api_id)+tl_str(api_hash)+vec
    def auth_import_login_token(self, token:bytes, api_id:int)->bytes:
        return u32(self.AUTH_IMPORT_LOGIN_TOKEN)+tl_bytes(token)
    def auth_log_out(self)->bytes:
        return u32(self.AUTH_LOG_OUT)
    def input_peer_empty(self)->bytes:
        return u32(self.INPUT_PEER_EMPTY)
    def input_peer_self(self)->bytes:
        return u32(self.INPUT_PEER_SELF)
    def input_peer_chat(self, chat_id:int)->bytes:
        return u32(self.INPUT_PEER_CHAT)+i64(chat_id)
    def input_peer_user(self, user_id:int, access_hash:int)->bytes:
        return u32(self.INPUT_PEER_USER)+i64(user_id)+i64(access_hash)
    def input_peer_channel(self, channel_id:int, access_hash:int)->bytes:
        return u32(self.INPUT_PEER_CHANNEL)+i64(channel_id)+i64(access_hash)
    def input_channel(self, channel_id:int, access_hash:int)->bytes:
        return u32(self.INPUT_CHANNEL)+i64(channel_id)+i64(access_hash)
    def input_reply_to_message(self, reply_to_msg_id:int, top_msg_id:int|None=None)->bytes:
        flags = 0
        raw = u32(self.INPUT_REPLY_TO_MESSAGE)
        if top_msg_id is not None:
            flags |= 1 << 0
        raw += i32(flags) + i32(reply_to_msg_id)
        if top_msg_id is not None:
            raw += i32(top_msg_id)
        return raw
    def messages_get_dialogs(
        self,
        *,
        limit:int,
        exclude_pinned:bool=False,
        folder_id:int|None=None,
        offset_date:int=0,
        offset_id:int=0,
        offset_peer:bytes|None=None,
        hash:int=0,
    )->bytes:
        flags = 0
        if exclude_pinned:
            flags |= 1 << 0
        if folder_id is not None:
            flags |= 1 << 1
        req=u32(self.MESSAGES_GET_DIALOGS)+i32(flags)
        if folder_id is not None:
            req += i32(folder_id)
        req += i32(offset_date)+i32(offset_id)+(offset_peer or self.input_peer_empty())+i32(limit)+i64(hash)
        return req
    def messages_get_history(
        self,
        *,
        peer:bytes,
        offset_id:int=0,
        offset_date:int=0,
        add_offset:int=0,
        limit:int=100,
        max_id:int=0,
        min_id:int=0,
        hash:int=0,
    )->bytes:
        return u32(self.MESSAGES_GET_HISTORY)+peer+i32(offset_id)+i32(offset_date)+i32(add_offset)+i32(limit)+i32(max_id)+i32(min_id)+i64(hash)
    def messages_get_messages(self, *, ids:list[int])->bytes:
        vec=u32(VECTOR_ID)+i32(len(ids))+b''.join(u32(0xbcd12c22)+i32(x) for x in ids)
        return u32(self.MESSAGES_GET_MESSAGES)+vec
    def messages_read_history(self, *, peer:bytes, max_id:int=0)->bytes:
        return u32(self.MESSAGES_READ_HISTORY)+peer+i32(max_id)
    def messages_search(
        self,
        *,
        peer:bytes,
        q:str="",
        filter_cid:int=0x57e2f66c,
        min_date:int=0,
        max_date:int=0,
        offset_id:int=0,
        add_offset:int=0,
        limit:int=100,
        max_id:int=0,
        min_id:int=0,
        hash:int=0,
    )->bytes:
        flags = 0
        req = u32(self.MESSAGES_SEARCH)+i32(flags)+peer+tl_str(q)+u32(filter_cid)+i32(min_date)+i32(max_date)+i32(offset_id)+i32(add_offset)+i32(limit)+i32(max_id)+i32(min_id)+i64(hash)
        return req
    def messages_forward_messages(
        self,
        *,
        from_peer:bytes,
        to_peer:bytes,
        ids:list[int],
        random_ids:list[int],
        silent:bool=False,
        drop_author:bool=False,
    )->bytes:
        flags = 0
        if silent:
            flags |= 1 << 5
        if drop_author:
            flags |= 1 << 11
        id_vec=u32(VECTOR_ID)+i32(len(ids))+b''.join(i32(x) for x in ids)
        rnd_vec=u32(VECTOR_ID)+i32(len(random_ids))+b''.join(i64(x) for x in random_ids)
        return u32(self.MESSAGES_FORWARD_MESSAGES)+i32(flags)+from_peer+id_vec+rnd_vec+to_peer
    def messages_send_message(
        self,
        *,
        peer:bytes,
        message:str,
        random_id:int,
        reply_to:bytes|None=None,
        no_webpage:bool=False,
        entities:list[tuple[int,int,int,str|None]]|None=None,
    )->bytes:
        flags = 0
        if reply_to is not None:
            flags |= 1 << 0
        if no_webpage:
            flags |= 1 << 1
        if entities:
            flags |= 1 << 3
        req=u32(self.MESSAGES_SEND_MESSAGE)+i32(flags)+peer
        if reply_to is not None:
            req += reply_to
        req += tl_str(message)+i64(random_id)
        if entities:
            req += self._encode_entities(entities)
        return req

    def _encode_entities(self, entities:list[tuple[int,int,int,str|None]])->bytes:
        raw = u32(0x1cb5c415) + i32(len(entities))
        for offset, length, tp, url in entities:
            if tp == 7 and url:
                raw += u32(0x76a6d327) + i32(offset) + i32(length) + tl_str(url)
            elif tp == 8 and url:
                raw += u32(0x352955c9) + i32(offset) + i32(length) + i64(int(url))
            elif tp == 1:
                raw += u32(0xbd610bc9) + i32(offset) + i32(length)
            elif tp == 2:
                raw += u32(0x826f8b60) + i32(offset) + i32(length)
            elif tp == 3:
                raw += u32(0xe04bb623) + i32(offset) + i32(length)
            elif tp == 4:
                raw += u32(0xbfa8f802) + i32(offset) + i32(length)
            elif tp == 5:
                raw += u32(0x28a20571) + i32(offset) + i32(length)
            elif tp == 6:
                raw += u32(0x73924be0) + i32(offset) + i32(length) + tl_str('')
        return raw
    def messages_edit_message(
        self,
        *,
        peer:bytes,
        msg_id:int,
        message:str,
        no_webpage:bool=False,
    )->bytes:
        flags = 1 << 11
        if no_webpage:
            flags |= 1 << 1
        req=u32(self.MESSAGES_EDIT_MESSAGE)+i32(flags)+peer+i32(msg_id)+tl_str(message)
        return req
    def messages_delete_messages(self, *, ids:list[int], revoke:bool=True)->bytes:
        flags = 1 if revoke else 0
        return u32(self.MESSAGES_DELETE_MESSAGES)+i32(flags)+u32(VECTOR_ID)+i32(len(ids))+b''.join(i32(x) for x in ids)
    def channels_delete_messages(self, *, channel:bytes, ids:list[int])->bytes:
        return u32(self.CHANNELS_DELETE_MESSAGES)+channel+u32(VECTOR_ID)+i32(len(ids))+b''.join(i32(x) for x in ids)
    def messages_set_typing(self, *, peer:bytes, action_cid:int=0x16bf744e)->bytes:
        return u32(self.MESSAGES_SET_TYPING)+i32(0)+peer+i32(0)+u32(action_cid)
    def messages_get_pinned_messages(self, *, peer:bytes)->bytes:
        return u32(self.MESSAGES_GET_PINNED_MESSAGES)+peer
    def messages_update_pinned_message(self, *, peer:bytes, msg_id:int, silent:bool=False, unpin:bool=False, pm_oneside:bool=False)->bytes:
        flags = 0
        if silent:
            flags |= 1 << 0
        if unpin:
            flags |= 1 << 1
        if pm_oneside:
            flags |= 1 << 2
        return u32(self.MESSAGES_UPDATE_PINNED_MESSAGE)+i32(flags)+peer+i32(msg_id)
    def messages_save_draft(self, *, peer:bytes, message:str, reply_to_msg_id:int|None=None)->bytes:
        flags = 0
        if reply_to_msg_id is not None:
            flags |= 1 << 4
        req = u32(self.MESSAGES_SAVE_DRAFT)+i32(flags)
        if reply_to_msg_id is not None:
            req += u32(self.INPUT_REPLY_TO_MESSAGE)+i32(0)+i32(reply_to_msg_id)
        req += peer+tl_str(message)
        return req
    def messages_get_all_drafts(self)->bytes:
        return u32(self.MESSAGES_GET_ALL_DRAFTS)
    def messages_get_all_chats(self, *, except_ids:list[int]|None=None)->bytes:
        ids = except_ids or []
        vec = u32(VECTOR_ID)+i32(len(ids))+b''.join(i64(x) for x in ids)
        return u32(self.MESSAGES_GET_ALL_CHATS)+vec
    def users_get_users(self, *, ids:list[bytes])->bytes:
        vec = u32(VECTOR_ID)+i32(len(ids))+b''.join(ids)
        return u32(self.USERS_GET_USERS)+vec
    def users_get_full_user(self, *, user_id:bytes)->bytes:
        return u32(self.USERS_GET_FULL_USER)+user_id
    def contacts_resolve_username(self, *, username:str)->bytes:
        return u32(self.CONTACTS_RESOLVE_USERNAME)+tl_str(username)
    def channels_get_full_channel(self, *, channel:bytes)->bytes:
        return u32(self.CHANNELS_GET_FULL_CHANNEL)+channel
    def channels_get_participants(
        self,
        *,
        channel:bytes,
        filter_cid:int=0xb4608969,
        offset:int=0,
        limit:int=200,
        hash:int=0,
    )->bytes:
        return u32(self.CHANNELS_GET_PARTICIPANTS)+channel+u32(filter_cid)+i32(offset)+i32(limit)+i64(hash)
    def channels_join_channel(self, *, channel:bytes)->bytes:
        return u32(self.CHANNELS_JOIN_CHANNEL)+channel
    def channels_leave_channel(self, *, channel:bytes)->bytes:
        return u32(self.CHANNELS_LEAVE_CHANNEL)+channel
    def channels_invite_to_channel(self, *, channel:bytes, users:list[bytes])->bytes:
        vec = u32(VECTOR_ID)+i32(len(users))+b''.join(users)
        return u32(self.CHANNELS_INVITE_TO_CHANNEL)+channel+vec
    def channels_edit_title(self, *, channel:bytes, title:str)->bytes:
        return u32(self.CHANNELS_EDIT_TITLE)+channel+tl_str(title)
    def channels_edit_about(self, *, channel:bytes, about:str)->bytes:
        return u32(self.CHANNELS_EDIT_ABOUT)+channel+tl_str(about)
    def account_update_status(self, *, offline:bool=False)->bytes:
        return u32(self.ACCOUNT_UPDATE_STATUS)+u32(0x997275b5 if offline else 0xbc799737)
    def updates_get_state(self)->bytes:
        return u32(self.UPDATES_GET_STATE)
    def updates_get_difference(
        self,
        *,
        pts:int,
        date:int,
        qts:int,
        pts_total_limit:int|None=None,
        pts_limit:int|None=None,
        qts_limit:int|None=None,
    )->bytes:
        flags = 0
        req=u32(self.UPDATES_GET_DIFFERENCE)
        if pts_total_limit is not None:
            flags |= 1 << 0
        if pts_limit is not None:
            flags |= 1 << 1
        if qts_limit is not None:
            flags |= 1 << 2
        req += i32(flags) + i32(pts)
        if pts_limit is not None:
            req += i32(pts_limit)
        if pts_total_limit is not None:
            req += i32(pts_total_limit)
        req += i32(date) + i32(qts)
        if qts_limit is not None:
            req += i32(qts_limit)
        return req
    def msgs_ack(self, msg_ids:list[int])->bytes:
        return u32(0x62d6b459)+u32(VECTOR_ID)+i32(len(msg_ids))+b''.join(i64(x) for x in msg_ids)
    def input_user(self, user_id:int, access_hash:int)->bytes:
        return u32(self.INPUT_USER)+i64(user_id)+i64(access_hash)
    def input_user_self(self)->bytes:
        return u32(self.INPUT_USER_SELF)


def factorize(pq:int)->tuple[int,int]:
    if pq%2==0: return 2,pq//2
    from math import gcd, isqrt
    for c in range(1, 100):
        x = secrets.randbelow(pq - 2) + 2
        y = x
        d = 1
        while d == 1:
            x = (x * x + c) % pq
            y = (y * y + c) % pq
            y = (y * y + c) % pq
            d = gcd(abs(x - y), pq)
        if d != pq:
            return (min(d, pq // d), max(d, pq // d))
    raise ValueError('cant factorize pq')

def kdf(new_nonce:bytes, server_nonce:bytes)->tuple[bytes,bytes]:
    a=sha1(new_nonce+server_nonce).digest()
    b=sha1(server_nonce+new_nonce).digest()
    c=sha1(new_nonce+new_nonce).digest()
    key=a+b[:12]
    iv=b[12:20]+c+new_nonce[:4]
    return key,iv

def kdf_msg(auth_key:bytes, msg_key:bytes, to_server=True)->tuple[bytes,bytes]:
    x=0 if to_server else 8
    a=sha256(msg_key+auth_key[x:x+36]).digest()
    b=sha256(auth_key[40+x:76+x]+msg_key).digest()
    return a[:8]+b[8:24]+a[24:32], b[:8]+a[8:24]+b[24:32]

def rsa_pad_encrypt(data:bytes,n:int,e:int)->bytes:
    d=sha1(data).digest()+data
    d+=secrets.token_bytes(255-len(d))
    return pow(int.from_bytes(d,'big'),e,n).to_bytes(256,'big')
