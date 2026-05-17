# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
from __future__ import annotations
import os, struct, secrets, time
from dataclasses import dataclass
from hashlib import sha1, sha256

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



    def auth_check_password(self, *, srp_id:int, A:bytes, M1:bytes, api_id:int)->bytes:
        req=u32(self.AUTH_CHECK_PASSWORD)+u32(self.INPUT_CHECK_PASSWORD_SRP)+i64(srp_id)+tl_bytes(A)+tl_bytes(M1)
        init=u32(self.INIT_CONNECTION)+i32(0)+i32(api_id)+tl_str('goygram')+tl_str('0.4.1')+tl_str('linux')+tl_str('en')+tl_str('')+tl_str('en')+req
        return u32(self.INVOKE_WITH_LAYER)+i32(self.LAYER)+init
    def auth_sign_in(self, phone:str, phone_code_hash:str, code:str, api_id:int)->bytes:
        req=u32(self.AUTH_SIGN_IN)+i32(1)+tl_str(phone)+tl_str(phone_code_hash)+tl_str(code)
        init=u32(self.INIT_CONNECTION)+i32(0)+i32(api_id)+tl_str('goygram')+tl_str('0.4.1')+tl_str('linux')+tl_str('en')+tl_str('')+tl_str('en')+req
        return u32(self.INVOKE_WITH_LAYER)+i32(self.LAYER)+init
    INIT_CONNECTION=0xc1cd5ea9
    INVOKE_WITH_LAYER=0xda9b0d0d
    CODE_SETTINGS=0xad253d78
    LAYER=214

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
        req=u32(self.AUTH_SEND_CODE)+tl_str(phone)+i32(api_id)+tl_str(api_hash)+u32(self.CODE_SETTINGS)+i32(0)
        init=u32(self.INIT_CONNECTION)+i32(0)+i32(api_id)+tl_str('goygram')+tl_str('0.4.1')+tl_str('linux')+tl_str('en')+tl_str('')+tl_str('en')+req
        return u32(self.INVOKE_WITH_LAYER)+i32(self.LAYER)+init
    def account_get_password(self, api_id:int)->bytes:
        req=u32(self.ACCOUNT_GET_PASSWORD)
        init=u32(self.INIT_CONNECTION)+i32(0)+i32(api_id)+tl_str('goygram')+tl_str('0.4.1')+tl_str('linux')+tl_str('en')+tl_str('')+tl_str('en')+req
        return u32(self.INVOKE_WITH_LAYER)+i32(self.LAYER)+init


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
