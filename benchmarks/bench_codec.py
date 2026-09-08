import json
import secrets
import time

import goygram.ext as rx
from goygram.schema_manager import init_schema

init_schema(rx)

peer_hex = rx.serialize_constructor("inputPeerSelf", "{}").hex()
peer_user_hex = rx.serialize_constructor("peerUser", json.dumps({"user_id": 1})).hex()

method = "messages.sendMessage"
args = {
    "peer": peer_hex,
    "message": "bench " * 4,
    "random_id": secrets.randbits(62),
    "flags": 0,
}

for _ in range(200):
    rx.serialize_method(method, json.dumps(args))
tl_obj = {"_": "message", "id": 42, "flags": 0, "flags2": 0, "date": 1700000000, "message": "bench " * 4, "peer_id": peer_user_hex}
buf = rx.serialize_constructor("message", json.dumps(tl_obj))


def bench(fn, budget=0.5):
    t0 = time.perf_counter()
    n = 0
    while time.perf_counter() - t0 < budget:
        fn()
        n += 1
    return n / (time.perf_counter() - t0)


ser_rate = bench(lambda: rx.serialize_method(method, json.dumps(args)))
deser_rate = bench(lambda: json.loads(rx.deserialize_constructor(bytes(buf))))
print(f"TL serialize (messages.sendMessage): {ser_rate:>10,.0f} ops/s")
print(f"TL deserialize (message obj):        {deser_rate:>10,.0f} ops/s")

key = secrets.token_bytes(32)
nonce = secrets.token_bytes(12)
data = secrets.token_bytes(4096)
gcm_e = bench(lambda: rx.aes_gcm_encrypt(key, nonce, data, b""))
ct = rx.aes_gcm_encrypt(key, nonce, data, b"")
gcm_d = bench(lambda: rx.aes_gcm_decrypt(key, nonce, ct, b""))
print(f"AES-256-GCM encrypt (4 KiB):         {gcm_e:>10,.0f} ops/s")
print(f"AES-256-GCM decrypt (4 KiB):         {gcm_d:>10,.0f} ops/s")

info = rx.schema_info()
print(f"schema loaded: layer {info['layer']}, {info['methods']} methods, {info['constructors']} constructors")
