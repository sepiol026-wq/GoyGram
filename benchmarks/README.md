# Benchmarks

Reproducible comparisons of GoyGram against the major Python Telegram libraries.

## What is measured

1. **AES-256-IGE throughput and latency** — the core MTProto crypto operation (packet encryption).
2. **TL codec throughput** — serializing a `messages.sendMessage` request and deserializing a `message` object.
3. **AES-256-GCM throughput** — the vault encryption operation.
4. **Cold import time** — how long the library takes to load.
5. **Memory footprint** — resident set size after import.

## Environment

| Component | Version |
|---|---|
| Python | 3.11 |
| goygram | 0.7.68 (Rust core, AES-NI, `lto = true`, `opt-level = 3`) |
| telethon | 1.44.0 |
| pyrogram | 2.0.106 |
| aiogram | 3.31.0 |
| python-telegram-bot | 22.8 |
| tgcrypto | 1.2.5 |

A single unremarkable VPS (AMD Ryzen 9 5950X), no special hardware. Each library was measured in a fresh process.

## Results

### AES-256-IGE throughput (MB/s, higher is better)

| Library | 256 B | 4 KiB | 64 KiB |
|---|---|---|---|
| goygram (Rust, AES-NI, built-in) | 544 | 1001 | 1094 |
| tgcrypto (C, separate install) | 168 | 224 | 234 |
| pyrogram | 168 | 223 | 228 |
| telethon (default) | 12 | 14 | 14 |

Per-message latency at 256 B (lower is better): goygram 0.4 µs, tgcrypto 1.3 µs, pyrogram 1.4 µs, telethon 23 µs.

GoyGram's IGE uses AES-NI intrinsics with a runtime CPU check and zero-copy `&[u8]` extraction at the Python boundary. tgcrypto 1.2.5 is a table-based software implementation, which is why the gap is a factor of 3-4.7x across sizes.

### TL codec (ops/s, higher is better)

| Operation | ops/s |
|---|---|
| serialize `messages.sendMessage` | 284,933 |
| deserialize `message` object | 66,457 |

### AES-256-GCM (4 KiB, ops/s)

| Operation | ops/s |
|---|---|
| encrypt | 313,217 |
| decrypt | 303,643 |

### Cold import time (ms, lower is better)

| Library | ms |
|---|---|
| goygram | 74 |
| python-telegram-bot | 141 |
| telethon | 272 |
| pyrogram | 436 |
| aiogram | 2699 |

### Memory footprint, RSS delta after import (MB, lower is better)

| Library | MB |
|---|---|
| goygram | 13 |
| python-telegram-bot | 19 |
| pyrogram | 35 |
| telethon | 48 |
| aiogram | 152 |

## Honest notes

- **tgcrypto loses on raw AES-IGE now.** tgcrypto 1.2.5 drives table-based software AES; GoyGram's core dispatches to AES-NI intrinsics when the CPU has them (with a software fallback for older CPUs). Both are far beyond what Telegram needs in practice — the network round-trip dominates. The difference is that GoyGram's crypto is built in, while tgcrypto (or Telethon's `cryptg`) must be installed separately.
- **Telethon's default path is slow** because it drives OpenSSL through `ctypes`, re-running the key schedule and unpacking buffers byte-by-byte on every call. Its fast path (`cryptg`) is not installed by default. This is not a bug in Telethon, it is a default-configuration fact.
- **aiogram's import time and memory** are dominated by pydantic v2.
- **Schema load** (823 methods + 1698 constructors of the official layer 229 schema) takes ~31 ms from cache and ~0.4 µs for a warm `serialize_method` call — dynamic dispatch does not mean slow.

## Reproduce

```bash
uv venv .bench && source .bench/bin/activate
uv pip install goygram telethon tgcrypto pyrogram aiogram python-telegram-bot
python bench_crypto.py
python bench_codec.py
python bench_import.py
```
