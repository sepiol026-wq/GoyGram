# GoyGram

<p align="center">
  <img src="https://raw.githubusercontent.com/GoyGram/GoyGram/main/GoyGram.png" alt="GoyGram Logo" width="650">
</p>

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg?style=for-the-badge&logo=python)](https://www.python.org)
[![Rust Core](https://img.shields.io/badge/Rust_Core-Blazing_Fast-orange.svg?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-red.svg?style=for-the-badge)](https://www.gnu.org/licenses/agpl-3.0)
[![PyPI version](https://img.shields.io/pypi/v/goygram.svg?style=for-the-badge&logo=pypi&color=3775A9)](https://pypi.org/project/goygram/)
[![PyPI downloads](https://img.shields.io/pypi/dm/goygram.svg?style=for-the-badge&logo=pypi&color=3775A9)](https://pypi.org/project/goygram/)
[![Telegram API](https://img.shields.io/badge/Telegram-MTProto_%7C_BotAPI-2CA5E0.svg?style=for-the-badge&logo=telegram)](https://telegram.org)
[![Security](https://img.shields.io/badge/OpSec-Vault_Encrypted-black.svg?style=for-the-badge&logo=security)](https://github.com/GoyGram/GoyGram)
[![Docs & Wiki](https://img.shields.io/badge/Docs-Read_the_Wiki-blue.svg?style=for-the-badge&logo=readthedocs)](https://goygram.github.io/docs)

## What is this?

Ultimate hybrid Telegram framework (Python + Rust core) built for production-grade speed, control, and maximum OpSec.

Under the hood: a Python orchestration layer drives two completely independent network transports (Bot API over aiohttp + MTProto over raw TCP with full DH key exchange), both feeding into a single async event bus. Every crypto operation — AES-256-IGE for MTProto packets, AES-256-GCM for session vaults — runs in a Rust `.so` compiled with LTO and opt-level=3. Hand-written TL codec, no code generation at runtime. QR code login rendering in the terminal via `qrcode` + Rich. SRP password proofs for 2FA. And the vault: your auth key locked to your machine-id through PBKDF2-SHA256 at 600,000 iterations.

## Key Features
- **Hybrid architecture**: ergonomic Python layer + blazing-fast Rust extension.
- **Session zeroize**: aggressive in-memory cleanup (zeroize strategy for legacy `.session` files after migration).
- **Vault AES-256-GCM**: encrypted local session bootstrap. Key derived from machine-id + session name via PBKDF2 (or bypass with `GOYGRAM_VAULT_KEY`).
- **TUI auth flow**: terminal-first authorization workflow — phone login with SMS code, QR code scanning in ASCII art, 2FA/SRP password challenges. All Rich-styled when a TTY is present.
- **Proxy support**: SOCKS5 (with user/pass auth) and HTTP CONNECT tunneling for MTProto connections. Also respects `ALL_PROXY` / `HTTPS_PROXY` / `HTTP_PROXY` env vars.
- **Dual transport**: Bot API (HTTP long-polling via aiohttp, multipart uploads, auto-webhook-clear on 409) + MTProto (raw TCP with AES-256-IGE, dynamic salt recovery on `bad_server_salt`, auto-DC migration on `PHONE_MIGRATE_N`) — in one app runtime.
- **Bot over MTProto**: pass `bot_token` + `api_id`/`api_hash` to authorize a bot through `auth.importBotAuthorization` and switch between `via="api"` and `via="mtproto"` in the same runtime.
- **DC Routing**: MTProto uses a built-in map of the five Telegram DC endpoints and selects the preferred DC, falling back to `149.154.167.50:443` (DC 2).
- **Dynamic API dispatch**: every Bot API method works via `__getattr__` — `sendAnimation`, `getUserProfilePhotos`, `setMyCommands`, whatever. Snake_case auto-converts to CamelCase. `mt_` prefix routes to MTProto.
- **Keyboard system**: inline keyboards, reply keyboards, force reply, reply removal. All with `to_dict()` serialization that adapts per transport.
- **Forum topic management**: full create/edit/close/reopen/delete lifecycle for forum topics and the General topic. Both transports supported.
- **Zero-copy event objects**: `MsgObj`, `CbObj`, `PollObj`, `MemberObj` with `__slots__` — no per-message dict overhead.
- **Composable filters**: boolean AND/OR/NOT on `Filter` (`filters.text & ~filters.me`).
- **Multi-session**: named vaults (`session_name="worker_1"`) for farming multiple accounts from the same process. Separate auth keys, separate TCP connections, separate `self_id`.
- **Portable sessions**: a single `Session` object doubles as memory, file (`.vault`), and encrypted string (`export_string()` / `from_string()`). Rename-safe vaults let you name the file by `self_id` after login.
- **Durable delivery state**: Bot API offsets and MTProto `pts/qts/date/seq` cursors are persisted atomically with restrictive permissions.
- **Direct media primitives**: chunked MTProto `upload_file()`/`download_file()` and Bot API `download_file()` without a heavyweight media framework.

## Benchmarks

Cold import, memory footprint, and MTProto crypto (AES-256-IGE) measured against telethon, pyrogram, aiogram and python-telegram-bot. Full methodology and reproduction in [`benchmarks/`](./benchmarks).

| | goygram | telethon | pyrogram | aiogram | python-telegram-bot |
|---|---|---|---|---|---|
| cold import (ms) | **87** | 298 | 477 | 3112 | 140 |
| RSS delta (MB) | **12** | 48 | 35 | 152 | 18 |
| AES-256-IGE (MB/s, 64 KiB) | **113** | 12 | 203 | — | — |

The crypto runs in Rust (built in, no separate C extension), GoyGram starts ~36× faster than aiogram, and uses ~12× less memory.

## Installation
```bash
pip install goygram
```

Requires Python 3.11+. Pre-built wheels ship for Linux, Windows, macOS, and FreeBSD where the corresponding runner build succeeds. Termux is natively validated in a Termux environment; install the Python package from source there because Android/Termux wheels are not interchangeable with manylinux wheels. Rust is not required for the standard Linux, Windows, and macOS wheels. Installs `aiohttp`, `rich`, and `qrcode` as dependencies.

### FreeBSD and Termux

FreeBSD packages are built by the release workflow inside a FreeBSD 15 VM and attached to the GitHub Release because PyPI rejects FreeBSD's nonstandard wheel platform tag. The Rust core is built in the official `termux/termux-docker` environment and attached as a native validation asset; Termux users should build locally from the source distribution. On a real Termux device, install the Termux toolchain and build from the source distribution:

```bash
pkg update
pkg install python rust clang
python -m pip install --no-build-isolation .
```

## Quick Start

### 1) Bot API (token)
```python
import asyncio
from goygram import GoyGram, filters

app = GoyGram(bot_token="123456:ABC_TOKEN")

@app.on_msg(filt=filters.text)
async def echo(msg):
    await msg.reply("Hello from Bot API")

asyncio.run(app.run())
```

### 2) MTProto (no bot token, requires API ID + API Hash)
```python
import asyncio
from goygram import GoyGram

app = GoyGram(api_id=123456, api_hash="0123456789abcdef0123456789abcdef")  # auto-fetches Telegram DC endpoint at startup

@app.on_cmd("ping")
async def ping(msg):
    await msg.reply("pong from MTProto (api_id/api_hash)")

asyncio.run(app.run())
```


### 3) Named MTProto sessions (multi-session in one folder)
```python
import asyncio
from goygram import GoyGram

app = GoyGram(
    api_id=123456,
    api_hash="0123456789abcdef0123456789abcdef",
    session_name="farm_worker_1",
)

asyncio.run(app.run())
```

- By default, session data is stored in `default.vault`.
- With `session_name="farm_worker_1"`, session data is stored in `farm_worker_1.vault`.
- If `farm_worker_1.session` exists, it is migrated to `farm_worker_1.vault` during bootstrap (securely zeroized after).

### 4) Bot over MTProto (auth.importBotAuthorization)

A bot can run over raw MTProto instead of the Bot API HTTP transport. Pass `bot_token` together with `api_id`/`api_hash` and GoyGram authorizes the bot through `auth.importBotAuthorization` — the MTProto equivalent of the Bot API token handshake (with automatic `USER_MIGRATE_N` DC migration):

```python
import asyncio
from goygram import GoyGram

app = GoyGram(
    bot_token="123456:ABC_TOKEN",
    api_id=123456,
    api_hash="0123456789abcdef0123456789abcdef",
    default_transport="mtproto",   # prefer MTProto for outgoing calls
)

@app.on_cmd("ping")
async def ping(msg):
    await msg.reply("pong via MTProto")

asyncio.run(app.run())
```

Both transports stay available in one runtime. Switch per call with `via="api"` (Bot API) or `via="mtproto"` (MTProto):

```python
await app.send_msg("123456789", "via Bot API", via="api")
await app.send_msg("123456789", "via MTProto", via="mtproto")
```

`default_transport` sets the default when `via` is omitted: `"api"`, `"mtproto"`, or `"auto"` (Bot API if a token is present, else MTProto).

## Dynamic API & Methods
GoyGram can route Bot API method names dynamically, including methods that are not hardcoded as convenience methods:

- Call Bot API methods directly even if they are not explicitly hardcoded:
  - `await app.sendDocument(chat_id=..., document=...)`
  - `await app.getChat(chat_id=...)`
  - `await app.getUpdates(timeout=30)`
- Snake-case also works and is converted to Bot API method names:
  - `await app.send_document(chat_id=..., document=...)` -> `sendDocument`
- MTProto actions (authorized with API ID/API Hash) are available with `mt_` prefix:
  - `await app.mt_get_dialogs(limit=50)`
  - `await app.mt_get_chat_full(chat_id=...)`

This behavior is implemented through dynamic method resolution in the client core (`__getattr__`) and transport-aware request routing.

For Bot API files, `await app.download_file(file_id, destination)` downloads a Telegram file to memory or atomically to a local path. MTProto exposes the same low-level chunk control through `app.core.mt.upload_file(...)` and `app.core.mt.download_file(...)`.

## Authentication & Security

### Interactive Login
On first run with MTProto, GoyGram launches a Rich-powered TUI:

```
GoyGram Interactive Login

? Choose login method:
  > QR Code Login
    Phone Number Login
```

Choose QR code (scan with any Telegram client) or phone number (SMS code). 2FA password is handled automatically via SRP proofs. The resulting session is stored as `default.vault` — AES-256-GCM encrypted, keyed to your machine.

### Vault Encryption
- **Algorithm**: AES-256-GCM (authenticated encryption via Rust's `aes-gcm` crate)
- **Key derivation**: PBKDF2-HMAC-SHA256, 600,000 iterations, key material = `{machine-id}:{session_name}`
- **Override**: `GOYGRAM_VAULT_KEY` env var (base64-encoded 32 bytes) bypasses PBKDF2 entirely
The vault does not fall back to silently accepting plaintext after a failed decryption.

### Session Migration
Telethon/Pyrogram `.session` files are auto-detected, read from SQLite, migrated to `.vault`, and securely zeroized (overwrite + fsync + unlink).

## Session: memory, file, and portable string

Every app exposes `app.session` — a single `Session` object that is the session in **memory**, in a **file** (`.vault`), and as a **portable encrypted string** at the same time. No separate `MemorySession` / `StringSession` / `SQLiteSession` classes and no painful conversions.

```python
from goygram import GoyGram, Session

app = GoyGram(api_id=123456, api_hash="0123456789abcdef0123456789abcdef")

# after authorization, read the account id and name the file by it (rename-safe):
await app.session.save(f"{app.session.self_id}.vault")

# or keep it as an encrypted, portable string (not plaintext like Telethon/Pyrogram):
token = app.session.export_string()   # AES-256-GCM encrypted, machine-locked
sess = Session.from_string(token)     # one call to restore
```

- **Rename-safe vaults**: the encryption key no longer depends on the file name, so you can log in first and name/rename the session file afterwards (e.g. by `self_id`).
- **Encrypted string sessions**: `export_string()` / `from_string()` carry the session as an authenticated, machine-locked blob — unlike Telethon's and Pyrogram's plaintext `StringSession`.
- **One object, three forms**: `session.data`, `session.save(path)`, `session.load(path)`, `session.export_string()`, `session.from_string(s)`. `self_id`, `is_bot`, `auth_key`, `server_salt`, and `dc` are exposed as properties.
- **Backward compatible**: legacy vaults (and `.session` migrations) still decrypt; new vaults are written with a `GGV2` header that the reader auto-detects.

Pass an existing session explicitly:

```python
app = GoyGram(api_id=..., api_hash=..., session=Session.from_string(token))
app = GoyGram(api_id=..., api_hash=..., session=Session(name="worker_1"))
```

The constructor still accepts `session_name="..."` for the plain file-backed case.

## Developer Tools (Help)
Use built-in introspection tools:

```python
app.help()            # pretty DX overview in console
print(dir(app))       # inspect available shortcuts + dynamic entries
```

or:

```python
from goygram.utils import print_methods
print_methods(app)
```

With type hints on key event objects (`MsgObj`, `CbObj`, `MemberObj`, `PollObj`) and filter primitives, modern IDE autocomplete works much better out of the box.

## Filters
`goygram.filters` supports composable boolean operators:

```python
from goygram import filters

smart_filter = filters.text & ~filters.me
another = filters.text | filters.me

@app.on_msg(filt=smart_filter)
async def handler(msg):
    await msg.reply("Filtered")
```

Built-in filters: `filters.text` (message has text), `filters.me` (message from current account/bot). Compose with `&`, `|`, `~`. Custom filters: `Filter(lambda e: ...)`.

## Transport Routing

Messages can be routed explicitly by transport:

```python
# Force Bot API
await app.send_msg("bot:123456789", "via api", via="api")

# Force MTProto
await app.send_msg("mt:123456789", "via mtproto", via="mtproto")
```

`via="api"` is an alias for the Bot API transport and `via="mtproto"` for MTProto (the short forms `via="bot"` / `via="mt"` still work). Chat ID prefixes (`bot:` / `mt:`) are auto-resolved. When replying, the transport source is preserved automatically — reply to a Bot API message, it goes back via Bot API.

## FSM Persistence

The default FSM remains in memory:

```python
app = GoyGram(bot_token="123456:ABC_TOKEN")
```

For an external store, pass an object with `load()` and `save(snapshot)` methods:

```python
class RedisFSM:
    def __init__(self, redis):
        self.redis = redis

    def load(self):
        return self.redis.json().get("goygram:fsm") or []

    def save(self, snapshot):
        self.redis.json().set("goygram:fsm", ".", snapshot)

app = GoyGram(bot_token="123456:ABC_TOKEN", fsm_backend=RedisFSM(redis))
```

For complete control, use `fsm_on_change`. It receives a JSON-compatible snapshot after every state change and can write it to Redis, PostgreSQL, a file, or another service:

```python
def persist_fsm(snapshot):
    external_store.write(snapshot)

app = GoyGram(bot_token="123456:ABC_TOKEN", fsm_on_change=persist_fsm)
```

The active core object is also available as `app.fsm`. It exposes `snapshot()` and `restore(snapshot)` for explicit checkpoints and migrations. Existing `set_state`, `get_state`, `get_state_data`, and `clear_state` behavior is unchanged.

## Event Pipeline

```
BotNet.spin() ──→ bus.push("bot", data)
                                          ──→ Disp.consume() → your handlers
MTNet.spin() ──→ bus.push("mt", data)
```

Single `asyncio.Queue` → typed event objects (`MsgObj`/`CbObj`/`PollObj`/`MemberObj`) → handler lists in registration order. Per-handler error isolation — one crashing handler never takes down the dispatcher.

## Logging

```bash
GOYGRAM_LOG=DEBUG python app.py   # verbose (raw MTProto packet dumps)
GOYGRAM_LOG=INFO python app.py    # default (startup, errors)
GOYGRAM_LOG=WARNING python app.py # quiet
```

Logger hierarchy: `goygram.app`, `goygram.botapi`, `goygram.mtproto`, `goygram.disp`, `goygram.security`, `goygram.dc`.

## Architecture at a Glance

```
┌─────────────────────────────────────────────┐
│             GoyGram (Public API)             │  ← User-facing facade
├─────────────────────────────────────────────┤
│        AppCore (Internal Engine)             │  ← Config, hooks, routing
├──────────────────┬──────────────────────────┤
│ BotNet (aiohttp) │   MTNet (TCP/MTProto)    │  ← Independent transports
├──────────────────┴──────────────────────────┤
│          Bus → Disp (Event Pipeline)         │  ← asyncio.Queue + dispatcher
├─────────────────────────────────────────────┤
│  goygram.ext (Rust .so) — AES-IGE/AES-GCM   │  ← Native crypto (LTO, opt=3)
└─────────────────────────────────────────────┘
```

## Wiki
> 📚 **Official documentation and Wiki.** There are separate pages for using the client, Bot API, MTProto, events, bytes and TL data.
> 👉 **[Open GoyGram Pages](https://goygram.github.io/docs)** · **[Open GitHub Wiki](https://github.com/GoyGram/GoyGram/wiki)**

## License
See [LICENSE](./LICENSE).
