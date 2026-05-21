# GoyGram

<p align="center">
  <img src="https://raw.githubusercontent.com/sepiol026-wq/GoyGram/refs/heads/main/GoyGram.png" alt="GoyGram Logo" width="650">
</p>

[![Python 3.14+](https://img.shields.io/badge/python-3.14+-blue.svg?style=for-the-badge&logo=python)](https://www.python.org)
[![Rust Core](https://img.shields.io/badge/Rust_Core-Blazing_Fast-orange.svg?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-red.svg?style=for-the-badge)](https://www.gnu.org/licenses/agpl-3.0)
[![Telegram API](https://img.shields.io/badge/Telegram-MTProto_%7C_BotAPI-2CA5E0.svg?style=for-the-badge&logo=telegram)](https://telegram.org)
[![Security](https://img.shields.io/badge/OpSec-Vault_Encrypted-black.svg?style=for-the-badge&logo=security)](https://github.com/sepiol026-wq/GoyGram)
[![Docs & Wiki](https://img.shields.io/badge/Docs-Read_the_Wiki-blue.svg?style=for-the-badge&logo=readthedocs)](https://github.com/sepiol026-wq/GoyGram/wiki)

## What is this?

Ultimate split-brain Telegram framework (Python + Rust core) built for production-grade speed, control, and maximum OpSec.

Under the hood: a Python orchestration layer drives two completely independent network transports (Bot API over aiohttp + MTProto over raw TCP with full DH key exchange), both feeding into a single async event bus. Every crypto operation — AES-256-IGE for MTProto packets, AES-256-GCM for session vaults — runs in a Rust `.so` compiled with LTO and opt-level=3. Hand-written TL codec, no code generation at runtime. QR code login rendering in the terminal via `qrcode` + Rich. SRP password proofs for 2FA. And the vault: your auth key locked to your machine-id through PBKDF2-SHA256 at 600,000 iterations.

## Key Features
- **Split-brain architecture**: ergonomic Python layer + blazing-fast Rust extension.
- **Session Eater**: aggressive in-memory cleanup (zeroize strategy for legacy `.session` files after migration).
- **Vault AES-256-GCM**: encrypted local session bootstrap. Key derived from machine-id + session name via PBKDF2 (or bypass with `GOYGRAM_VAULT_KEY`).
- **TUI auth flow**: terminal-first authorization workflow — phone login with SMS code, QR code scanning in ASCII art, 2FA/SRP password challenges. All Rich-styled when a TTY is present.
- **Proxy support**: SOCKS5 (with user/pass auth) and HTTP CONNECT tunneling for MTProto connections. Also respects `ALL_PROXY` / `HTTPS_PROXY` / `HTTP_PROXY` env vars.
- **Dual transport**: Bot API (HTTP long-polling via aiohttp, multipart uploads, auto-webhook-clear on 409) + MTProto (raw TCP with AES-256-IGE, dynamic salt recovery on `bad_server_salt`, auto-DC migration on `PHONE_MIGRATE_N`) — in one app runtime.
- **Dynamic DC Routing**: MTProto nodes are resolved at startup from a built-in DC map (5 Telegram DCs). Falls back to `149.154.167.50:443` (DC 2) if resolution fails.
- **Dynamic API dispatch**: every Bot API method works via `__getattr__` — `sendAnimation`, `getUserProfilePhotos`, `setMyCommands`, whatever. Snake_case auto-converts to CamelCase. `mt_` prefix routes to MTProto.
- **Keyboard system**: inline keyboards, reply keyboards, force reply, reply removal. All with `to_dict()` serialization that adapts per transport.
- **Forum topic management**: full create/edit/close/reopen/delete lifecycle for forum topics and the General topic. Both transports supported.
- **Zero-copy event objects**: `MsgObj`, `CbObj`, `PollObj`, `MemberObj` with `__slots__` — no per-message dict overhead.
- **Composable filters**: boolean AND/OR/NOT on `Filter` (`filters.text & ~filters.me`).
- **Multi-session**: named vaults (`session_name="worker_1"`) for farming multiple accounts from the same process. Separate auth keys, separate TCP connections, separate `self_id`.

## Installation
```bash
pip install goygram
```

Requires Python 3.11+. Rust is **not** required — pre-built wheels ship for Linux, Windows, and macOS (x86-64 + ARM64). Installs `aiohttp`, `pydantic`, `rich`, and `qrcode` as dependencies.

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

## Dynamic API & Methods
GoyGram now supports **all Telegram methods out of the box** with dynamic dispatch:

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
- **Plain JSON fallback**: if decryption fails, tries reading as plain JSON (auto-re-encrypts on next save)

### Session Migration
Telethon/Pyrogram `.session` files are auto-detected, read from SQLite, migrated to `.vault`, and securely zeroized (overwrite + fsync + unlink).

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
await app.send_msg("bot:123456789", "via bot", via="bot")

# Force MTProto
await app.send_msg("mt:123456789", "via mt", via="mt")
```

Chat ID prefixes (`bot:` / `mt:`) are auto-resolved. When replying, the transport source is preserved automatically — reply to a Bot API message, it goes back via Bot API.

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
> 📚 **55 pages of reverse-engineered documentation.** Every line of GoyGram, explained.
> 👉 **[Check out the Official GoyGram Wiki!](https://github.com/sepiol026-wq/GoyGram/wiki)**

## License
See [LICENSE](./LICENSE).
