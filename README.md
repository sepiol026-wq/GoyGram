[![Python 3.14+](https://img.shields.io/badge/python-3.14+-blue.svg?style=for-the-badge&logo=python)](https://www.python.org)
[![Rust Core](https://img.shields.io/badge/Rust_Core-Blazing_Fast-orange.svg?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-red.svg?style=for-the-badge)](https://www.gnu.org/licenses/agpl-3.0)
[![Telegram API](https://img.shields.io/badge/Telegram-MTProto_%7C_BotAPI-2CA5E0.svg?style=for-the-badge&logo=telegram)](https://telegram.org)
[![Security](https://img.shields.io/badge/OpSec-Vault_Encrypted-black.svg?style=for-the-badge&logo=security)](https://github.com/sepiol026-wq/GoyGram)

# GoyGram

Ultimate split-brain Telegram framework (Python + Rust core) built for production-grade speed, control, and maximum OpSec.

## Key Features
- **Split-brain architecture**: ergonomic Python layer + blazing-fast Rust extension.
- **Session Eater**: aggressive in-memory cleanup (zeroize strategy).
- **Vault AES-GCM**: encrypted local session bootstrap.
- **TUI auth flow**: terminal-first authorization workflow.
- **Proxy support**: route traffic through your required network topology.
- **Dual transport**: Bot API + MTProto (with API ID/API Hash) in one app runtime.
- **Dynamic DC Routing**: MTProto nodes are fetched at startup from Telegram public config (no baked-in DC IP list).

## Installation
```bash
pip install goygram
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
- If `farm_worker_1.session` exists, it is migrated to `farm_worker_1.vault` during bootstrap.

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

## License
See [LICENSE](./LICENSE).
