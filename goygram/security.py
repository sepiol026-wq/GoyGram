# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
from __future__ import annotations

import asyncio
import getpass
import base64
import json
import os
import re
import sys
import time
import sqlite3
from pathlib import Path
from typing import Any

import hashlib
import secrets as _secrets

from goygram.dc_fetcher import get_dynamic_dc_config, pick_dc_endpoint
from goygram.errors import GoyGramError
from goygram.logging import get_logger

try:
    from goygram import ext as _rx
except Exception:
    _rx = None

log = get_logger("goygram.security")

VAULT_MAGIC = b"GGV2"


def _get_machine_id() -> str:
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            return Path(p).read_text().strip()
        except Exception:
            continue
    try:
        import platform
        return platform.node() or "unknown"
    except Exception:
        return "unknown"


def _derive_vault_key(session_name: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    env_key = os.getenv("GOYGRAM_VAULT_KEY", "").strip()
    if env_key:
        try:
            key = base64.b64decode(env_key)
            if len(key) == 32:
                return key, salt or b"\x00" * 16
        except Exception:
            pass
    if salt is None:
        salt = _secrets.token_bytes(16)
    material = f"{_get_machine_id()}:{session_name}".encode()
    key = hashlib.pbkdf2_hmac("sha256", material, salt, 600000, dklen=32)
    return key, salt


def _derive_vault_key_v2(salt: bytes | None = None) -> tuple[bytes, bytes]:
    env_key = os.getenv("GOYGRAM_VAULT_KEY", "").strip()
    if env_key:
        try:
            key = base64.b64decode(env_key)
            if len(key) == 32:
                return key, salt or b"\x00" * 16
        except Exception:
            pass
    if salt is None:
        salt = _secrets.token_bytes(16)
    material = _get_machine_id().encode()
    key = hashlib.pbkdf2_hmac("sha256", material, salt, 600000, dklen=32)
    return key, salt


def _encrypt_vault_data(data: bytes, session_name: str) -> bytes:
    key, salt = _derive_vault_key_v2()
    nonce = _secrets.token_bytes(12)
    ciphertext = _rx.aes_gcm_encrypt(key, nonce, data, b"")
    return VAULT_MAGIC + salt + nonce + ciphertext


def _decrypt_vault_data(raw: bytes, session_name: str) -> bytes:
    if raw.startswith(VAULT_MAGIC):
        body = raw[len(VAULT_MAGIC):]
        salt = body[:16]
        nonce = body[16:28]
        ciphertext = body[28:]
        key, _ = _derive_vault_key_v2(salt)
        return _rx.aes_gcm_decrypt(key, nonce, ciphertext, b"")
    salt = raw[:16]
    nonce = raw[16:28]
    ciphertext = raw[28:]
    key, _ = _derive_vault_key(session_name, salt)
    return _rx.aes_gcm_decrypt(key, nonce, ciphertext, b"")


def _write_vault(path: Path, payload: dict[str, Any], session_name: str) -> None:
    raw_json = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    encrypted = _encrypt_vault_data(raw_json, session_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    try:
        with tmp_path.open("wb") as handle:
            handle.write(encrypted)
            handle.flush()
            os.fsync(handle.fileno())
        tmp_path.chmod(0o600)
        os.replace(tmp_path, path)
        path.chmod(0o600)
        log.debug("Vault %s written (AES-256-GCM encrypted).", path.name)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


def _read_vault(path: Path, session_name: str) -> dict[str, Any] | None:
    raw = path.read_bytes()
    if not raw:
        return None
    if raw[0] == 0x7B:
        raise ValueError(f"Plaintext vault {path.name} is not accepted")
    try:
        plain = _decrypt_vault_data(raw, session_name)
        return json.loads(plain.decode())
    except Exception as e:
        raise ValueError(f"Cannot decrypt vault {path.name}") from e


def _zeroize_and_remove(path: Path) -> None:
    size = path.stat().st_size
    with path.open("r+b") as f:
        f.write(b"\x00" * size)
        f.flush()
        os.fsync(f.fileno())
    path.unlink(missing_ok=True)


def _is_interactive() -> bool:
    try:
        import termios, tty
        import rich
        return sys.stdout.isatty() and sys.stdin.isatty()
    except ImportError:
        return False

def _rich_menu_sync(title: str, options: list[str]) -> int:
    sys.stdout.write(f"\n\033[1m\033[36m? {title}\033[0m\n")
    sys.stdout.flush()

    selected = 0
    import termios, tty
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        while True:
            sys.stdout.write("\r\033[2K")
            for i, opt in enumerate(options):
                if i == selected:
                    sys.stdout.write(f"\033[32m\033[1m> {opt}\033[0m  ")
                else:
                    sys.stdout.write(f"  {opt}  ")
            sys.stdout.flush()

            ch = sys.stdin.read(1)
            if ch == '\r' or ch == '\n':
                sys.stdout.write("\n\r")
                break
            elif ch == '\x03':
                sys.stdout.write("\n\r")
                raise KeyboardInterrupt
            elif ch == '\x1b':
                next_ch = sys.stdin.read(2)
                if next_ch == '[C' or next_ch == '[B':
                    selected = (selected + 1) % len(options)
                elif next_ch == '[D' or next_ch == '[A':
                    selected = (selected - 1) % len(options)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return selected

def _rich_password_input_sync(prompt_text: str) -> str:
    sys.stdout.write(f"\r\033[1m\033[36m? \033[0m{prompt_text}")
    sys.stdout.flush()
    
    pwd = []
    import termios, tty
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        while True:
            ch = sys.stdin.read(1)
            if ch == '\r' or ch == '\n':
                sys.stdout.write("\n\r")
                break
            elif ch == '\x03':
                sys.stdout.write("\n\r")
                raise KeyboardInterrupt
            elif ch in ('\x08', '\x7f'):
                if pwd:
                    pwd.pop()
                    sys.stdout.write(f"\r\033[K\033[1m\033[36m? \033[0m{prompt_text}")
                    sys.stdout.write("*" * len(pwd))
                    sys.stdout.flush()
            elif ch.isprintable():
                pwd.append(ch)
                sys.stdout.write(ch)
                sys.stdout.flush()
                time.sleep(0.1)
                sys.stdout.write("\b*")
                sys.stdout.flush()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return "".join(pwd)

async def _ask_non_empty(prompt: str, is_password: bool = False) -> str:
    while True:
        try:
            if _is_interactive():
                if is_password:
                    val = await asyncio.to_thread(_rich_password_input_sync, prompt)
                else:
                    from rich.console import Console
                    val = await asyncio.to_thread(Console().input, f"[bold cyan]? [/bold cyan]{prompt}")
            else:
                if is_password:
                    val = await asyncio.to_thread(getpass.getpass, prompt)
                else:
                    val = await asyncio.to_thread(input, prompt)
        except EOFError:
            raise RuntimeError("Interactive input is not available (stdin closed/EOF). Cannot proceed with login.")
        val = val.strip()
        if val:
            return val
        if _is_interactive():
            from rich.console import Console
            Console().print("[bold red]Input cannot be empty[/bold red]")
        else:
            print("Input cannot be empty")


def _normalize_phone(raw: str) -> str:
    val = raw.strip()
    compact = re.sub(r"[^\d+]", "", val)
    if compact.count("+") > 1:
        raise ValueError("phone must contain only one '+' prefix")
    if "+" in compact and not compact.startswith("+"):
        raise ValueError("phone '+' is only allowed at the beginning")
    digits = "".join(ch for ch in compact if ch.isdigit())
    if not digits:
        raise ValueError("phone number must contain digits")
    if compact.startswith("+"):
        if len(digits) < 8 or len(digits) > 15:
            raise ValueError("international phone length must be 8-15 digits")
        return f"+{digits}"
    if len(digits) == 11 and digits.startswith("8"):
        return f"+7{digits[1:]}"
    if len(digits) == 10:
        return f"+1{digits}"
    if len(digits) == 11 and digits.startswith("1"):
        return f"+{digits}"
    if len(digits) < 8 or len(digits) > 15:
        raise ValueError("phone length must be 8-15 digits")
    return f"+{digits}"


def _field(obj: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in obj and obj[key] is not None:
            return obj[key]
    return None


def _current_dc_id(app: Any) -> int | None:
    mt = getattr(app, "mt", None)
    if mt is None:
        return None
    try:
        dc_map = get_dynamic_dc_config()
        for dc_id, endpoints in dc_map.items():
            if dc_id == 0:
                continue
            if any(endpoint.host == mt.host and endpoint.port == mt.port for endpoint in endpoints):
                return int(dc_id)
    except Exception:
        pass
    preferred = getattr(mt, "_preferred_dc", None)
    return int(preferred) if preferred in {1, 2, 3, 4, 5} else None


def _extract_error(obj: dict[str, Any]) -> str | None:
    val = _field(obj, "error", "error_message", "error_code", "status", "state", "kind")
    if val is None:
        return None
    text = str(val).upper()
    if any(x in text for x in ("INVALID", "ERROR", "NEEDED", "FAIL")):
        return text
    return None


def _extract_phone_code_hash(obj: dict[str, Any]) -> str | None:
    return _field(obj, "phone_code_hash", "code_hash")


def _extract_user(obj: dict[str, Any]) -> dict[str, Any] | None:
    user = _field(obj, "user", "me")
    if isinstance(user, dict):
        uid = user.get("id") or user.get("user_id", 0)
        if uid and uid != 0:
            return user
        if user.get("first_name") and user.get("first_name") not in ("Parse Error", "Unknown"):
            return user
    if str(_field(obj, "kind", "type", "_", "constructor") or "").lower() == "user":
        return obj
    return None


def _extract_auth_blob(obj: dict[str, Any]) -> bytes | None:
    auth_key = _field(obj, "auth_key", "session_key")
    if isinstance(auth_key, (bytes, bytearray)):
        return bytes(auth_key)
    if isinstance(auth_key, str) and auth_key:
        try:
            return bytes.fromhex(auth_key)
        except ValueError:
            try:
                return base64.b64decode(auth_key.encode(), validate=True)
            except Exception:
                return auth_key.encode()
    return None




def _extract_migrate_dc(err_text: str) -> int | None:
    m = re.search(r"(?:PHONE|NETWORK|USER)_MIGRATE_(\d+)", err_text.upper())
    if not m:
        return None
    return int(m.group(1))


async def _mt_req_with_migrate(app: Any, act: str, **kw: Any) -> dict[str, Any]:
    while True:
        try:
            res = await app.mt_req(act, **kw)
        except GoyGramError as exc:
            dc_id = _extract_migrate_dc(str(exc))
            if dc_id is None:
                raise
            log.info("MT request %s triggered migration to dc%s", act, dc_id)
        else:
            if not isinstance(res, dict):
                return {"error": "UNEXPECTED_RESPONSE", "raw": res}
            err = (_extract_error(res) or "")
            dc_id = _extract_migrate_dc(err)
            if dc_id is None:
                return res
        dc_map = get_dynamic_dc_config()
        endpoint = pick_dc_endpoint(dc_map, preferred_dc=dc_id)
        await app.mt.close()
        app.mt.stop_ev.clear()
        app.mt.host = endpoint.host
        app.mt.port = endpoint.port
        app.mt._preferred_dc = dc_id
        app.mt.auth_key = None
        app.mt.seq = 0
        app.mt._init_done = False
        import secrets as _sec
        app.mt.session_id = _sec.token_bytes(8)
        await app.mt.boot()
        await app.mt.ensure_auth_key()
        ensure_reader = getattr(app.mt, "_ensure_reader", None)
        if ensure_reader is not None:
            await ensure_reader()
        log.warning("Migrated MT auth request to dc%s %s:%s", dc_id, endpoint.host, endpoint.port)

async def _mt_qr_auth_flow(app: Any, vault: Path, session_name: str, api_id: int, api_hash: str) -> dict[str, str] | None:
    if _is_interactive():
        from rich.console import Console
        Console().print("[bold green]Starting QR code login flow...[/bold green]")
    else:
        print("Starting QR code login flow...")
    qr_lines_printed = 0
    while True:
        try:
            res = await _mt_req_with_migrate(app, "auth_export_login_token", api_id=api_id, api_hash=api_hash, except_ids=[])
        except Exception as e:
            if _is_interactive():
                from rich.console import Console
                Console().print(f"[bold red]Failed to export login token: {e}[/bold red]")
            else:
                print(f"Failed to export login token: {e}")
            return None
            
        if not res.get("ok"):
            if _is_interactive():
                from rich.console import Console
                Console().print(f"[bold red]Error: {res}[/bold red]")
            else:
                print(f"Error: {res}")
            return None
            
        res_type = res.get("type")
        if res_type == "loginToken":
            token = res["token"]
            b64_token = base64.urlsafe_b64encode(token).decode().rstrip("=")
            url = f"tg://login?token={b64_token}"
            
            import qrcode
            try:
                import io
                qr = qrcode.QRCode()
                qr.add_data(url)
                
                f = io.StringIO()
                qr.print_ascii(out=f)
                qr_output = f.getvalue()
                qr_height = qr_output.count('\n')
                
                if _is_interactive() and qr_lines_printed > 0:
                    sys.stdout.write(f"\033[{qr_lines_printed}A\033[J")
                    sys.stdout.flush()
                
                sys.stdout.write(qr_output)
                sys.stdout.flush()
                qr_lines_printed = qr_height
            except Exception:
                if _is_interactive():
                    from rich.console import Console
                    Console().print(f"[bold yellow]Open this link in Telegram to log in: {url}[/bold yellow]")
                else:
                    print(f"Open this link in Telegram to log in: {url}")
                
            if _is_interactive():
                sys.stdout.write("\033[36mWaiting for scan... (or expiration)\033[0m\r")
                sys.stdout.flush()
            else:
                print("Waiting for scan... (or expiration)")
            import time
            expires = res.get("expires", int(time.time()) + 30)
            
            app.mt.qr_update_ev.clear()
            
            while time.time() < expires:
                try:
                    await asyncio.wait_for(app.mt.qr_update_ev.wait(), timeout=expires - time.time())
                except asyncio.TimeoutError:
                    break
                
                app.mt.qr_update_ev.clear()
                try:
                    poll_res = await _mt_req_with_migrate(app, "auth_export_login_token", api_id=api_id, api_hash=api_hash, except_ids=[])
                except GoyGramError as e:
                    poll_err = str(e)
                    if "SESSION_PASSWORD_NEEDED" in poll_err:
                        if _is_interactive() and qr_lines_printed > 0:
                            sys.stdout.write("\n")
                        while True:
                            pwd = await _ask_non_empty("2FA password: ", is_password=True)
                            try:
                                check = await _mt_req_with_migrate(app, "auth_check_password", password=pwd, api_id=api_id, api_hash=api_hash)
                            except GoyGramError as e2:
                                if _is_interactive():
                                    from rich.console import Console
                                    Console().print(f"[bold red]2FA error: {e2}[/bold red]")
                                else:
                                    print(f"2FA error: {e2}")
                                continue
                            except Exception as e2:
                                if _is_interactive():
                                    from rich.console import Console
                                    Console().print(f"[bold red]auth.checkPassword failed: {e2}[/bold red]")
                                else:
                                    print(f"auth.checkPassword failed: {e2}")
                                continue
                            if not isinstance(check, dict):
                                if _is_interactive():
                                    from rich.console import Console
                                    Console().print("[bold red]Unexpected MT response for auth.checkPassword[/bold red]")
                                else:
                                    print("Unexpected MT response for auth.checkPassword")
                                continue
                            check_err = _extract_error(check) or ""
                            if check_err:
                                if _is_interactive():
                                    from rich.console import Console
                                    Console().print(f"[bold red]2FA error: {check_err}[/bold red]")
                                else:
                                    print(f"2FA error: {check_err}")
                                continue
                            poll_res = check
                            poll_res["type"] = "loginTokenSuccess"
                            break
                    else:
                        if _is_interactive():
                            from rich.console import Console
                            Console().print(f"[bold red]QR poll error: {poll_err}[/bold red]")
                        continue
                
                if poll_res.get("type") == "loginTokenSuccess":
                    final = poll_res
                    user = _extract_user(final)
                    auth_blob = _extract_auth_blob(final)
                    if auth_blob is None and getattr(app, "mt", None) is not None:
                        auth_blob = getattr(app.mt, "auth_key", None)
                    if user and auth_blob:
                        if _is_interactive() and qr_lines_printed > 0:
                            sys.stdout.write("\n")
                        payload = {
                            "phone": user.get("phone", ""),
                            "user": user,
                            "auth_key": auth_blob.hex(),
                            "server_salt": app.mt.server_salt.hex(),
                            "dc": _field(final, "dc_id", "dc") or _current_dc_id(app),
                            "api_id": api_id,
                            "api_hash": api_hash,
                        }
                        _write_vault(vault, payload, session_name)
                        uid = user.get("id", 0)
                        if uid and uid != 0:
                            app.self_id = uid
                            app.mt.self_id = uid
                        if _is_interactive():
                            from rich.console import Console
                            Console().print(f"[bold green]Success! Session saved to {vault.name}[/bold green]")
                        else:
                            print(f"Success! Session saved to {vault.name}")
                        return {"source": "qr"}
                    else:
                        if _is_interactive() and qr_lines_printed > 0:
                            sys.stdout.write("\n")
                        if _is_interactive():
                            from rich.console import Console
                            Console().print(f"[bold red]Failed to extract session details from final: {final}[/bold red]")
                        else:
                            print(f"Failed to extract session details from final: {final}")
                        return None
                elif poll_res.get("type") == "loginTokenMigrateTo":
                    dc_id = poll_res["dc_id"]
                    token_m = poll_res["token"]
                    dc_map = get_dynamic_dc_config()
                    endpoint = pick_dc_endpoint(dc_map, preferred_dc=dc_id)
                    await app.mt.close()
                    app.mt.stop_ev.clear()
                    app.mt.host = endpoint.host
                    app.mt.port = endpoint.port
                    app.mt._preferred_dc = dc_id
                    app.mt.auth_key = None
                    app.mt.seq = 0
                    app.mt._init_done = False
                    import secrets as _sec
                    app.mt.session_id = _sec.token_bytes(8)
                    await app.mt.boot()
                    await app.mt.ensure_auth_key()
                    
                    try:
                        mig_res = await _mt_req_with_migrate(app, "auth_import_login_token", token=token_m, api_id=api_id)
                    except GoyGramError as e:
                        mig_err = str(e)
                    else:
                        mig_err = _extract_error(mig_res) or ""
                    if "SESSION_PASSWORD_NEEDED" in mig_err:
                        if _is_interactive() and qr_lines_printed > 0:
                            sys.stdout.write("\n")
                        while True:
                            pwd = await _ask_non_empty("2FA password: ", is_password=True)
                            try:
                                check = await _mt_req_with_migrate(app, "auth_check_password", password=pwd, api_id=api_id, api_hash=api_hash)
                            except Exception as e:
                                if _is_interactive():
                                    from rich.console import Console
                                    Console().print(f"[bold red]auth.checkPassword failed: {e}[/bold red]")
                                else:
                                    print(f"auth.checkPassword failed: {e}")
                                continue
                            if not isinstance(check, dict):
                                if _is_interactive():
                                    from rich.console import Console
                                    Console().print("[bold red]Unexpected MT response for auth.checkPassword[/bold red]")
                                else:
                                    print("Unexpected MT response for auth.checkPassword")
                                continue
                            check_err = _extract_error(check) or ""
                            if check_err:
                                if _is_interactive():
                                    from rich.console import Console
                                    Console().print(f"[bold red]2FA error: {check_err}[/bold red]")
                                else:
                                    print(f"2FA error: {check_err}")
                                continue
                            mig_res = check
                            mig_res["type"] = "loginTokenSuccess"
                            break

                    final = mig_res
                    user = _extract_user(final)
                    auth_blob = _extract_auth_blob(final)
                    if auth_blob is None and getattr(app, "mt", None) is not None:
                        auth_blob = getattr(app.mt, "auth_key", None)
                    if auth_blob is None:
                        continue
                    if _is_interactive() and qr_lines_printed > 0:
                        sys.stdout.write("\n")
                    payload = {
                        "phone": user.get("phone", ""),
                        "user": user,
                        "auth_key": auth_blob.hex(),
                        "server_salt": app.mt.server_salt.hex(),
                        "dc": dc_id,
                        "api_id": api_id,
                        "api_hash": api_hash,
                    }
                    _write_vault(vault, payload, session_name)
                    uid = user.get("id", 0)
                    if uid and uid != 0:
                        app.self_id = uid
                        app.mt.self_id = uid
                    if _is_interactive():
                        from rich.console import Console
                        Console().print(f"[bold green]Success! Session saved to {vault.name}[/bold green]")
                    else:
                        print(f"Success! Session saved to {vault.name}")
                    return {"source": "qr"}
            
            if _is_interactive():

                pass
            else:
                print("Token expired. Regenerating...")
            continue
        elif res_type == "loginTokenSuccess":
            pass
        
        break


async def _mt_auth_flow(app: Any, vault: Path, session_name: str, api_id: int | str | None = None, api_hash: str | None = None) -> dict[str, str] | None:
    if _is_interactive():
        from rich.console import Console
        Console().print(f"\n[bold magenta]GoyGram Interactive Login[/bold magenta]")
    else:
        print("GoyGram interactive login")
    
    if api_id is None:
        api_id = await _ask_non_empty("Telegram API ID: ")
    if api_hash is None:
        api_hash = await _ask_non_empty("Telegram API Hash: ")
    api_id = int(str(api_id).strip())
    api_hash = str(api_hash).strip()
    
    use_qr = False
    if _is_interactive():
        selected = await asyncio.to_thread(_rich_menu_sync, "Choose login method:", ["QR Code Login", "Phone Number Login"])
        use_qr = (selected == 0)
    else:
        ans = (await asyncio.to_thread(input, "Use QR code login? [Y/n]: ")).strip().lower()
        use_qr = ans in ("", "y", "yes")

    if use_qr:
        res = await _mt_qr_auth_flow(app, vault, session_name, api_id, api_hash)
        if res:
            return res
    phone_retries = 0
    max_phone_retries = 5
    while phone_retries < max_phone_retries:
        raw_phone = await _ask_non_empty("Phone number (e.g. +1234567890): ")
        try:
            phone = _normalize_phone(raw_phone)
        except ValueError as e:
            if _is_interactive():
                from rich.console import Console
                Console().print(f"[bold red]Invalid phone format: {e}[/bold red]")
            else:
                print(f"Invalid phone format: {e}")
            continue
        
        if _is_interactive():
            from rich.console import Console
            Console().print(f"[cyan]Requesting Telegram code for {phone}...[/cyan]")
        else:
            print(f"Requesting Telegram code for {phone}...")
            
        try:
            settings = _rx.serialize_constructor("codeSettings", json.dumps({"flags": 0}))
            sent = await _mt_req_with_migrate(app, "auth_send_code", phone_number=phone, api_id=api_id, api_hash=api_hash, settings=settings)
        except Exception as e:
            if _is_interactive():
                from rich.console import Console
                Console().print(f"[bold red]Failed to send code: {e}[/bold red]")
            else:
                print(f"Failed to send code: {e}")
            continue
            
        if not isinstance(sent, dict):
            if _is_interactive():
                from rich.console import Console
                Console().print("[bold red]Unexpected MT response for auth.sendCode[/bold red]")
            else:
                print("Unexpected MT response for auth.sendCode")
            continue
            
        err = _extract_error(sent)
        if err and "SESSION_PASSWORD_NEEDED" not in err:
            if _is_interactive():
                from rich.console import Console
                Console().print(f"[bold red]auth.sendCode error: {err}[/bold red]")
            else:
                print(f"auth.sendCode error: {err}")
            phone_retries += 1
            continue
            
        phone_code_hash = _extract_phone_code_hash(sent)
        if not phone_code_hash:
            if _is_interactive():
                from rich.console import Console
                Console().print("[bold red]auth.sendCode did not return phone_code_hash[/bold red]")
            else:
                print("auth.sendCode did not return phone_code_hash")
            continue
            
        if _is_interactive():
            from rich.console import Console
            Console().print("[cyan]Code sent. Enter the code from Telegram/SMS.[/cyan]")
        else:
            print("Code sent. Enter the code from Telegram/SMS.")

        while True:
            code = await _ask_non_empty("Code: ")
            try:
                sign = await _mt_req_with_migrate(
                    app,
                    "auth_sign_in",
                    phone_number=phone,
                    phone_code=code,
                    phone_code_hash=phone_code_hash,
                    api_id=api_id,
                    api_hash=api_hash,
                )
            except GoyGramError as e:
                sign_err = str(e)
            except Exception as e:
                sign_err = str(e)
            else:
                if not isinstance(sign, dict):
                    if _is_interactive():
                        from rich.console import Console
                        Console().print("[bold red]Unexpected MT response for auth.signIn[/bold red]")
                    else:
                        print("Unexpected MT response for auth.signIn")
                    continue
                sign_err = _extract_error(sign) or ""
                if not sign_err:
                    final = sign
            if "PHONE_CODE_INVALID" in sign_err or "CODE_INVALID" in sign_err:
                if _is_interactive():
                    from rich.console import Console
                    Console().print("[bold red]Invalid code, try again.[/bold red]")
                else:
                    print("Invalid code, try again.")
                continue
            if sign_err and "SESSION_PASSWORD_NEEDED" not in sign_err:
                if _is_interactive():
                    from rich.console import Console
                    Console().print(f"[bold red]auth.signIn failed: {sign_err}[/bold red]")
                else:
                    print(f"auth.signIn failed: {sign_err}")
                continue
            if "SESSION_PASSWORD_NEEDED" in sign_err:
                while True:
                    pwd = await _ask_non_empty("2FA password: ", is_password=True)
                    try:
                        check = await _mt_req_with_migrate(app, "auth_check_password", password=pwd, api_id=api_id, api_hash=api_hash)
                    except Exception as e:
                        if _is_interactive():
                            from rich.console import Console
                            Console().print(f"[bold red]auth.checkPassword failed: {e}[/bold red]")
                        else:
                            print(f"auth.checkPassword failed: {e}")
                        continue
                    if not isinstance(check, dict):
                        if _is_interactive():
                            from rich.console import Console
                            Console().print("[bold red]Unexpected MT response for auth.checkPassword[/bold red]")
                        else:
                            print("Unexpected MT response for auth.checkPassword")
                        continue
                    check_err = _extract_error(check) or ""
                    if check_err:
                        if _is_interactive():
                            from rich.console import Console
                            Console().print(f"[bold red]2FA error: {check_err}[/bold red]")
                        else:
                            print(f"2FA error: {check_err}")
                        continue
                    final = check
                    break

            user = _extract_user(final)
            auth_blob = _extract_auth_blob(final)
            if auth_blob is None and getattr(app, "mt", None) is not None:
                auth_blob = getattr(app.mt, "auth_key", None)
            if user is None or auth_blob is None:
                if _is_interactive():
                    from rich.console import Console
                    Console().print("[bold red]Authorization did not return finalized user/session data[/bold red]")
                else:
                    print("Authorization did not return finalized user/session data")
                continue

            payload = {
                "phone": phone,
                "user": user,
                "auth_key": auth_blob.hex(),
                "server_salt": app.mt.server_salt.hex(),
                "dc": _field(final, "dc_id", "dc") or _current_dc_id(app),
                "api_id": api_id,
                "api_hash": api_hash,
            }
            _write_vault(vault, payload, session_name)
            uid = user.get("id", 0)
            if uid and uid != 0:
                app.self_id = uid
                app.mt.self_id = uid
            if _is_interactive():
                from rich.console import Console
                Console().print(f"[bold green]Success! Session saved to {vault.name}[/bold green]")
            else:
                print(f"Success! Session saved to {vault.name}")
            log.info("Interactive login completed and session stored in %s.", vault.name)
            return {"source": "interactive"}


async def _mt_bot_auth_flow(app: Any, vault: Path, session_name: str, api_id: int, api_hash: str, bot_token: str) -> dict[str, str] | None:
    if _is_interactive():
        from rich.console import Console
        Console().print("[bold magenta]GoyGram Bot Authorization (MTProto)[/bold magenta]")
    else:
        print("GoyGram bot authorization via MTProto (auth.importBotAuthorization)")
    try:
        res = await _mt_req_with_migrate(
            app,
            "auth.importBotAuthorization",
            flags=0,
            api_id=api_id,
            api_hash=api_hash,
            bot_auth_token=bot_token,
        )
    except Exception as exc:
        if _is_interactive():
            from rich.console import Console
            Console().print(f"[bold red]auth.importBotAuthorization failed: {exc}[/bold red]")
        else:
            print(f"auth.importBotAuthorization failed: {exc}")
        return None
    if not isinstance(res, dict):
        if _is_interactive():
            from rich.console import Console
            Console().print("[bold red]Unexpected MT response for auth.importBotAuthorization[/bold red]")
        else:
            print("Unexpected MT response for auth.importBotAuthorization")
        return None
    err = _extract_error(res) or ""
    if err:
        if _is_interactive():
            from rich.console import Console
            Console().print(f"[bold red]auth.importBotAuthorization error: {err}[/bold red]")
        else:
            print(f"auth.importBotAuthorization error: {err}")
        return None
    user = _extract_user(res)
    auth_blob = _extract_auth_blob(res)
    if auth_blob is None and getattr(app, "mt", None) is not None:
        auth_blob = getattr(app.mt, "auth_key", None)
    if user is None or auth_blob is None:
        if _is_interactive():
            from rich.console import Console
            Console().print("[bold red]Bot authorization did not return user/session data[/bold red]")
        else:
            print("Bot authorization did not return user/session data")
        return None
    payload = {
        "user": user,
        "auth_key": auth_blob.hex(),
        "server_salt": app.mt.server_salt.hex(),
        "dc": _current_dc_id(app),
        "api_id": api_id,
        "api_hash": api_hash,
        "bot_token": bot_token,
        "is_bot": True,
    }
    _write_vault(vault, payload, session_name)
    uid = user.get("id", 0)
    if uid and uid != 0:
        app.self_id = uid
        app.mt.self_id = uid
    if _is_interactive():
        from rich.console import Console
        Console().print(f"[bold green]Bot session saved to {vault.name}[/bold green]")
    else:
        print(f"Bot session saved to {vault.name}")
    log.info("Bot MTProto authorization completed and session stored in %s.", vault.name)
    return {"source": "bot_mtproto"}


async def bootstrap_session(app: Any | None = None, api_id: int | str | None = None, api_hash: str | None = None, session_name: str = "default", bot_token: str | None = None, session: Any | None = None) -> dict[str, str] | None:
    if session is None:
        from goygram.session import Session
        session = Session(name=session_name)
    name = session.name
    vault = session.path if session.path is not None else Path(f"{name}.vault")
    if vault.exists() and vault.stat().st_size > 0:
        if app is None or getattr(app, "mt", None) is None:
            log.info("Vault %s detected. Session bootstrap completed without MT context.", vault.name)
            return {"source": "vault"}
        try:
            data = _read_vault(vault, Path(name).name)
            auth_key = data.get("auth_key")
            if isinstance(auth_key, str) and auth_key:
                app.mt.auth_key = _extract_auth_blob({"auth_key": auth_key})
            server_salt = data.get("server_salt")
            if server_salt:
                app.mt.server_salt = _extract_auth_blob({"auth_key": server_salt}) or app.mt.server_salt
            dc = data.get("dc")
            if dc is not None:
                if isinstance(dc, str) and "." in str(dc):
                    app.mt.host = str(dc)
                else:
                    dc_map = get_dynamic_dc_config()
                    endpoint = pick_dc_endpoint(dc_map, preferred_dc=int(dc))
                    app.mt.host = endpoint.host
                    app.mt.port = endpoint.port
            await app.mt.ensure_auth_key()
            user_data = data.get("user", {})
            uid = user_data.get("id", 0) if isinstance(user_data, dict) else 0
            if uid and uid != 0:
                app.self_id = uid
                app.mt.self_id = uid
                log.info("Self ID resolved: %s", uid)
            session.data = data
            log.info("Vault %s detected. Session restored from vault into MT runtime.", vault.name)
            return {"source": "vault"}
        except Exception as e:
            if app is not None and getattr(app, "mt", None) is not None:
                app.mt.auth_key = None
            log.warning("Vault %s restore failed (%r), fallback to interactive auth.", vault.name, e)
    sess = Path(f"{name}.session")
    if sess.exists():
        log.info("Third-party session detected: %s", sess.name)
        try:
            conn = sqlite3.connect(str(sess))
            try:
                cur = conn.cursor()
                row = cur.execute(
                    "SELECT dc_id, auth_key, user_id, api_id, test_mode FROM sessions LIMIT 1"
                ).fetchone()
                if row is None:
                    row = cur.execute("SELECT dc_id, auth_key FROM sessions LIMIT 1").fetchone()
                if row is None:
                    raise ValueError("sessions table is empty")
            finally:
                conn.close()

            dc_id = row[0] if len(row) > 0 else None
            auth_val = row[1] if len(row) > 1 else None
            user_id = row[2] if len(row) > 2 else None
            src_api_id = row[3] if len(row) > 3 else None
            test_mode = row[4] if len(row) > 4 else None
            auth_blob = _extract_auth_blob({"auth_key": auth_val})
            if auth_blob is None:
                raise ValueError("auth_key not found or invalid in sessions table")

            payload: dict[str, Any] = {
                "auth_key": auth_blob.hex(),
                "dc": int(dc_id) if dc_id is not None else None,
                "user_id": user_id,
                "api_id": src_api_id,
                "test_mode": test_mode,
                "source_session": sess.name,
            }
            _write_vault(vault, payload, name)
            _zeroize_and_remove(sess)
            for suffix in ("-wal", "-shm", "-journal"):
                sidecar = Path(f"{sess}{suffix}")
                if sidecar.exists() and sidecar.is_file():
                    _zeroize_and_remove(sidecar)
            session.data = payload
            log.info("Session migrated into %s and source file securely deleted.", vault.name)
            return {"source": "session_migrated"}
        except Exception as e:
            log.warning("Session migration failed for %s (%r).", sess.name, e)
    if app is None:
        raise RuntimeError("MT app context is required for interactive authorization")
    if bot_token is not None:
        if api_id is None or api_hash is None:
            raise RuntimeError("bot_token over MTProto requires api_id and api_hash")
        result = await _mt_bot_auth_flow(app, vault, session_name=name, api_id=int(str(api_id).strip()), api_hash=str(api_hash).strip(), bot_token=str(bot_token).strip())
    else:
        result = await _mt_auth_flow(app, vault, session_name=name, api_id=api_id, api_hash=api_hash)
    if vault.exists() and vault.stat().st_size > 0:
        try:
            session.data = _read_vault(vault, Path(name).name) or session.data
        except Exception:
            pass
    return result
