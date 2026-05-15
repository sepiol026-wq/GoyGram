# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
from __future__ import annotations

import asyncio
import getpass
import json
import os
import re
from pathlib import Path
from typing import Any

from goygram.dc_fetcher import get_dynamic_dc_config, pick_dc_endpoint
from goygram.logging import get_logger

log = get_logger("goygram.security")


def _zeroize_and_remove(path: Path) -> None:
    size = path.stat().st_size
    with path.open("r+b") as f:
        f.write(b"\x00" * size)
        f.flush()
        os.fsync(f.fileno())
    path.unlink(missing_ok=True)


async def _ask_non_empty(prompt: str) -> str:
    while True:
        val = (await asyncio.to_thread(input, prompt)).strip()
        if val:
            return val
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
        return user
    if str(_field(obj, "kind", "type", "_", "constructor") or "").lower() == "user":
        return obj
    return None


def _extract_auth_blob(obj: dict[str, Any]) -> bytes | None:
    auth_key = _field(obj, "auth_key", "session_key")
    if isinstance(auth_key, (bytes, bytearray)):
        return bytes(auth_key)
    if isinstance(auth_key, str) and auth_key:
        return auth_key.encode()
    return None




def _extract_migrate_dc(err_text: str) -> int | None:
    m = re.search(r"(?:PHONE|NETWORK)_MIGRATE_(\d+)", err_text.upper())
    if not m:
        return None
    return int(m.group(1))


async def _mt_req_with_migrate(app: Any, act: str, **kw: Any) -> dict[str, Any]:
    while True:
        res = await app.mt_req(act, **kw)
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
        await app.mt.boot()
        log.warning("Migrated MT auth request to dc%s %s:%s", dc_id, endpoint.host, endpoint.port)

async def _mt_auth_flow(app: Any, vault: Path, api_id: int | str | None = None, api_hash: str | None = None) -> dict[str, str] | None:
    print("GoyGram interactive login")
    if api_id is None:
        api_id = await _ask_non_empty("Telegram API ID: ")
    if api_hash is None:
        api_hash = await _ask_non_empty("Telegram API Hash: ")
    api_id = int(str(api_id).strip())
    api_hash = str(api_hash).strip()
    while True:
        raw_phone = await _ask_non_empty("Phone number: ")
        try:
            phone = _normalize_phone(raw_phone)
        except ValueError as e:
            print(f"Invalid phone format: {e}")
            continue
        print(f"Requesting Telegram code for {phone}...")
        try:
            sent = await _mt_req_with_migrate(app, "auth_send_code", phone=phone, api_id=api_id, api_hash=api_hash)
        except Exception as e:
            print(f"Failed to send code: {e}")
            continue
        if not isinstance(sent, dict):
            print("Unexpected MT response for auth.sendCode")
            continue
        err = _extract_error(sent)
        if err and "SESSION_PASSWORD_NEEDED" not in err:
            print(f"auth.sendCode error: {err}")
            continue
        phone_code_hash = _extract_phone_code_hash(sent)
        if not phone_code_hash:
            print("auth.sendCode did not return phone_code_hash")
            continue
        print("Code sent. Enter the code from Telegram/SMS.")

        while True:
            code = await _ask_non_empty("Code: ")
            try:
                sign = await _mt_req_with_migrate(
                    app,
                    "auth_sign_in",
                    phone=phone,
                    code=code,
                    phone_code_hash=phone_code_hash,
                    api_id=api_id,
                    api_hash=api_hash,
                )
            except Exception as e:
                print(f"auth.signIn failed: {e}")
                continue
            if not isinstance(sign, dict):
                print("Unexpected MT response for auth.signIn")
                continue
            sign_err = _extract_error(sign) or ""
            if "PHONE_CODE_INVALID" in sign_err or "CODE_INVALID" in sign_err:
                print("Invalid code, try again.")
                continue

            final = sign
            if "SESSION_PASSWORD_NEEDED" in sign_err:
                while True:
                    pwd = (await asyncio.to_thread(getpass.getpass, "2FA password: ")).strip()
                    if not pwd:
                        print("Input cannot be empty")
                        continue
                    try:
                        check = await _mt_req_with_migrate(app, "auth_check_password", password=pwd, api_id=api_id, api_hash=api_hash)
                    except Exception as e:
                        print(f"auth.checkPassword failed: {e}")
                        continue
                    if not isinstance(check, dict):
                        print("Unexpected MT response for auth.checkPassword")
                        continue
                    check_err = _extract_error(check) or ""
                    if "INVALID" in check_err or "ERROR" in check_err:
                        print("Invalid 2FA password")
                        continue
                    final = check
                    break

            user = _extract_user(final)
            auth_blob = _extract_auth_blob(final)
            if user is None or auth_blob is None:
                print("Authorization did not return finalized user/session data")
                continue

            payload = {
                "phone": phone,
                "user": user,
                "auth_key": auth_blob.decode("utf-8", errors="ignore"),
                "dc": _field(final, "dc_id", "dc"),
                "api_id": api_id,
                "api_hash": api_hash,
            }
            vault.write_bytes(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode())
            print("Success! Session saved to vault.bin")
            log.info("Interactive login completed and session stored in vault.")
            return {"source": "interactive"}


async def bootstrap_session(app: Any | None = None, api_id: int | str | None = None, api_hash: str | None = None) -> dict[str, str] | None:
    vault = Path("vault.bin")
    if vault.exists() and vault.stat().st_size > 0:
        log.info("Vault detected. Session bootstrap completed.")
        return {"source": "vault"}
    for sess in Path.cwd().glob("*.session"):
        log.info("Third-party session detected: %s", sess.name)
        _zeroize_and_remove(sess)
        vault.write_bytes(b"migrated")
        log.info("Session migrated into vault and source file securely deleted.")
        return {"source": "session_migrated"}
    if app is None:
        raise RuntimeError("MT app context is required for interactive authorization")
    return await _mt_auth_flow(app, vault, api_id=api_id, api_hash=api_hash)
