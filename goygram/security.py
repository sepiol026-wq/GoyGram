# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
from __future__ import annotations

import getpass
import os
from pathlib import Path
from typing import Any

from goygram.logging import get_logger

log = get_logger("goygram.security")


def _zeroize_and_remove(path: Path) -> None:
    size = path.stat().st_size
    with path.open("r+b") as f:
        f.write(b"\x00" * size)
        f.flush()
        os.fsync(f.fileno())
    path.unlink(missing_ok=True)


def _norm_status(obj: dict[str, Any]) -> str:
    return str(obj.get("status") or obj.get("state") or obj.get("kind") or "").upper()


def _ask_non_empty(prompt: str) -> str:
    while True:
        val = input(prompt).strip()
        if val:
            return val
        print("1mInput cannot be emptym")


async def _mt_auth_flow(app: Any, vault: Path) -> dict[str, str] | None:
    print("6mGoyGram interactive loginm")
    while True:
        phone = _ask_non_empty("Phone number: ")
        print(f"4mRequesting code for {phone}...m")
        try:
            sent = await app.mt_req("auth_send_code", phone=phone)
        except Exception:
            print("1mInvalid phone numberm")
            continue

        status = _norm_status(sent if isinstance(sent, dict) else {})
        if status in {"ERR", "ERROR", "PHONE_INVALID"}:
            print("1mInvalid phone numberm")
            continue
        print("2mCode sent to your Telegram appm")

        while True:
            code = _ask_non_empty("Code: ")
            try:
                sign = await app.mt_req("auth_sign_in", phone=phone, code=code)
            except Exception:
                print("1mInvalid code, try againm")
                continue
            sign_status = _norm_status(sign if isinstance(sign, dict) else {})
            if sign_status in {"PHONE_CODE_INVALID", "CODE_INVALID", "INVALID_CODE", "ERR", "ERROR"}:
                print("1mInvalid code, try againm")
                continue
            if sign_status == "SESSION_PASSWORD_NEEDED":
                pwd = getpass.getpass("2FA password: ").strip()
                if not pwd:
                    print("1mInput cannot be emptym")
                    continue
                try:
                    check = await app.mt_req("auth_check_password", password=pwd)
                except Exception:
                    print("1mInvalid 2FA passwordm")
                    continue
                check_status = _norm_status(check if isinstance(check, dict) else {})
                if check_status in {"ERR", "ERROR", "PASSWORD_INVALID"}:
                    print("1mInvalid 2FA passwordm")
                    continue
                auth_key = (check if isinstance(check, dict) else {}).get("auth_key")
            else:
                auth_key = (sign if isinstance(sign, dict) else {}).get("auth_key")

            payload = auth_key if isinstance(auth_key, (bytes, bytearray)) else str(auth_key or "authorized").encode()
            vault.write_bytes(payload)
            print("2mSuccess! Session saved to vault.binm")
            log.info("Interactive login completed and session stored in vault.")
            return {"source": "interactive"}


async def bootstrap_session(app: Any | None = None) -> dict[str, str] | None:
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
    return await _mt_auth_flow(app, vault)
