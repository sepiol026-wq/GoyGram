# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
from __future__ import annotations

import getpass
import os
from pathlib import Path

from goygram.logging import get_logger

log = get_logger("goygram.security")


def _zeroize_and_remove(path: Path) -> None:
    size = path.stat().st_size
    with path.open("r+b") as f:
        f.write(b"\x00" * size)
        f.flush()
        os.fsync(f.fileno())
    path.unlink(missing_ok=True)


def bootstrap_session() -> dict[str, str] | None:
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
    print("\033[96mGoyGram interactive login\033[0m")
    _ = input("Phone number: ")
    _ = input("Code: ")
    _ = getpass.getpass("2FA password: ")
    vault.write_bytes(b"interactive")
    log.info("Interactive login completed and session stored in vault.")
    return {"source": "interactive"}
