# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from goygram.security import (
    _decrypt_vault_data,
    _encrypt_vault_data,
    _extract_auth_blob,
    _read_vault,
    _write_vault,
)

STRING_PREFIX = "goygram_v2:"


def _b64pad(value: str) -> str:
    return value + "=" * (-len(value) % 4)


class Session:
    __slots__ = ("data", "name", "path", "persist")

    def __init__(
        self,
        name: str = "default",
        *,
        data: dict[str, Any] | None = None,
        path: str | Path | None = None,
        persist: bool | None = None,
    ) -> None:
        self.name = name
        self.data = dict(data) if data else {}
        if path is not None:
            self.path = Path(path)
            self.persist = True
        elif persist is False:
            self.path = None
            self.persist = False
        else:
            self.path = Path(f"{name}.vault")
            self.persist = True

    @property
    def self_id(self) -> int | None:
        user = self.data.get("user")
        if isinstance(user, dict):
            uid = user.get("id") or user.get("user_id")
            if uid and uid != 0:
                return int(uid)
        uid = self.data.get("self_id") or self.data.get("user_id")
        if uid and uid != 0:
            return int(uid)
        return None

    @property
    def is_bot(self) -> bool:
        if bool(self.data.get("is_bot", False)):
            return True
        user = self.data.get("user")
        if isinstance(user, dict) and bool(user.get("bot", False)):
            return True
        return False

    @property
    def auth_key(self) -> bytes | None:
        return _extract_auth_blob(self.data)

    @property
    def server_salt(self) -> bytes | None:
        salt = self.data.get("server_salt")
        if isinstance(salt, (bytes, bytearray)):
            return bytes(salt)
        if isinstance(salt, str) and salt:
            try:
                return bytes.fromhex(salt)
            except ValueError:
                return None
        return None

    @property
    def dc(self) -> int | None:
        dc = self.data.get("dc")
        if dc is None:
            return None
        try:
            return int(dc)
        except (TypeError, ValueError):
            return None

    def to_dict(self) -> dict[str, Any]:
        return dict(self.data)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None, name: str = "default", **kw: Any) -> "Session":
        return cls(name=name, data=data, **kw)

    def suggest_name(self) -> str:
        uid = self.self_id
        return f"{uid}.vault" if uid else f"{self.name}.vault"

    def export_string(self) -> str:
        raw = json.dumps(self.data, ensure_ascii=False, separators=(",", ":")).encode()
        encrypted = _encrypt_vault_data(raw, self.name)
        return STRING_PREFIX + base64.urlsafe_b64encode(encrypted).decode().rstrip("=")

    @classmethod
    def from_string(cls, value: str, name: str = "default") -> "Session":
        token = value[len(STRING_PREFIX):] if value.startswith(STRING_PREFIX) else value
        raw = base64.urlsafe_b64decode(_b64pad(token))
        plain = _decrypt_vault_data(raw, name)
        data = json.loads(plain.decode())
        return cls(name=name, data=data)

    def save(self, path: str | Path | None = None) -> Path:
        target = Path(path) if path is not None else self.path
        if target is None:
            target = Path(f"{self.name}.vault")
        _write_vault(target, self.data, self.name)
        self.path = target
        self.persist = True
        return target

    @classmethod
    def load(cls, path: str | Path, name: str | None = None) -> "Session":
        target = Path(path)
        vault_name = name if name is not None else target.name
        data = _read_vault(target, vault_name) or {}
        return cls(name=vault_name, data=data, path=target, persist=True)
