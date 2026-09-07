# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
from __future__ import annotations

import json
import re
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger("goygram.tl.schema_loader")

VECTOR_RE = re.compile(r"^(?:Vector|vector)<(.*)>$")
FLAG_RE = re.compile(r"^(flags2?)\.(\d+)\?(.+)$")


def _parse_field_type(raw: str) -> dict[str, Any]:
    raw = raw.strip().lstrip("%")
    m = VECTOR_RE.match(raw)
    if m:
        inner = _parse_field_type(m.group(1))
        if inner.get("is_vector"):
            inner["type"] = "Vector"
        return {"type": "Vector", "is_vector": True, "vector_inner": inner["type"].lstrip("%"), "vector_inner_is_vector": inner.get("is_vector", False)}

    m = FLAG_RE.match(raw)
    if m:
        flags_prefix = m.group(1)
        bit = int(m.group(2))
        inner_raw = m.group(3)
        inner = _parse_field_type(inner_raw)
        inner["flag_bit"] = bit
        inner["flags_group"] = flags_prefix
        return inner

    if raw in {"true", "True"}:
        return {"type": "true", "is_bare": True}

    return {"type": raw}


def _parse_fields(fields_str: str) -> tuple[list[dict[str, Any]], bool]:
    result: list[dict[str, Any]] = []
    has_flags = False
    tokens = fields_str.strip().split()
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token.startswith("{") or ":" not in token:
            i += 1
            continue
        name, type_str = token.split(":", 1)
        field = _parse_field_type(type_str)
        field["name"] = name
        if type_str == "#":
            has_flags = True
        result.append(field)
        i += 1
    return result, has_flags


def parse_api_tl(path: str | Path) -> dict[str, Any]:
    raw = Path(path).read_text(encoding="utf-8")
    in_functions = False
    methods: dict[str, dict[str, Any]] = {}
    constructors: dict[str, dict[str, Any]] = {}

    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        if line.startswith("---functions---"):
            in_functions = True
            continue
        if line.startswith("---types---"):
            in_functions = False
            continue

        line_unsc = line.rstrip(";")
        m = re.match(
            r"^([A-Za-z0-9_.]+)#([0-9a-fA-F]+)\s*(.*?)\s*=\s*.+$",
            line_unsc,
        )
        if not m:
            continue

        name = m.group(1)
        cid = int(m.group(2), 16)
        rest = m.group(3).strip()

        fields, has_flags = _parse_fields(rest)

        entry = {"cid": cid, "fields": fields, "has_flags": has_flags}

        if in_functions:
            methods[name] = entry
        else:
            constructors[name] = entry

    log.info(
        "Parsed %d methods + %d constructors from %s",
        len(methods),
        len(constructors),
        path,
    )
    return {"methods": methods, "constructors": constructors}


def parse_api_json(raw: str) -> dict[str, Any]:
    document = json.loads(raw)
    result: dict[str, dict[str, dict[str, Any]]] = {"methods": {}, "constructors": {}}
    for source, target in (("methods", "methods"), ("constructors", "constructors")):
        for item in document.get(source, []):
            if not isinstance(item, dict):
                continue
            name_key = "method" if source == "methods" else "predicate"
            name = item.get(name_key)
            if not isinstance(name, str):
                continue
            try:
                cid = int(str(item["id"])) & 0xFFFFFFFF
            except (KeyError, TypeError, ValueError):
                continue
            fields: list[dict[str, Any]] = []
            has_flags = False
            for param in item.get("params", []):
                if not isinstance(param, dict) or not isinstance(param.get("name"), str):
                    continue
                field = _parse_field_type(str(param.get("type", "")))
                field["name"] = param["name"]
                if field.get("type") == "#":
                    has_flags = True
                fields.append(field)
            result[target][name] = {"cid": cid, "fields": fields, "has_flags": has_flags}
    log.info("Parsed %d methods + %d constructors from official JSON", len(result["methods"]), len(result["constructors"]))
    return result


def load_schema_into_rust(ext_module: Any, api_tl_path: str | Path) -> dict[str, Any]:
    schema = parse_api_tl(api_tl_path)
    schema_json = json.dumps(schema, separators=(",", ":"), ensure_ascii=False)
    info = ext_module.load_schema(schema_json)
    log.info("Schema loaded into Rust: %s", info)
    return schema
