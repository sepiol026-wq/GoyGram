# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
from __future__ import annotations

import json as _json
import re as _re
import time as _time
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class Filter:
    fn: Callable[[object], bool]
    _name: str | None = None
    _left: Filter | None = field(default=None, repr=False)
    _right: Filter | None = field(default=None, repr=False)
    _op: str | None = field(default=None, repr=False)

    def __call__(self, event: object) -> bool:
        return bool(self.fn(event))

    def __and__(self, other: Filter) -> Filter:
        f = Filter(lambda e: self(e) and other(e), _name="and")
        f._left = self
        f._right = other
        f._op = "&"
        return f

    def __or__(self, other: Filter) -> Filter:
        f = Filter(lambda e: self(e) or other(e), _name="or")
        f._left = self
        f._right = other
        f._op = "|"
        return f

    def __invert__(self) -> Filter:
        f = Filter(lambda e: not self(e), _name=f"not({self._name or '?'})")
        f._left = self
        f._op = "~"
        return f

    def __xor__(self, other: Filter) -> Filter:
        f = Filter(lambda e: self(e) ^ other(e), _name="xor")
        f._left = self
        f._right = other
        f._op = "^"
        return f

    def __sub__(self, other: Filter) -> Filter:
        return self & ~other

    def __repr__(self) -> str:
        if self._name:
            return f"Filter({self._name})"
        return "Filter(<lambda>)"

    def explain(self, event: object) -> str:
        lines: list[str] = []
        ok = self._explain(event, lines, 0)
        lines.append(f"RESULT: {'✓' if ok else '✗'}")
        return "\n".join(lines)

    def _explain(self, event: object, lines: list[str], depth: int) -> bool:
        prefix = "  " * depth
        if self._op == "&":
            la = self._left._explain(event, lines, depth) if self._left else False
            lines.append(f"{prefix}{la} & ...")
            rb = self._right._explain(event, lines, depth) if self._right else False
            ok = la and rb
            lines.append(f"{prefix}= {'✓' if ok else '✗'}")
            return ok
        if self._op == "|":
            la = self._left._explain(event, lines, depth) if self._left else False
            lines.append(f"{prefix}{la} | ...")
            rb = self._right._explain(event, lines, depth) if self._right else False
            ok = la or rb
            lines.append(f"{prefix}= {'✓' if ok else '✗'}")
            return ok
        if self._op == "~":
            la = self._left._explain(event, lines, depth) if self._left else False
            ok = not la
            lines.append(f"{prefix}~{la} = {'✓' if ok else '✗'}")
            return ok
        if self._op == "^":
            la = self._left._explain(event, lines, depth) if self._left else False
            lines.append(f"{prefix}{la} ^ ...")
            rb = self._right._explain(event, lines, depth) if self._right else False
            ok = la ^ rb
            lines.append(f"{prefix}= {'✓' if ok else '✗'}")
            return ok
        ok = self(event)
        name = self._name or "custom"
        lines.append(f"{prefix}{name}: {'✓' if ok else '✗'}")
        return ok

    def tree(self, depth: int = 0) -> str:
        prefix = "  " * depth
        if self._op == "&":
            out = f"{prefix}And\n"
            if self._left:
                out += self._left.tree(depth + 1)
            if self._right:
                out += self._right.tree(depth + 1)
            return out
        if self._op == "|":
            out = f"{prefix}Or\n"
            if self._left:
                out += self._left.tree(depth + 1)
            if self._right:
                out += self._right.tree(depth + 1)
            return out
        if self._op == "~":
            out = f"{prefix}Not\n"
            if self._left:
                out += self._left.tree(depth + 1)
            return out
        if self._op == "^":
            out = f"{prefix}Xor\n"
            if self._left:
                out += self._left.tree(depth + 1)
            if self._right:
                out += self._right.tree(depth + 1)
            return out
        return f"{prefix}{self._name or 'custom'}\n"


def _rext(e: object, path: str, default: Any = None) -> Any:
    val = e
    for seg in path.split("."):
        if val is None:
            return default
        if isinstance(val, dict):
            val = val.get(seg)
        else:
            val = getattr(val, seg, default)
    return val if val is not None else default


def _rget(e: object, *keys: str) -> Any:
    if not keys:
        return None
    value: Any = e
    for key in keys:
        if isinstance(value, dict):
            value = value.get(key)
        elif hasattr(value, "get"):
            value = value.get(key)
        else:
            value = getattr(value, key, None)
        if value is None:
            return None
    return value


def _ct(e: object) -> str | None:
    raw = getattr(e, "raw", None)
    if isinstance(raw, dict):
        for src in (raw, raw.get("message") or {}, raw.get("edited_message") or {}, raw.get("callback_query", {}).get("message") or {}):
            c = src.get("chat") if isinstance(src, dict) else None
            if isinstance(c, dict) and c.get("type"):
                return c["type"]
    cid = getattr(e, "chat_id", None)
    if cid is not None:
        try:
            n = int(cid)
        except (TypeError, ValueError):
            return None
        if n > 0:
            return "private"
        if n > -1000000000000:
            return "group"
        return "channel"
    return None


def _mkey(e: object) -> str | None:
    for k in ("photo", "video", "audio", "document", "sticker", "animation",
              "voice", "video_note", "location", "contact", "venue", "dice",
              "game", "invoice", "story", "giveaway"):
        if _rget(e, k):
            return k
    return None


def _mdur(e: object) -> float:
    for k in ("video", "audio", "animation", "voice", "video_note"):
        obj = _rget(e, k)
        if isinstance(obj, dict):
            return float(obj.get("duration", 0))
    return 0


def _msize(e: object) -> int:
    for k in ("photo", "video", "audio", "document", "animation", "voice", "video_note", "sticker"):
        obj = _rget(e, k)
        sz = 0
        if isinstance(obj, dict):
            sz = int(obj.get("file_size", 0))
        elif isinstance(obj, list):
            sz = max((int(x.get("file_size", 0)) for x in obj if isinstance(x, dict)), default=0)
        if sz > 0:
            return sz
    return 0


def _mime(e: object) -> str:
    for k in ("document", "video", "audio", "animation", "voice", "video_note", "sticker"):
        obj = _rget(e, k)
        if isinstance(obj, dict):
            return str(obj.get("mime_type", ""))
    return ""


def _has_entity(e: object, etype: str) -> bool:
    for src in ("entities", "caption_entities"):
        lst = _rget(e, src)
        if isinstance(lst, list):
            for ent in lst:
                if isinstance(ent, dict):
                    if ent.get("type", "").lower() == etype.lower():
                        return True
                    ctor = str(ent.get("_", ""))
                    if f"messageentity{etype}" in ctor.lower():
                        return True
    return False



text = Filter(lambda e: bool(getattr(e, "text", None)), _name="text")


class command(Filter):
    def __init__(self, *cmds: str, prefixes: tuple[str, ...] = ("/", "!"), ignore_case: bool = True, sep: str = " "):
        self._cmds = {c.lower() if ignore_case else c for c in cmds}
        self._pfx = prefixes
        self._ic = ignore_case
        self._sep = sep
        super().__init__(fn=self._chk, _name=f"command({','.join(cmds)})")

    def _chk(self, e: object) -> bool:
        txt = (getattr(e, "text", "") or "").strip()
        if not txt:
            return False
        body = txt
        matched_pfx = ""
        for p in sorted(self._pfx, key=lambda x: -len(x)):
            if body.startswith(p):
                matched_pfx = p
                body = body[len(p):]
                break
        if not matched_pfx and not any(txt.startswith(p) for p in self._pfx):
            return False
        parts = body.split(self._sep, 1) if self._sep else [body]
        head = parts[0]
        base = head.split("@", 1)[0]
        if self._ic:
            base = base.lower()
        if base not in self._cmds:
            return False
        try:
            object.__setattr__(e, "cmd", base)
            object.__setattr__(e, "args", parts[1].strip() if len(parts) > 1 else "")
        except (AttributeError, TypeError):
            pass
        return True


class regex(Filter):
    def __init__(self, pattern: str, flags: int = 0):
        self._rx = _re.compile(pattern, flags)
        super().__init__(fn=self._chk, _name=f"regex({pattern!r})")

    def _chk(self, e: object) -> bool:
        txt = getattr(e, "text", None) or ""
        m = self._rx.search(txt)
        if m:
            try:
                object.__setattr__(e, "match", m)
            except (AttributeError, TypeError):
                pass
            return True
        return False


class fullmatch(Filter):
    def __init__(self, pattern: str, flags: int = 0):
        self._rx = _re.compile(pattern, flags)
        super().__init__(fn=self._chk, _name=f"fullmatch({pattern!r})")

    def _chk(self, e: object) -> bool:
        txt = getattr(e, "text", None) or ""
        m = self._rx.fullmatch(txt)
        if m:
            try:
                object.__setattr__(e, "match", m)
            except (AttributeError, TypeError):
                pass
            return True
        return False


class findall(Filter):
    def __init__(self, pattern: str, flags: int = 0):
        self._rx = _re.compile(pattern, flags)
        super().__init__(fn=self._chk, _name=f"findall({pattern!r})")

    def _chk(self, e: object) -> bool:
        txt = getattr(e, "text", None) or ""
        res = self._rx.findall(txt)
        if res:
            try:
                object.__setattr__(e, "finds", res)
            except (AttributeError, TypeError):
                pass
            return True
        return False


class finditer(Filter):
    def __init__(self, pattern: str, flags: int = 0):
        self._rx = _re.compile(pattern, flags)
        super().__init__(fn=self._chk, _name=f"finditer({pattern!r})")

    def _chk(self, e: object) -> bool:
        txt = getattr(e, "text", None) or ""
        it = self._rx.finditer(txt)
        try:
            first = next(it)
        except StopIteration:
            return False
        try:
            object.__setattr__(e, "finds", [first] + list(it))
        except (AttributeError, TypeError):
            pass
        return True


class split(Filter):
    def __init__(self, pattern: str, maxsplit: int = 0, flags: int = 0):
        self._rx = _re.compile(pattern, flags)
        self._ms = maxsplit
        super().__init__(fn=self._chk, _name=f"split({pattern!r})")

    def _chk(self, e: object) -> bool:
        txt = getattr(e, "text", None) or ""
        parts = self._rx.split(txt, maxsplit=self._ms)
        try:
            object.__setattr__(e, "parts", parts)
        except (AttributeError, TypeError):
            pass
        return True


class contains(Filter):
    def __init__(self, substring: str, ignore_case: bool = True):
        self._s = substring.lower() if ignore_case else substring
        self._ic = ignore_case
        super().__init__(fn=self._chk, _name=f"contains({substring!r})")

    def _chk(self, e: object) -> bool:
        txt = getattr(e, "text", None) or ""
        return self._s in (txt.lower() if self._ic else txt)


class contains_any(Filter):
    def __init__(self, *substrings: str, ignore_case: bool = True):
        self._ss = tuple(s.lower() if ignore_case else s for s in substrings)
        self._ic = ignore_case
        super().__init__(fn=self._chk, _name=f"contains_any({substrings})")

    def _chk(self, e: object) -> bool:
        txt = getattr(e, "text", None) or ""
        t = txt.lower() if self._ic else txt
        return any(s in t for s in self._ss)


class contains_all(Filter):
    def __init__(self, *substrings: str, ignore_case: bool = True):
        self._ss = tuple(s.lower() if ignore_case else s for s in substrings)
        self._ic = ignore_case
        super().__init__(fn=self._chk, _name=f"contains_all({substrings})")

    def _chk(self, e: object) -> bool:
        txt = getattr(e, "text", None) or ""
        t = txt.lower() if self._ic else txt
        return all(s in t for s in self._ss)


class startswith(Filter):
    def __init__(self, prefix: str, ignore_case: bool = False):
        self._p = prefix.lower() if ignore_case else prefix
        self._ic = ignore_case
        super().__init__(fn=self._chk, _name=f"startswith({prefix!r})")

    def _chk(self, e: object) -> bool:
        txt = getattr(e, "text", None) or ""
        return (txt.lower() if self._ic else txt).startswith(self._p)


class endswith(Filter):
    def __init__(self, suffix: str, ignore_case: bool = False):
        self._s = suffix.lower() if ignore_case else suffix
        self._ic = ignore_case
        super().__init__(fn=self._chk, _name=f"endswith({suffix!r})")

    def _chk(self, e: object) -> bool:
        txt = getattr(e, "text", None) or ""
        return (txt.lower() if self._ic else txt).endswith(self._s)


class text_len(Filter):
    def __init__(self, min_len: int | None = None, max_len: int | None = None):
        self._mn = min_len
        self._mx = max_len
        super().__init__(fn=self._chk, _name=f"text_len({min_len},{max_len})")

    def _chk(self, e: object) -> bool:
        n = len(getattr(e, "text", None) or "")
        if self._mn is not None and n < self._mn:
            return False
        if self._mx is not None and n > self._mx:
            return False
        return True


class word_count(Filter):
    def __init__(self, min_w: int | None = None, max_w: int | None = None):
        self._mn = min_w
        self._mx = max_w
        super().__init__(fn=self._chk, _name=f"word_count({min_w},{max_w})")

    def _chk(self, e: object) -> bool:
        n = len((getattr(e, "text", None) or "").split())
        if self._mn is not None and n < self._mn:
            return False
        if self._mx is not None and n > self._mx:
            return False
        return True


class line_count(Filter):
    def __init__(self, min_l: int | None = None, max_l: int | None = None):
        self._mn = min_l
        self._mx = max_l
        super().__init__(fn=self._chk, _name=f"line_count({min_l},{max_l})")

    def _chk(self, e: object) -> bool:
        n = (getattr(e, "text", None) or "").count("\n") + 1
        if self._mn is not None and n < self._mn:
            return False
        if self._mx is not None and n > self._mx:
            return False
        return True


numeric = Filter(lambda e: (getattr(e, "text", None) or "").strip().lstrip("-").replace(".", "", 1).isdigit(), _name="numeric")
json_text = Filter(lambda e: bool(_json.loads(getattr(e, "text", None) or "{}")), _name="json_text")


class is_language(Filter):
    def __init__(self, lang: str, min_confidence: float = 0.7):
        self._lang = lang.lower()
        self._conf = min_confidence
        super().__init__(fn=self._chk, _name=f"is_language({lang})")

    def _chk(self, e: object) -> bool:
        txt = getattr(e, "text", None) or ""
        if len(txt) < 4:
            return False
        try:
            from langdetect import detect_langs
            for r in detect_langs(txt):
                if r.lang == self._lang and r.prob >= self._conf:
                    return True
        except Exception:
            pass
        return False



class has_entity(Filter):
    def __init__(self, entity_type: str):
        self._et = entity_type
        super().__init__(fn=lambda e: _has_entity(e, entity_type), _name=f"has_entity({entity_type})")


has_url = Filter(lambda e: _has_entity(e, "url"), _name="has_url")
has_mention = Filter(lambda e: _has_entity(e, "mention"), _name="has_mention")
has_hashtag = Filter(lambda e: _has_entity(e, "hashtag"), _name="has_hashtag")
has_cashtag = Filter(lambda e: _has_entity(e, "cashtag"), _name="has_cashtag")
has_email = Filter(lambda e: _has_entity(e, "email"), _name="has_email")
has_phone = Filter(lambda e: _has_entity(e, "phone"), _name="has_phone")
has_bold = Filter(lambda e: _has_entity(e, "bold"), _name="has_bold")
has_italic = Filter(lambda e: _has_entity(e, "italic"), _name="has_italic")
has_code = Filter(lambda e: _has_entity(e, "code"), _name="has_code")
has_pre = Filter(lambda e: _has_entity(e, "pre"), _name="has_pre")
has_spoiler = Filter(lambda e: _has_entity(e, "spoiler"), _name="has_spoiler")
has_custom_emoji = Filter(lambda e: _has_entity(e, "custom_emoji"), _name="has_custom_emoji")
has_blockquote = Filter(lambda e: _has_entity(e, "blockquote"), _name="has_blockquote")
has_underline = Filter(lambda e: _has_entity(e, "underline"), _name="has_underline")
has_strikethrough = Filter(lambda e: _has_entity(e, "strikethrough"), _name="has_strikethrough")
has_text_link = Filter(lambda e: _has_entity(e, "text_link"), _name="has_text_link")
has_text_mention = Filter(lambda e: _has_entity(e, "text_mention"), _name="has_text_mention")
has_bank_card = Filter(lambda e: _has_entity(e, "bank_card"), _name="has_bank_card")


class mentioned(Filter):
    def __init__(self, user_id: int | None = None):
        self._uid = user_id
        super().__init__(fn=self._chk, _name=f"mentioned({user_id})" if user_id else "mentioned")

    def _chk(self, e: object) -> bool:
        raw = getattr(e, "raw", None)
        if not isinstance(raw, dict):
            return False
        for src in ("entities", "caption_entities"):
            lst = raw.get(src)
            if isinstance(lst, list):
                for ent in lst:
                    if not isinstance(ent, dict):
                        continue
                    if ent.get("type") == "text_mention" or "textMention" in str(ent.get("_", "")):
                        if self._uid is None:
                            return True
                        uid = ent.get("user_id") or (ent.get("user", {}) or {}).get("id")
                        if uid and int(uid) == int(self._uid):
                            return True
                    if ent.get("type") == "mention" or "Mention" in str(ent.get("_", "")):
                        if self._uid is None:
                            txt = getattr(e, "text", "") or ""
                            try:
                                offset = int(ent.get("offset", 0))
                                length = int(ent.get("length", 0))
                                mention = txt[offset:offset + length]
                                if mention.startswith("@"):
                                    return True
                            except Exception:
                                pass
        return False


mentioned = mentioned()


photo = Filter(lambda e: _mkey(e) == "photo", _name="photo")
video = Filter(lambda e: _mkey(e) == "video", _name="video")
audio = Filter(lambda e: _mkey(e) == "audio", _name="audio")
document = Filter(lambda e: _mkey(e) == "document", _name="document")
sticker = Filter(lambda e: _mkey(e) == "sticker", _name="sticker")
animation = Filter(lambda e: _mkey(e) == "animation", _name="animation")
voice = Filter(lambda e: _mkey(e) == "voice", _name="voice")
video_note = Filter(lambda e: _mkey(e) == "video_note", _name="video_note")
location = Filter(lambda e: _mkey(e) == "location", _name="location")
contact = Filter(lambda e: _mkey(e) == "contact", _name="contact")
venue = Filter(lambda e: _mkey(e) == "venue", _name="venue")
dice = Filter(lambda e: _mkey(e) == "dice", _name="dice")
game = Filter(lambda e: _mkey(e) == "game", _name="game")
invoice = Filter(lambda e: _mkey(e) == "invoice", _name="invoice")
story = Filter(lambda e: _mkey(e) == "story", _name="story")
giveaway = Filter(lambda e: _mkey(e) == "giveaway", _name="giveaway")
media = Filter(lambda e: _mkey(e) is not None, _name="media")
media_group = Filter(lambda e: bool(_rget(e, "media_group_id")), _name="media_group")
caption = Filter(lambda e: bool(_rget(e, "caption")), _name="caption")


class media_size(Filter):
    def __init__(self, min_bytes: int | None = None, max_bytes: int | None = None):
        self._mn = min_bytes
        self._mx = max_bytes
        super().__init__(fn=self._chk, _name=f"media_size({min_bytes},{max_bytes})")

    def _chk(self, e: object) -> bool:
        sz = _msize(e)
        if sz <= 0:
            return False
        if self._mn is not None and sz < self._mn:
            return False
        if self._mx is not None and sz > self._mx:
            return False
        return True


class media_duration(Filter):
    def __init__(self, min_secs: float | None = None, max_secs: float | None = None):
        self._mn = min_secs
        self._mx = max_secs
        super().__init__(fn=self._chk, _name=f"media_duration({min_secs},{max_secs})")

    def _chk(self, e: object) -> bool:
        dur = _mdur(e)
        if dur <= 0:
            return False
        if self._mn is not None and dur < self._mn:
            return False
        if self._mx is not None and dur > self._mx:
            return False
        return True


class media_mime(Filter):
    def __init__(self, mime_prefix: str):
        self._mp = mime_prefix.lower()
        super().__init__(fn=self._chk, _name=f"media_mime({mime_prefix})")

    def _chk(self, e: object) -> bool:
        return _mime(e).lower().startswith(self._mp)


class media_width(Filter):
    def __init__(self, min_w: int | None = None, max_w: int | None = None):
        self._mn = min_w
        self._mx = max_w
        super().__init__(fn=self._chk, _name=f"media_width({min_w},{max_w})")

    def _chk(self, e: object) -> bool:
        for k in ("photo", "video", "animation", "sticker", "video_note"):
            obj = _rget(e, k)
            w = 0
            if isinstance(obj, dict):
                w = int(obj.get("width", 0))
            elif isinstance(obj, list):
                w = max((int(x.get("width", 0)) for x in obj if isinstance(x, dict)), default=0)
            if w > 0:
                if self._mn is not None and w < self._mn:
                    return False
                if self._mx is not None and w > self._mx:
                    return False
                return True
        return False


class media_height(Filter):
    def __init__(self, min_h: int | None = None, max_h: int | None = None):
        self._mn = min_h
        self._mx = max_h
        super().__init__(fn=self._chk, _name=f"media_height({min_h},{max_h})")

    def _chk(self, e: object) -> bool:
        for k in ("photo", "video", "animation", "sticker", "video_note"):
            obj = _rget(e, k)
            h = 0
            if isinstance(obj, dict):
                h = int(obj.get("height", 0))
            elif isinstance(obj, list):
                h = max((int(x.get("height", 0)) for x in obj if isinstance(x, dict)), default=0)
            if h > 0:
                if self._mn is not None and h < self._mn:
                    return False
                if self._mx is not None and h > self._mx:
                    return False
                return True
        return False


class file_name(Filter):
    def __init__(self, pattern: str, flags: int = 0):
        self._rx = _re.compile(pattern, flags)
        super().__init__(fn=self._chk, _name=f"file_name({pattern!r})")

    def _chk(self, e: object) -> bool:
        for k in ("document", "audio", "video", "animation", "voice", "video_note", "sticker"):
            obj = _rget(e, k)
            if isinstance(obj, dict):
                fn = obj.get("file_name", "")
                if fn and self._rx.search(fn):
                    return True
        return False


class specific_media_group(Filter):
    def __init__(self, mgid: str | int):
        self._mg = str(mgid)
        super().__init__(fn=self._chk, _name=f"specific_media_group({mgid})")

    def _chk(self, e: object) -> bool:
        mg = _rget(e, "media_group_id")
        return str(mg) == self._mg if mg is not None else False


class album_len(Filter):
    def __init__(self, min_n: int | None = None, max_n: int | None = None):
        self._mn = min_n
        self._mx = max_n
        super().__init__(fn=self._chk, _name=f"album_len({min_n},{max_n})")

    def _chk(self, e: object) -> bool:
        arr = _rget(e, "photo") or _rget(e, "media") or []
        if not isinstance(arr, list):
            return False
        n = len(arr)
        if self._mn is not None and n < self._mn:
            return False
        if self._mx is not None and n > self._mx:
            return False
        return True



class caption_regex(Filter):
    def __init__(self, pattern: str, flags: int = 0):
        self._rx = _re.compile(pattern, flags)
        super().__init__(fn=self._chk, _name=f"caption_regex({pattern!r})")

    def _chk(self, e: object) -> bool:
        cap = _rget(e, "caption") or ""
        m = self._rx.search(str(cap))
        if m:
            try:
                object.__setattr__(e, "match", m)
            except (AttributeError, TypeError):
                pass
            return True
        return False


class caption_contains(Filter):
    def __init__(self, substring: str, ignore_case: bool = True):
        self._s = substring.lower() if ignore_case else substring
        self._ic = ignore_case
        super().__init__(fn=self._chk, _name=f"caption_contains({substring!r})")

    def _chk(self, e: object) -> bool:
        cap = str(_rget(e, "caption") or "")
        return self._s in (cap.lower() if self._ic else cap)


class caption_len(Filter):
    def __init__(self, min_len: int | None = None, max_len: int | None = None):
        self._mn = min_len
        self._mx = max_len
        super().__init__(fn=self._chk, _name=f"caption_len({min_len},{max_len})")

    def _chk(self, e: object) -> bool:
        n = len(str(_rget(e, "caption") or ""))
        if self._mn is not None and n < self._mn:
            return False
        if self._mx is not None and n > self._mx:
            return False
        return True



private = Filter(lambda e: _ct(e) == "private", _name="private")
group = Filter(lambda e: _ct(e) == "group", _name="group")
supergroup = Filter(lambda e: _ct(e) == "supergroup", _name="supergroup")
channel = Filter(lambda e: _ct(e) == "channel", _name="channel")
forum = Filter(lambda e: bool(_rget(e, "is_forum") or _rget(e, "chat", "is_forum")), _name="forum")


class chat_type(Filter):
    def __init__(self, ct: str):
        self._ct = ct
        super().__init__(fn=lambda e: _ct(e) == ct, _name=f"chat_type({ct})")


class chat(Filter):
    def __init__(self, chat_id: int | str):
        self._cid = chat_id
        super().__init__(fn=self._chk, _name=f"chat({chat_id})")

    def _chk(self, e: object) -> bool:
        cid = getattr(e, "chat_id", None)
        if cid is None:
            return False
        try:
            return int(cid) == int(self._cid)
        except (TypeError, ValueError):
            return str(cid) == str(self._cid)


class any_chat(Filter):
    def __init__(self, *chat_ids: int | str):
        self._ids = {str(c) for c in chat_ids}
        super().__init__(fn=self._chk, _name=f"any_chat({chat_ids})")

    def _chk(self, e: object) -> bool:
        cid = getattr(e, "chat_id", None)
        return str(cid) in self._ids if cid is not None else False


class not_chat(Filter):
    def __init__(self, *chat_ids: int | str):
        self._ids = {str(c) for c in chat_ids}
        super().__init__(fn=self._chk, _name=f"not_chat({chat_ids})")

    def _chk(self, e: object) -> bool:
        cid = getattr(e, "chat_id", None)
        return str(cid) not in self._ids if cid is not None else True


class topic(Filter):
    def __init__(self, topic_id: int):
        self._tid = topic_id
        super().__init__(fn=self._chk, _name=f"topic({topic_id})")

    def _chk(self, e: object) -> bool:
        tid = _rget(e, "message_thread_id")
        if tid is None:
            return False
        try:
            return int(tid) == int(self._tid)
        except (TypeError, ValueError):
            return False



me = Filter(
    lambda e: bool(getattr(e, "is_me", False) or getattr(e, "from_id", None) == getattr(getattr(e, "app", None), "self_id", object())),
    _name="me"
)


class from_user(Filter):
    def __init__(self, user_id: int):
        self._uid = user_id
        super().__init__(fn=self._chk, _name=f"from_user({user_id})")

    def _chk(self, e: object) -> bool:
        fid = getattr(e, "from_id", None)
        if fid is None:
            return False
        try:
            return int(fid) == int(self._uid)
        except (TypeError, ValueError):
            return False


class from_any(Filter):
    def __init__(self, *user_ids: int):
        self._ids = set(user_ids)
        super().__init__(fn=self._chk, _name=f"from_any({user_ids})")

    def _chk(self, e: object) -> bool:
        fid = getattr(e, "from_id", None)
        if fid is None:
            return False
        try:
            return int(fid) in self._ids
        except (TypeError, ValueError):
            return False


class not_from(Filter):
    def __init__(self, *user_ids: int):
        self._ids = set(user_ids)
        super().__init__(fn=self._chk, _name=f"not_from({user_ids})")

    def _chk(self, e: object) -> bool:
        fid = getattr(e, "from_id", None)
        if fid is None:
            return True
        try:
            return int(fid) not in self._ids
        except (TypeError, ValueError):
            return True


is_bot = Filter(lambda e: bool(_rget(e, "from", "is_bot")), _name="is_bot")
is_premium = Filter(lambda e: bool(_rget(e, "from", "is_premium")), _name="is_premium")
is_verified = Filter(lambda e: bool(_rget(e, "from", "is_verified")), _name="is_verified")
is_scam = Filter(lambda e: bool(_rget(e, "from", "is_scam")), _name="is_scam")
is_fake = Filter(lambda e: bool(_rget(e, "from", "is_fake")), _name="is_fake")
is_support = Filter(lambda e: bool(_rget(e, "from", "is_support")), _name="is_support")
is_contact = Filter(lambda e: bool(_rget(e, "from", "is_contact")), _name="is_contact")
is_mutual_contact = Filter(lambda e: bool(_rget(e, "from", "is_mutual_contact")), _name="is_mutual_contact")


class lang_code(Filter):
    def __init__(self, lang: str):
        self._lang = lang.lower()
        super().__init__(fn=self._chk, _name=f"lang_code({lang})")

    def _chk(self, e: object) -> bool:
        lc = _rget(e, "from", "language_code")
        return str(lc or "").lower() == self._lang



edited = Filter(lambda e: bool(_rget(e, "edit_date")), _name="edited")
forwarded = Filter(
    lambda e: bool(_rget(e, "forward_date") or _rget(e, "forward_from") or _rget(e, "forward_from_chat") or _rget(e, "forward_from_message_id")),
    _name="forwarded"
)
reply = Filter(lambda e: bool(_rget(e, "reply_to_message") or _rget(e, "reply_to")), _name="reply")
pinned = Filter(lambda e: bool(_rget(e, "pinned_message")), _name="pinned")
has_protected_content = Filter(lambda e: bool(_rget(e, "has_protected_content")), _name="has_protected_content")
has_media_spoiler = Filter(lambda e: bool(_rget(e, "has_media_spoiler")), _name="has_media_spoiler")
via_bot = Filter(lambda e: bool(_rget(e, "via_bot")), _name="via_bot")
is_topic_message = Filter(lambda e: bool(_rget(e, "is_topic_message") or _rget(e, "message_thread_id")), _name="is_topic_message")
has_markup = Filter(lambda e: bool(_rget(e, "reply_markup")), _name="has_markup")
has_inline_kbd = Filter(
    lambda e: bool((_rget(e, "reply_markup") or {}).get("inline_keyboard")),
    _name="has_inline_kbd"
)
has_reply_kbd = Filter(
    lambda e: bool((_rget(e, "reply_markup") or {}).get("keyboard")),
    _name="has_reply_kbd"
)
silent = Filter(lambda e: bool(_rget(e, "disable_notification")), _name="silent")
from_offline = Filter(lambda e: bool(_rget(e, "from_offline")), _name="from_offline")
effect = Filter(lambda e: bool(_rget(e, "effect_id")), _name="effect")
has_web_preview = Filter(lambda e: bool(_rget(e, "web_page")), _name="has_web_preview")
noforwards = Filter(lambda e: bool(_rget(e, "noforwards")), _name="noforwards")



class views(Filter):
    def __init__(self, min_views: int):
        self._min = min_views
        super().__init__(fn=self._chk, _name=f"views({min_views})")

    def _chk(self, e: object) -> bool:
        v = _rget(e, "views")
        return int(v or 0) >= self._min


class forwards(Filter):
    def __init__(self, min_forwards: int):
        self._min = min_forwards
        super().__init__(fn=self._chk, _name=f"forwards({min_forwards})")

    def _chk(self, e: object) -> bool:
        f = _rget(e, "forwards")
        return int(f or 0) >= self._min


reaction = Filter(lambda e: bool(_rget(e, "reactions")), _name="reaction")
has_sender_name = Filter(lambda e: bool(_rget(e, "sender_name")), _name="has_sender_name")
signature = Filter(lambda e: bool(_rget(e, "author_signature")), _name="signature")


class message_id(Filter):
    def __init__(self, msg_id: int):
        self._mid = msg_id
        super().__init__(fn=self._chk, _name=f"message_id({msg_id})")

    def _chk(self, e: object) -> bool:
        mid = getattr(e, "id", None) or getattr(e, "msg_id", None)
        try:
            return int(mid) == int(self._mid)
        except (TypeError, ValueError):
            return False



new_chat_members = Filter(lambda e: bool(_rget(e, "new_chat_members")), _name="new_chat_members")
left_chat_member = Filter(lambda e: bool(_rget(e, "left_chat_member")), _name="left_chat_member")
new_chat_title = Filter(lambda e: bool(_rget(e, "new_chat_title")), _name="new_chat_title")
new_chat_photo = Filter(lambda e: bool(_rget(e, "new_chat_photo")), _name="new_chat_photo")
delete_chat_photo = Filter(lambda e: bool(_rget(e, "delete_chat_photo")), _name="delete_chat_photo")
group_created = Filter(lambda e: bool(_rget(e, "group_chat_created")), _name="group_created")
supergroup_created = Filter(lambda e: bool(_rget(e, "supergroup_chat_created")), _name="supergroup_created")
channel_created = Filter(lambda e: bool(_rget(e, "channel_chat_created")), _name="channel_created")
migrate_to = Filter(lambda e: bool(_rget(e, "migrate_to_chat_id")), _name="migrate_to")
migrate_from = Filter(lambda e: bool(_rget(e, "migrate_from_chat_id")), _name="migrate_from")
pinned_msg = Filter(lambda e: bool(_rget(e, "pinned_message")), _name="pinned_msg")
connected_website = Filter(lambda e: bool(_rget(e, "connected_website")), _name="connected_website")
proximity_alert = Filter(lambda e: bool(_rget(e, "proximity_alert_triggered")), _name="proximity_alert")
video_chat_started = Filter(lambda e: bool(_rget(e, "video_chat_started")), _name="video_chat_started")
video_chat_ended = Filter(lambda e: bool(_rget(e, "video_chat_ended")), _name="video_chat_ended")
video_chat_scheduled = Filter(lambda e: bool(_rget(e, "video_chat_scheduled")), _name="video_chat_scheduled")
message_auto_delete_timer = Filter(lambda e: bool(_rget(e, "message_auto_delete_timer_changed")), _name="message_auto_delete_timer")
successful_payment = Filter(lambda e: bool(_rget(e, "successful_payment")), _name="successful_payment")
refunded_payment = Filter(lambda e: bool(_rget(e, "refunded_payment")), _name="refunded_payment")
users_shared = Filter(lambda e: bool(_rget(e, "users_shared")), _name="users_shared")
chat_shared = Filter(lambda e: bool(_rget(e, "chat_shared")), _name="chat_shared")
write_access_allowed = Filter(lambda e: bool(_rget(e, "write_access_allowed")), _name="write_access_allowed")
boost_added = Filter(lambda e: bool(_rget(e, "boost_added")), _name="boost_added")
forum_topic_created = Filter(lambda e: bool(_rget(e, "forum_topic_created")), _name="forum_topic_created")
forum_topic_edited = Filter(lambda e: bool(_rget(e, "forum_topic_edited")), _name="forum_topic_edited")
forum_topic_closed = Filter(lambda e: bool(_rget(e, "forum_topic_closed")), _name="forum_topic_closed")
forum_topic_reopened = Filter(lambda e: bool(_rget(e, "forum_topic_reopened")), _name="forum_topic_reopened")
general_forum_topic_hidden = Filter(lambda e: bool(_rget(e, "general_forum_topic_hidden")), _name="general_forum_topic_hidden")
general_forum_topic_unhidden = Filter(lambda e: bool(_rget(e, "general_forum_topic_unhidden")), _name="general_forum_topic_unhidden")
giveaway_created = Filter(lambda e: bool(_rget(e, "giveaway_created")), _name="giveaway_created")
giveaway_completed = Filter(lambda e: bool(_rget(e, "giveaway_completed")), _name="giveaway_completed")
giveaway_winners = Filter(lambda e: bool(_rget(e, "giveaway_winners")), _name="giveaway_winners")

service = Filter(
    lambda e: any(_rget(e, k) for k in (
        "new_chat_members", "left_chat_member", "new_chat_title", "new_chat_photo",
        "delete_chat_photo", "group_chat_created", "supergroup_chat_created",
        "channel_chat_created", "migrate_to_chat_id", "migrate_from_chat_id",
        "pinned_message", "connected_website", "proximity_alert_triggered",
        "video_chat_started", "video_chat_ended", "video_chat_scheduled",
        "message_auto_delete_timer_changed", "successful_payment",
        "forum_topic_created", "forum_topic_edited", "forum_topic_closed",
        "forum_topic_reopened", "general_forum_topic_hidden", "general_forum_topic_unhidden",
        "boost_added", "giveaway_created", "giveaway_completed", "giveaway_winners",
        "write_access_allowed", "users_shared", "chat_shared",
    )),
    _name="service"
)



class cb_data(Filter):
    def __init__(self, data: str):
        self._d = data
        super().__init__(fn=self._chk, _name=f"cb_data({data!r})")

    def _chk(self, e: object) -> bool:
        return getattr(e, "data", None) == self._d


class cb_startswith(Filter):
    def __init__(self, prefix: str):
        self._p = prefix
        super().__init__(fn=self._chk, _name=f"cb_startswith({prefix!r})")

    def _chk(self, e: object) -> bool:
        d = getattr(e, "data", None) or ""
        return d.startswith(self._p)


class cb_endswith(Filter):
    def __init__(self, suffix: str):
        self._s = suffix
        super().__init__(fn=self._chk, _name=f"cb_endswith({suffix!r})")

    def _chk(self, e: object) -> bool:
        d = getattr(e, "data", None) or ""
        return d.endswith(self._s)


class cb_contains(Filter):
    def __init__(self, substring: str):
        self._s = substring
        super().__init__(fn=self._chk, _name=f"cb_contains({substring!r})")

    def _chk(self, e: object) -> bool:
        d = getattr(e, "data", None) or ""
        return self._s in d


class cb_regex(Filter):
    def __init__(self, pattern: str, flags: int = 0):
        self._rx = _re.compile(pattern, flags)
        super().__init__(fn=self._chk, _name=f"cb_regex({pattern!r})")

    def _chk(self, e: object) -> bool:
        d = getattr(e, "data", None) or ""
        m = self._rx.search(d)
        if m:
            try:
                object.__setattr__(e, "match", m)
            except (AttributeError, TypeError):
                pass
            return True
        return False


class cb_payload(Filter):
    def __init__(self, prefix: str, sep: str = ":"):
        self._p = prefix + sep
        super().__init__(fn=self._chk, _name=f"cb_payload({prefix!r})")

    def _chk(self, e: object) -> bool:
        d = getattr(e, "data", None) or ""
        if d.startswith(self._p):
            try:
                object.__setattr__(e, "payload", d[len(self._p):])
            except (AttributeError, TypeError):
                pass
            return True
        return False


class cb_json(Filter):
    def __init__(self, key: str, value: Any = None):
        self._key = key
        self._val = value
        super().__init__(fn=self._chk, _name=f"cb_json({key!r})")

    def _chk(self, e: object) -> bool:
        d = getattr(e, "data", None) or ""
        try:
            obj = _json.loads(d)
            if not isinstance(obj, dict):
                return False
            if self._val is not None:
                ok = obj.get(self._key) == self._val
            else:
                ok = self._key in obj
            if ok:
                try:
                    object.__setattr__(e, "json_data", obj)
                except (AttributeError, TypeError):
                    pass
            return ok
        except Exception:
            return False


class cb_kvp(Filter):
    def __init__(self, key: str, sep: str = "=", pair_sep: str = "&"):
        self._key = key
        self._sep = sep
        self._ps = pair_sep
        super().__init__(fn=self._chk, _name=f"cb_kvp({key!r})")

    def _chk(self, e: object) -> bool:
        d = getattr(e, "data", None) or ""
        for pair in d.split(self._ps):
            if self._sep in pair:
                k, v = pair.split(self._sep, 1)
                if k == self._key:
                    try:
                        object.__setattr__(e, "payload", v)
                    except (AttributeError, TypeError):
                        pass
                    return True
        return False


class cb_from(Filter):
    def __init__(self, user_id: int):
        self._uid = user_id
        super().__init__(fn=self._chk, _name=f"cb_from({user_id})")

    def _chk(self, e: object) -> bool:
        fid = getattr(e, "from_id", None)
        try:
            return int(fid) == int(self._uid)
        except (TypeError, ValueError):
            return False


class cb_chat(Filter):
    def __init__(self, chat_id: int):
        self._cid = chat_id
        super().__init__(fn=self._chk, _name=f"cb_chat({chat_id})")

    def _chk(self, e: object) -> bool:
        cid = getattr(e, "chat_id", None)
        try:
            return int(cid) == int(self._cid)
        except (TypeError, ValueError):
            return False


class cb_msg(Filter):
    def __init__(self, msg_id: int):
        self._mid = msg_id
        super().__init__(fn=self._chk, _name=f"cb_msg({msg_id})")

    def _chk(self, e: object) -> bool:
        mid = getattr(e, "msg_id", None)
        try:
            return int(mid) == int(self._mid)
        except (TypeError, ValueError):
            return False


cb_game = Filter(lambda e: bool(_rget(e, "game_short_name")), _name="cb_game")
cb_any = Filter(lambda e: True, _name="cb_any")



poll_filter = Filter(lambda e: True, _name="poll_filter")
poll_closed = Filter(lambda e: bool(getattr(e, "closed", False)), _name="poll_closed")
poll_open = Filter(lambda e: not bool(getattr(e, "closed", True)), _name="poll_open")


class poll_question(Filter):
    def __init__(self, question: str):
        self._q = question
        super().__init__(fn=self._chk, _name=f"poll_question({question!r})")

    def _chk(self, e: object) -> bool:
        return (getattr(e, "question", None) or "") == self._q


class poll_contains(Filter):
    def __init__(self, text: str):
        self._t = text.lower()
        super().__init__(fn=self._chk, _name=f"poll_contains({text!r})")

    def _chk(self, e: object) -> bool:
        q = (getattr(e, "question", None) or "").lower()
        return self._t in q


class poll_regex(Filter):
    def __init__(self, pattern: str, flags: int = 0):
        self._rx = _re.compile(pattern, flags)
        super().__init__(fn=self._chk, _name=f"poll_regex({pattern!r})")

    def _chk(self, e: object) -> bool:
        q = getattr(e, "question", None) or ""
        return bool(self._rx.search(q))


class poll_type(Filter):
    def __init__(self, pt: str):
        self._pt = pt
        super().__init__(fn=self._chk, _name=f"poll_type({pt})")

    def _chk(self, e: object) -> bool:
        return getattr(e, "kind", None) == self._pt


class poll_chat(Filter):
    def __init__(self, chat_id: int):
        self._cid = chat_id
        super().__init__(fn=self._chk, _name=f"poll_chat({chat_id})")

    def _chk(self, e: object) -> bool:
        cid = getattr(e, "chat_id", None)
        try:
            return int(cid) == int(self._cid)
        except (TypeError, ValueError):
            return False


class poll_option(Filter):
    def __init__(self, idx: int):
        self._idx = idx
        super().__init__(fn=self._chk, _name=f"poll_option({idx})")

    def _chk(self, e: object) -> bool:
        raw = getattr(e, "raw", None)
        if not isinstance(raw, dict):
            return False
        for src in ("options", "chosen_options", "option_ids"):
            opts = raw.get(src)
            if isinstance(opts, list):
                for o in opts:
                    v = o if not isinstance(o, dict) else (o.get("option_id") or o.get("option") or o.get("id"))
                    try:
                        if int(v) == self._idx:
                            return True
                    except (TypeError, ValueError):
                        pass
        return False


poll_any = poll_filter
poll_answer = Filter(lambda e: getattr(e, "kind", None) == "poll_answer", _name="poll_answer")



def _mtrans(e: object, old_s: str | None, new_s: str | None) -> bool:
    old_ok = old_s is None or getattr(e, "old", None) == old_s
    new_ok = new_s is None or getattr(e, "new", None) == new_s
    return old_ok and new_ok


member_joined = Filter(lambda e: _mtrans(e, None, "member"), _name="member_joined")
member_left = Filter(
    lambda e: _mtrans(e, "member", "left") or _mtrans(e, "member", "kicked"),
    _name="member_left"
)
member_banned = Filter(lambda e: _mtrans(e, None, "kicked"), _name="member_banned")
member_unbanned = Filter(
    lambda e: _mtrans(e, "kicked", "member") or _mtrans(e, "restricted", "member"),
    _name="member_unbanned"
)
member_promoted = Filter(lambda e: _mtrans(e, "member", "administrator"), _name="member_promoted")
member_demoted = Filter(lambda e: _mtrans(e, "administrator", "member"), _name="member_demoted")
member_restricted = Filter(lambda e: _mtrans(e, "member", "restricted"), _name="member_restricted")
member_unrestricted = Filter(lambda e: _mtrans(e, "restricted", "member"), _name="member_unrestricted")


class member_status(Filter):
    def __init__(self, status: str):
        self._st = status
        super().__init__(fn=self._chk, _name=f"member_status({status})")

    def _chk(self, e: object) -> bool:
        return getattr(e, "new", None) == self._st


class member_chat(Filter):
    def __init__(self, chat_id: int):
        self._cid = chat_id
        super().__init__(fn=self._chk, _name=f"member_chat({chat_id})")

    def _chk(self, e: object) -> bool:
        cid = getattr(e, "chat_id", None)
        try:
            return int(cid) == int(self._cid)
        except (TypeError, ValueError):
            return False


class member_user(Filter):
    def __init__(self, user_id: int):
        self._uid = user_id
        super().__init__(fn=self._chk, _name=f"member_user({user_id})")

    def _chk(self, e: object) -> bool:
        uid = getattr(e, "user_id", None)
        try:
            return int(uid) == int(self._uid)
        except (TypeError, ValueError):
            return False


class member_by(Filter):
    def __init__(self, admin_id: int):
        self._aid = admin_id
        super().__init__(fn=self._chk, _name=f"member_by({admin_id})")

    def _chk(self, e: object) -> bool:
        fid = getattr(e, "from_id", None)
        try:
            return int(fid) == int(self._aid)
        except (TypeError, ValueError):
            return False


member_self = Filter(
    lambda e: getattr(e, "user_id", None) == getattr(getattr(e, "app", None), "self_id", object()),
    _name="member_self"
)
member_any = Filter(lambda e: True, _name="member_any")



class update_type(Filter):
    _MAP = {"msg": "msg", "cb": "cb", "poll": "poll", "member": "member", "inline": "inline", "update": "update", "edit": "edit"}

    def __init__(self, *types: str):
        self._ts = {self._MAP.get(t, t) for t in types}
        super().__init__(fn=self._chk, _name=f"update_type({types})")

    def _chk(self, e: object) -> bool:
        return getattr(e, "kind", None) in self._ts or getattr(e, "update_type", None) in self._ts


class network(Filter):
    def __init__(self, net: str):
        self._net = net
        super().__init__(fn=self._chk, _name=f"network({net})")

    def _chk(self, e: object) -> bool:
        return getattr(e, "src", None) == self._net


class user(Filter):
    def __init__(self, user_id: int):
        self._uid = user_id
        super().__init__(fn=self._chk, _name=f"user({user_id})")

    def _chk(self, e: object) -> bool:
        fid = getattr(e, "from_id", None) or getattr(e, "user_id", None)
        try:
            return int(fid) == int(self._uid)
        except (TypeError, ValueError):
            return False


class state(Filter):
    def __init__(self, name: str):
        self._name_val = name
        super().__init__(fn=self._chk, _name=f"state({name!r})")

    def _chk(self, e: object) -> bool:
        chat_id = getattr(e, 'chat_id', None)
        from_id = getattr(e, 'from_id', None)
        if chat_id is None or from_id is None:
            return False
        try:
            chat_id = int(chat_id)
            from_id = int(from_id)
        except (TypeError, ValueError):
            return False
        app = getattr(e, 'app', None)
        if app is None or not hasattr(app, 'fsm'):
            return False
        return app.fsm.get(chat_id, from_id) == self._name_val


class state_any(Filter):
    def __init__(self, *names: str):
        self._names = set(names)
        super().__init__(fn=self._chk, _name=f"state_any({names})")

    def _chk(self, e: object) -> bool:
        chat_id = getattr(e, 'chat_id', None)
        from_id = getattr(e, 'from_id', None)
        if chat_id is None or from_id is None:
            return False
        try:
            chat_id = int(chat_id)
            from_id = int(from_id)
        except (TypeError, ValueError):
            return False
        app = getattr(e, 'app', None)
        if app is None or not hasattr(app, 'fsm'):
            return False
        cur = app.fsm.get(chat_id, from_id)
        return cur is not None and cur in self._names



any_filter = Filter(lambda e: True, _name="any")
none_filter = Filter(lambda e: False, _name="none")


class func(Filter):
    def __init__(self, fn: Callable[[object], bool], name: str | None = None):
        super().__init__(fn=fn, _name=name or f"func({getattr(fn, '__name__', 'λ')})")


def all_of(*filters: Filter) -> Filter:
    if not filters:
        return any_filter
    r = filters[0]
    for f in filters[1:]:
        r = r & f
    r._name = f"all_of({len(filters)})"
    return r


def any_of(*filters: Filter) -> Filter:
    if not filters:
        return none_filter
    r = filters[0]
    for f in filters[1:]:
        r = r | f
    r._name = f"any_of({len(filters)})"
    return r


def none_of(*filters: Filter) -> Filter:
    return ~any_of(*filters)


def at_least(n: int, *filters: Filter) -> Filter:
    return Filter(lambda e: sum(1 for f in filters if f(e)) >= n, _name=f"at_least({n},{len(filters)})")


def at_most(n: int, *filters: Filter) -> Filter:
    return Filter(lambda e: sum(1 for f in filters if f(e)) <= n, _name=f"at_most({n},{len(filters)})")


def exactly(n: int, *filters: Filter) -> Filter:
    return Filter(lambda e: sum(1 for f in filters if f(e)) == n, _name=f"exactly({n},{len(filters)})")


def invert(f: Filter) -> Filter:
    return ~f



def if_(cond: Filter, then_f: Filter, else_f: Filter | None = None) -> Filter:
    ef = else_f or none_filter
    return Filter(lambda e: then_f(e) if cond(e) else ef(e), _name="if_(...)")

def unless(filter_a: Filter, filter_b: Filter) -> Filter:
    return if_(~filter_b, filter_a)



class once(Filter):
    def __init__(self, inner: Filter | None = None):
        self._ok = False
        self._inner = inner
        super().__init__(fn=self._chk, _name="once")

    def _chk(self, e: object) -> bool:
        if self._ok:
            return False
        ok = self._inner(e) if self._inner else True
        if ok:
            self._ok = True
        return ok


class limit(Filter):
    def __init__(self, n: int, inner: Filter | None = None):
        self._max = n
        self._cnt = 0
        self._inner = inner
        super().__init__(fn=self._chk, _name=f"limit({n})")

    def _chk(self, e: object) -> bool:
        if self._cnt >= self._max:
            return False
        ok = self._inner(e) if self._inner else True
        if ok:
            self._cnt += 1
        return ok


class every_n(Filter):
    def __init__(self, n: int, inner: Filter | None = None):
        self._n = n
        self._cnt = 0
        self._inner = inner
        super().__init__(fn=self._chk, _name=f"every_n({n})")

    def _chk(self, e: object) -> bool:
        ok = self._inner(e) if self._inner else True
        if not ok:
            return False
        self._cnt += 1
        return self._cnt % self._n == 0


class cooldown(Filter):
    def __init__(self, seconds: float, inner: Filter | None = None, key: str = "chat_id"):
        self._secs = seconds
        self._last: dict[str, float] = {}
        self._inner = inner
        self._key = key
        super().__init__(fn=self._chk, _name=f"cooldown({seconds}s)")

    def _chk(self, e: object) -> bool:
        k = str(getattr(e, self._key, "__g__"))
        now = _time.monotonic()
        if now - self._last.get(k, 0) < self._secs:
            return False
        ok = self._inner(e) if self._inner else True
        if ok:
            self._last[k] = now
        return ok


class throttled(Filter):
    def __init__(self, rate: int, per: float, inner: Filter | None = None, key: str = "chat_id"):
        self._rate = rate
        self._per = per
        self._win: dict[str, list[float]] = {}
        self._inner = inner
        self._key = key
        super().__init__(fn=self._chk, _name=f"throttled({rate}/{per}s)")

    def _chk(self, e: object) -> bool:
        k = str(getattr(e, self._key, "__g__"))
        now = _time.monotonic()
        ts = self._win.setdefault(k, [])
        cutoff = now - self._per
        while ts and ts[0] < cutoff:
            ts.pop(0)
        if len(ts) >= self._rate:
            return False
        ok = self._inner(e) if self._inner else True
        if ok:
            ts.append(now)
        return ok



class _AnyData(Filter):
    def __init__(self):
        super().__init__(fn=lambda e: True, _name="*")


class filter_data(Filter):
    def __init__(self, **kwargs: Any):
        self._spec = kwargs
        super().__init__(fn=self._chk, _name=f"filter_data({kwargs})")

    def _chk(self, e: object) -> bool:
        for k, v in self._spec.items():
            ev = getattr(e, k, None)
            if isinstance(v, Filter):
                if not v(e):
                    return False
            elif ev != v:
                return False
        return True



__all__ = [
    "Filter",
    "text", "command", "regex", "fullmatch", "findall", "finditer", "split",
    "contains", "contains_any", "contains_all", "startswith", "endswith",
    "text_len", "word_count", "line_count", "numeric", "json_text", "is_language",
    "has_entity", "has_url", "has_mention", "has_hashtag", "has_cashtag",
    "has_email", "has_phone", "has_bold", "has_italic", "has_code", "has_pre",
    "has_spoiler", "has_custom_emoji", "has_blockquote", "has_underline",
    "has_strikethrough", "has_text_link", "has_text_mention", "has_bank_card",
    "mentioned",
    "photo", "video", "audio", "document", "sticker", "animation", "voice",
    "video_note", "location", "contact", "venue", "dice", "game", "invoice",
    "story", "giveaway", "media", "media_group", "caption",
    "media_size", "media_duration", "media_mime", "media_width", "media_height",
    "file_name", "specific_media_group", "album_len",
    "caption_regex", "caption_contains", "caption_len",
    "private", "group", "supergroup", "channel", "chat_type", "forum",
    "chat", "any_chat", "not_chat", "topic",
    "me", "from_user", "from_any", "not_from",
    "is_bot", "is_premium", "is_verified", "is_scam", "is_fake", "is_support",
    "is_contact", "is_mutual_contact", "lang_code",
    "edited", "forwarded", "reply", "pinned",
    "has_protected_content", "has_media_spoiler", "via_bot",
    "is_topic_message", "has_markup", "has_inline_kbd", "has_reply_kbd",
    "has_web_preview", "silent", "from_offline", "effect", "noforwards",
    "views", "forwards", "reaction", "has_sender_name", "signature", "message_id",
    "new_chat_members", "left_chat_member", "new_chat_title", "new_chat_photo",
    "delete_chat_photo", "group_created", "supergroup_created", "channel_created",
    "migrate_to", "migrate_from", "pinned_msg", "connected_website",
    "proximity_alert", "video_chat_started", "video_chat_ended",
    "video_chat_scheduled", "message_auto_delete_timer",
    "successful_payment", "refunded_payment", "users_shared", "chat_shared",
    "write_access_allowed", "boost_added",
    "forum_topic_created", "forum_topic_edited", "forum_topic_closed",
    "forum_topic_reopened", "general_forum_topic_hidden", "general_forum_topic_unhidden",
    "giveaway_created", "giveaway_completed", "giveaway_winners", "service",
    "cb_data", "cb_startswith", "cb_endswith", "cb_contains", "cb_regex",
    "cb_payload", "cb_json", "cb_kvp", "cb_from", "cb_chat", "cb_msg",
    "cb_game", "cb_any",
    "poll_filter", "poll_closed", "poll_open", "poll_question", "poll_contains",
    "poll_regex", "poll_type", "poll_chat", "poll_option", "poll_any", "poll_answer",
    "member_joined", "member_left", "member_banned", "member_unbanned",
    "member_promoted", "member_demoted", "member_restricted", "member_unrestricted",
    "member_status", "member_chat", "member_user", "member_by",
    "member_self", "member_any",
    "update_type", "network", "user", "state", "state_any",
    "any_filter", "none_filter", "func",
    "all_of", "any_of", "none_of", "at_least", "at_most", "exactly", "invert",
    "if_", "unless",
    "once", "limit", "every_n", "cooldown", "throttled",
    "filter_data",
]
