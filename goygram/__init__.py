# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
from importlib.metadata import PackageNotFoundError, version as pkg_version

from .client import GoyGram
from .errors import StopPropagation
from .session import Session
from .utils import print_methods
from .types.kbd import KbdBuilder
from .types.member import MemberObj
from .types.poll import PollObj

__all__ = ["GoyGram", "Session", "StopPropagation", "KbdBuilder", "PollObj", "MemberObj", "print_methods"]

from . import filters

try:
    __version__ = pkg_version("goygram")
except PackageNotFoundError:
    __version__ = "0.0.0"
