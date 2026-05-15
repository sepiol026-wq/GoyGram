# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
from __future__ import annotations

import logging
import os


def get_logger(name: str = "goygram") -> logging.Logger:
    level_name = os.getenv("GOYGRAM_LOG", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(level=level, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    logger = logging.getLogger(name)
    logger.setLevel(level)
    return logger
