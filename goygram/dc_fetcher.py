# CopyLeft 2026 github.com/sepiol026-wq | telegram:@samsepi0l_ovf. Licensed under AGPLv3.
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DcEndpoint:
    dc_id: int
    host: str
    port: int


def get_dynamic_dc_config(timeout: int = 6) -> dict[int, list[DcEndpoint]]:
    _ = timeout
    by_dc: dict[int, list[DcEndpoint]] = {
        1: [DcEndpoint(dc_id=1, host="149.154.175.53", port=443)],
        2: [DcEndpoint(dc_id=2, host="149.154.167.50", port=443)],
        3: [DcEndpoint(dc_id=3, host="149.154.175.100", port=443)],
        4: [DcEndpoint(dc_id=4, host="149.154.167.91", port=443)],
        5: [DcEndpoint(dc_id=5, host="91.108.56.130", port=443)],
    }
    by_dc[0] = by_dc[2]
    return by_dc


def pick_dc_endpoint(dc_map: dict[int, list[DcEndpoint]], preferred_dc: int | None = None) -> DcEndpoint:
    if preferred_dc is not None and preferred_dc in dc_map and dc_map[preferred_dc]:
        return dc_map[preferred_dc][0]
    if 0 in dc_map and dc_map[0]:
        return dc_map[0][0]
    for dc_id in (2, 1, 4, 5, 3):
        if dc_id in dc_map and dc_map[dc_id]:
            return dc_map[dc_id][0]
    raise RuntimeError("No available endpoint in DC map")
