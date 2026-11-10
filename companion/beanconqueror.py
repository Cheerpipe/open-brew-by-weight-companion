"""Beanconqueror machine endpoints from the archive (the firmware's docs/schemas/README.md,
"Beanconqueror machine endpoints v1"): one good shot as a Gaggiuino or a GaggiMate serves it.

Pure: an archived Stats row in, JSON or bytes out, pinned by
tests/fixtures/beanconqueror-v1.vectors.json (byte-identical to the firmware's). The flow is
the Stats page's (runtime.js buildShotSparkModel), with the same IEEE operations in the same
order as the firmware's port, so both serve the same bytes."""

import base64
import math
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

FORMATS = ("off", "gaggiuino", "gaggimate")


@dataclass(frozen=True)
class Shot:
    """What both formats send, from a good row."""

    id: int
    start: int  # Unix s, 0 without wall time
    duration_ds: int
    yield_cg: int
    dose_dg: int
    temp_deci_c: int
    avg_flow_cgs: int
    first_drop_ds: int | None
    preset_id: int
    rating: int
    preset_name: str


def _half_up(value: float) -> int:
    return math.floor(value + 0.5)


def _number(row: Mapping[str, object], key: str) -> float | None:
    value = row.get(key)
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else None


def shot_of(row: Mapping[str, object]) -> Shot | None:
    """The shot a good row serves; None for a bad one."""
    if row.get("badReason"):
        return None
    duration_ds = _half_up((_number(row, "durationS") or 0) * 10)
    unix = _number(row, "endedAtUnixSec") or 0
    start = (int(unix) * 10 - duration_ds + 5) // 10 if row.get("hasWallTime") and unix > 0 else 0
    drop = _number(row, "firstDropS")
    flow = _number(row, "avgFlowGS")
    return Shot(
        id=int(_number(row, "id") or 0),
        start=start,
        duration_ds=duration_ds,
        yield_cg=_half_up((_number(row, "actualG") or 0) * 100),
        dose_dg=_half_up((_number(row, "doseG") or 0) * 10),
        temp_deci_c=int(_number(row, "targetTempDeciC") or 0),
        avg_flow_cgs=0 if flow is None else _half_up(flow * 100),
        first_drop_ds=None if drop is None else _half_up(drop * 10),
        preset_id=int(_number(row, "presetId") or 0),
        rating=int(_number(row, "rating") or 0),
        preset_name=str(row.get("presetName") or ""),
    )


def points(row: Mapping[str, object]) -> list[tuple[int, int]]:
    """The curve's readings (ms, cg): the vectors' arrays, or the archive's `wD` stream (a time
    step of one byte, or 255 then the absolute LE uint16; a weight step of one signed byte, or
    -128 then the absolute LE int16; from 0 ms and 0 cg)."""
    at, cg = row.get("wAtMs"), row.get("wCg")
    if isinstance(at, list) and isinstance(cg, list):
        return [(int(t), int(w)) for t, w in zip(at, cg, strict=True)]
    encoded = row.get("wD")
    data = base64.b64decode(encoded) if isinstance(encoded, str) else b""
    out, t, w, i = [], 0, 0, 0
    while i + 1 < len(data):
        if data[i] == 0xFF:
            t, i = int.from_bytes(data[i + 1 : i + 3], "little"), i + 3
        else:
            t, i = t + data[i], i + 1
        if i >= len(data):
            break
        if data[i] == 0x80:
            w, i = int.from_bytes(data[i + 1 : i + 3], "little", signed=True), i + 3
        else:
            w = (w + struct.unpack("b", data[i : i + 1])[0] + 0x8000) % 0x10000 - 0x8000
            i += 1
        out.append((t, w))
    return out


def _ms(row: Mapping[str, object], key: str) -> int | None:
    seconds = _number(row, key)
    return None if seconds is None else _half_up(seconds * 1000)


def flow(row: Mapping[str, object], shot: Shot) -> list[tuple[int, int]]:
    """(tenths, hundredths) of g/s per reading, (0, 0) where the Stats page has no flow."""
    readings = points(row)
    breaks = set(_ints(row.get("wBreakBefore")))
    held = set(_ints(row.get("wHeld")))
    end, atm, clear = _ms(row, "endS"), _ms(row, "atmS"), _ms(row, "atmClearedS")
    limit = end if end is not None else shot.duration_ds * 100
    drop = _ms(row, "dropS")
    if drop is None and shot.first_drop_ds is not None:
        drop = shot.first_drop_ds * 100
    observations: list[tuple[int, int, int, int]] = []  # t, cg, index, segment
    touched: list[list[int]] = []
    segment = 0
    for i, (t, cg) in enumerate(readings):
        if i in breaks:
            segment += 1
        if t > limit and end is None:
            continue
        if i in held:
            if touched and touched[-1][1] >= t - 500:
                touched[-1][1] = t
            else:
                touched.append([t - 500, t])
            continue
        if atm is not None and t >= atm and (clear is None or t < clear):
            segment += 1
            continue
        last = observations[-1] if observations else None
        if last and atm is not None and last[0] < atm <= t:
            segment += 1
        if last and clear is not None and last[0] < clear <= t:
            segment += 1
        if last and last[3] == segment and last[0] == t:
            observations[-1] = (t, cg, i, segment)
        else:
            observations.append((t, cg, i, segment))
    out = [(0, 0)] * len(readings)
    boundary = 0
    for i, (t, cg, index, seg) in enumerate(observations):
        if not i or seg != observations[i - 1][3]:
            boundary = i
            continue
        span = max(1000, t - observations[i - 1][0])
        start = t - span
        while boundary + 1 < i and observations[boundary + 1][0] <= start:
            boundary += 1
        a, b = observations[boundary], observations[boundary + 1]
        if (
            a[3] != seg
            or a[0] > start
            or (drop is not None and a[0] < drop)
            or any(start <= to and t >= frm for frm, to in touched)
        ):
            continue
        start_cg = float(a[1])
        if a[0] != start:
            scaled = float((b[1] - a[1]) * (start - a[0]))
            step = scaled / (b[0] - a[0])
            start_cg = a[1] + step
        gain = cg - start_cg
        gain10 = gain * 10
        rate = max(0.0, gain10 / span)
        out[index] = (math.floor(rate * 10 + 0.5), min(32767, math.floor(rate * 100 + 0.5)))
    return out


def _ints(value: object) -> list[int]:
    return [int(v) for v in value] if isinstance(value, list) else []


def _samples(row: Mapping[str, object]) -> list[tuple[int, int, int]]:
    """Each non-held reading in order: (index, ms, cg)."""
    held = set(_ints(row.get("wHeld")))
    return [(i, t, cg) for i, (t, cg) in enumerate(points(row)) if i not in held]


def _dg(cg: int) -> int:
    return 0 if cg < 0 else (cg + 5) // 10


def gaggiuino_shot(row: Mapping[str, object], shot: Shot) -> dict[str, object]:
    rates, samples, temp = flow(row, shot), _samples(row), shot.temp_deci_c
    answer: dict[str, object] = {"id": shot.id}
    if shot.start:
        answer["timestamp"] = shot.start
    answer["duration"] = shot.duration_ds
    tenths = [rates[i][0] for i, _, _ in samples]
    zeros = [0] * len(samples)
    answer["datapoints"] = {
        "timeInShot": [(t + 50) // 100 for _, t, _ in samples],
        "pressure": zeros,
        "pumpFlow": tenths,
        "weightFlow": tenths,
        "temperature": [temp] * len(samples),
        "shotWeight": [_dg(cg) for _, _, cg in samples],
        "waterPumped": zeros,
        "targetTemperature": [temp] * len(samples),
        "targetPumpFlow": zeros,
        "targetPressure": zeros,
    }
    answer["profile"] = {
        "id": shot.preset_id,
        "name": shot.preset_name,
        "waterTemperature": temp / 10,
    }
    return answer


def _c_string(text: str, most: int, field: int) -> bytes:
    data = text.encode()
    if len(data) > most:
        n = most
        while n > 0 and data[n] & 0xC0 == 0x80:  # never split a character
            n -= 1
        data = data[:n]
    return data.ljust(field, b"\0")


def index_entry(shot: Shot) -> bytes:
    return (
        struct.pack(
            "<IIIHBB",
            shot.id,
            shot.start,
            shot.duration_ds * 100,
            _dg(shot.yield_cg),
            shot.rating,
            0x01 | (0x04 if shot.dose_dg else 0),
        )
        + _c_string(str(shot.preset_id), 31, 32)
        + _c_string(shot.preset_name, 47, 48)
        + struct.pack("<HHH", 0, 0, shot.avg_flow_cgs)
        + bytes(26)
    )


def index(shots: Sequence[Shot], next_id: int) -> bytes:
    """A SIDX v1 index of `shots`, newest first."""
    head = struct.pack("<IHHII", 0x58444953, 1, 128, len(shots), next_id) + bytes(16)
    return head + b"".join(index_entry(shot) for shot in shots)


def slog(row: Mapping[str, object], shot: Shot) -> bytes:
    rates, samples = flow(row, shot), _samples(row)
    head = (
        struct.pack(
            "<IBBHHHIIII",
            0x544F4853,
            7,
            30,
            512,
            50,
            0,
            0x3FFF,
            len(samples),
            shot.duration_ds * 100,
            shot.start,
        )
        + _c_string(str(shot.preset_id), 31, 32)
        + _c_string(shot.preset_name, 47, 48)
        + struct.pack("<H", _dg(shot.yield_cg))
    )
    body = b"".join(
        struct.pack("<IH", t, shot.temp_deci_c)
        + bytes(12)
        + struct.pack("<hH", rates[i][1], min(0xFFFF, _dg(cg)))
        + bytes(8)
        for i, t, cg in samples
    )
    return head.ljust(512, b"\0") + body


def notes(shot: Shot) -> dict[str, str] | None:
    """The shot's notes: its dose, as GaggiMate keeps it (text); None without one."""
    if not shot.dose_dg:
        return None
    return {"id": str(shot.id), "doseIn": f"{shot.dose_dg // 10}.{shot.dose_dg % 10}"}


def good_shots(rows: Iterable[Mapping[str, object]]) -> list[tuple[Mapping[str, object], Shot]]:
    """The good rows with their shots, in the order given."""
    return [(row, shot) for row in rows if (shot := shot_of(row)) is not None]
