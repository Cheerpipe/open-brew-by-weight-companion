"""La Marzocco's dashboard reduced to exactly what the controller's decoder reads.

The controller runs decodeMicraDashboard on the reduced object, so the filter
keeps La Marzocco's own shape and values and only drops keys: values are never
checked or converted here, and each event is filtered on its own (no diffing).
"""

import json
from typing import TYPE_CHECKING, TypedDict

if TYPE_CHECKING:
    from collections.abc import Mapping

WIDGETS = {
    "CMMachineStatus": ("mode",),
    "CMCoffeeBoiler": ("status", "targetTemperature", "readyStartTime"),
    "CMSteamBoilerLevel": ("status", "targetLevel", "readyStartTime"),
    # The Linea Mini's steam boiler: the controller reads no steam temperature.
    "CMSteamBoilerTemperature": ("status", "readyStartTime"),
    "CMBackFlush": ("status",),  # Only from pushes, as the direct decoder enforces.
}
CONSUMED = {"connected", "widgets", "removedWidgets", "code", "output"}.union(*WIDGETS.values())


class Reduced(TypedDict, total=False):
    """What reduce keeps of one event."""

    connected: object
    widgets: list[dict[str, object]]
    removedWidgets: list[str]


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    keys = [key for key, _ in pairs]
    if any(keys.count(key) > 1 for key in CONSUMED.intersection(keys)):
        raise ValueError("a consumed key is repeated")  # The controller rejects these too.
    return dict(pairs)


def parse(text: str) -> dict[str, object]:
    """La Marzocco JSON payload; ValueError when it is not an object or repeats a consumed key."""
    value = json.loads(text, object_pairs_hook=_unique)
    if not isinstance(value, dict):
        raise ValueError("not a JSON object")
    return value


def _code(entry: object) -> str | None:
    code = entry.get("code") if isinstance(entry, dict) else entry
    return code if isinstance(code, str) else None


def reduce(dashboard: Mapping[str, object], push: bool) -> Reduced | None:
    """The consumed fields this event carries, or None when it carries none."""
    codes = (
        WIDGETS if push else {code: keys for code, keys in WIDGETS.items() if code != "CMBackFlush"}
    )
    reduced: Reduced = {"connected": dashboard["connected"]} if "connected" in dashboard else {}
    widgets: list[dict[str, object]] = []
    listed = dashboard.get("widgets")
    for widget in listed if isinstance(listed, list) else ():
        code = _code(widget) if isinstance(widget, dict) else None
        keys = None if code is None else codes.get(code)
        output = widget.get("output") if keys else None
        kept = (
            {key: output[key] for key in keys if key in output}
            if keys and isinstance(output, dict)
            else None
        )
        if kept:
            widgets.append({"code": widget["code"], "output": kept})
    gone = dashboard.get("removedWidgets")
    removed = (
        [code for code in map(_code, gone) if code is not None and code in codes]
        if isinstance(gone, list)
        else []
    )
    if widgets:
        reduced["widgets"] = widgets
    if removed:
        reduced["removedWidgets"] = removed
    return reduced or None


def confirms(dashboard: Mapping[str, object], op: str, value: int | None) -> bool:
    """True when a push shows the outcome of an accepted command."""
    listed = dashboard.get("widgets")
    for widget in listed if isinstance(listed, list) else ():
        output = widget.get("output") if isinstance(widget, dict) else None
        if not isinstance(output, dict):
            continue
        if op == "temp" and widget.get("code") == "CMCoffeeBoiler":
            target = output.get("targetTemperature")
            if (
                isinstance(target, (int, float))
                and not isinstance(target, bool)
                and round(target * 10) == value
            ):
                return True
        if (
            op in ("standby", "on")
            and widget.get("code") == "CMMachineStatus"
            and output.get("mode") == ("StandBy" if op == "standby" else "BrewingMode")
        ):
            return True
    return False
