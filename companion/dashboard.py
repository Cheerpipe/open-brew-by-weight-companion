"""La Marzocco's dashboard reduced to exactly what the controller's decoder reads.

The controller runs decodeMicraDashboard on the reduced object, so the filter
keeps La Marzocco's own shape and values and only drops keys: values are never
checked or converted here, and each event is filtered on its own (no diffing).
"""

import json

WIDGETS = {
    "CMMachineStatus": ("mode",),
    "CMCoffeeBoiler": ("status", "targetTemperature", "readyStartTime"),
    "CMSteamBoilerLevel": ("status", "targetLevel", "readyStartTime"),
    "CMBackFlush": ("status",),  # Only from pushes, as the direct decoder enforces.
}
CONSUMED = {"connected", "widgets", "removedWidgets", "code", "output"}.union(*WIDGETS.values())


def _unique(pairs):
    keys = [key for key, _ in pairs]
    if any(keys.count(key) > 1 for key in CONSUMED.intersection(keys)):
        raise ValueError("a consumed key is repeated")  # The controller rejects these too.
    return dict(pairs)


def parse(text):
    """La Marzocco JSON payload; ValueError when it is not an object or repeats a consumed key."""
    value = json.loads(text, object_pairs_hook=_unique)
    if not isinstance(value, dict):
        raise ValueError("not a JSON object")
    return value


def _code(entry):
    return entry if isinstance(entry, str) else entry.get("code") if isinstance(entry, dict) else None


def reduce(dashboard, push):
    """The consumed fields this event carries, or None when it carries none."""
    codes = WIDGETS if push else {code: keys for code, keys in WIDGETS.items() if code != "CMBackFlush"}
    reduced = {"connected": dashboard["connected"]} if "connected" in dashboard else {}
    widgets = []
    for widget in dashboard.get("widgets") if isinstance(dashboard.get("widgets"), list) else ():
        keys = codes.get(_code(widget)) if isinstance(widget, dict) else None
        output = widget.get("output") if keys else None
        kept = {key: output[key] for key in keys if key in output} if isinstance(output, dict) else None
        if kept:
            widgets.append({"code": widget["code"], "output": kept})
    removed = [_code(entry) for entry in dashboard.get("removedWidgets") or () if _code(entry) in codes] \
        if isinstance(dashboard.get("removedWidgets"), list) else []
    if widgets:
        reduced["widgets"] = widgets
    if removed:
        reduced["removedWidgets"] = removed
    return reduced or None


def confirms(dashboard, op, value):
    """True when a push shows the outcome of an accepted command."""
    for widget in dashboard.get("widgets") if isinstance(dashboard.get("widgets"), list) else ():
        output = widget.get("output") if isinstance(widget, dict) else None
        if not isinstance(output, dict):
            continue
        if op == "temp" and widget.get("code") == "CMCoffeeBoiler":
            target = output.get("targetTemperature")
            if isinstance(target, (int, float)) and not isinstance(target, bool) and round(target * 10) == value:
                return True
        if op in ("standby", "on") and widget.get("code") == "CMMachineStatus":
            if output.get("mode") == ("StandBy" if op == "standby" else "BrewingMode"):
                return True
    return False
