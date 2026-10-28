#!/usr/bin/env python3
"""./setup renames the HTTPS gateway's settings in an existing .env (bash, no Docker)."""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

if not __debug__:
    raise SystemExit("assertions are disabled (PYTHONOPTIMIZE); these checks would not run")
if not shutil.which("bash"):
    raise SystemExit("bash is not on the PATH; ./setup needs it")

ROOT = Path(__file__).resolve().parents[1]
OLD = """# Free address for the gateway
GATEWAY_IP=192.168.1.240
LAN_INTERFACE=eth0
GATEWAY_HOSTNAME=espresso
# GATEWAY_DATA=./data
MDNS_PUBLISH=false
HTTP_PORT=8080
HTTPS_PORT=8443
OBBW_CONTROLLER_URL=http://192.168.1.50
"""
NEW = """# Free address for the gateway
COMPANION_IP=192.168.1.240
LAN_INTERFACE=eth0
COMPANION_HOSTNAME=espresso
# COMPANION_DATA=./data
COMPANION_MDNS_PUBLISH=false
COMPANION_HTTP_PORT=8080
COMPANION_HTTPS_PORT=8443
OBBW_CONTROLLER_URL=http://192.168.1.50
"""

with tempfile.TemporaryDirectory(prefix="openbrewbyweight-setup-") as temporary:
    folder, tools = Path(temporary) / "companion", Path(temporary) / "bin"
    folder.mkdir()
    tools.mkdir()
    shutil.copy(ROOT / "setup", folder / "setup")
    # A docker that cannot reach its daemon: ./setup stops right after the migration.
    (tools / "docker").write_text("#!/bin/sh\nexit 1\n")
    (tools / "docker").chmod(0o755)
    env = {**os.environ, "PATH": f"{tools}:{os.environ['PATH']}"}

    def run():
        return subprocess.run(["bash", str(folder / "setup"), "--yes"], env=env, capture_output=True,
                              text=True, stdin=subprocess.DEVNULL)

    (folder / ".env").write_text(OLD)
    result = run()
    assert result.returncode == 1 and "cannot use Docker" in result.stderr, result
    assert "Renamed the settings" in result.stdout
    assert (folder / ".env").read_text() == NEW
    assert (folder / ".env.bak").read_text() == OLD, "the earlier file is kept"

    (folder / ".env.bak").unlink()
    result = run()
    assert "Renamed" not in result.stdout and (folder / ".env").read_text() == NEW
    assert not (folder / ".env.bak").exists(), "an already migrated .env is left alone"

print("Setup: .env migration OK")
