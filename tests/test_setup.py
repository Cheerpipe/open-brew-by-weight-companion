#!/usr/bin/env python3
"""./setup with a fake Docker: the .env migration, and the controller search with its step messages."""

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

# The controller search, against a fake Docker whose companion finds nothing over mDNS. The scenarios
# run at once because each waits out the real 20 s mDNS step.
FAKE_DOCKER = r"""#!/bin/sh
state=$FAKE_STATE
case "$*" in
info | "compose build" | "compose ps"* | "rm "* | "ps -aq"*) [ "$1" = compose ] && [ "$2" = ps ] && echo id ;;
"compose version --short") echo 2.30.0 ;;
"version -f"*) echo 27.0 ;;
"compose up"*)
	echo "$*" >>"$state/up"
	case "$*" in *--force-recreate*) touch "$state/restarted" ;; esac ;;
*"gateway.py check"*)
	echo "ok setup-page"
	if [ -f "$state/restarted" ]; then echo "ok controller openbrewbyweight 192.168.4.194:80 scan"; exit 0; fi
	echo "fail controller not found yet"
	exit 1 ;;
*"gateway.py scan") echo scan >>"$state/scans"; cat "$state/scan" ;;
*"python3 -c"*) echo http://openbrewbyweight-secure.local ;;
esac
exit 0
"""
SCENARIOS = {
    "one": "range 192.168.4.0/24 253 9\ncontroller 192.168.4.194 1.1.0+abc openbrewbyweight\n",
    "several": "range 192.168.4.0/24 253 9\ncontroller 192.168.4.20 1.0.0 Cafe Bar\n"
               "controller 192.168.4.194 1.1.0 openbrewbyweight\n",
    "twins": "range 192.168.4.0/24 253 9\ncontroller 192.168.4.20 1.0.0 openbrewbyweight\n"
             "controller 192.168.4.194 1.1.0 openbrewbyweight\n",
    "none": "range 192.168.4.0/24 253 9\n",
    "skip": "skip 172.17.0.0/16 is larger than /22\n",
}
with tempfile.TemporaryDirectory(prefix="openbrewbyweight-setup-") as temporary:
    runs = {}
    for name, scan in SCENARIOS.items():
        folder, tools, state = (Path(temporary) / name / part for part in ("companion", "bin", "state"))
        for path in (folder, tools, state):
            path.mkdir(parents=True)
        shutil.copy(ROOT / "setup", folder / "setup")
        (folder / ".env").write_text(NEW)
        (state / "scan").write_text(scan)
        for tool, body in (("docker", FAKE_DOCKER), ("ip", "#!/bin/sh\nexit 0\n")):
            (tools / tool).write_text(body)
            (tools / tool).chmod(0o755)
        env = {**os.environ, "PATH": f"{tools}:{os.environ['PATH']}", "FAKE_STATE": str(state)}
        runs[name] = (folder, state, subprocess.Popen(
            ["bash", str(folder / "setup"), "--yes"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL, text=True))
    results = {}
    for name, (folder, state, process) in runs.items():
        out, err = process.communicate(timeout=120)
        results[name] = (process.returncode, out, err, (folder / ".env").read_text(), state)

    code, out, err, env_file, state = results["one"]
    assert code == 0, (out, err)
    steps = [line.strip() for line in out.splitlines() if line.startswith("  ")]
    expected = ["Building the companion image (about a minute the first time)…", "Image ready (",
                "Starting the companion…", "Running (", "Looking for the controller over mDNS (up to 20 s)…",
                "Not found over mDNS (2", "Searching 192.168.4.0/24 for a controller (253 addresses, about 9 s)…",
                'Found Open Brew by Weight "openbrewbyweight" at 192.168.4.194, firmware 1.1.0+abc (',
                "Starting the companion…", "Running (",
                'Using "openbrewbyweight" at 192.168.4.194, found by searching your network.']
    assert [line[:len(want)] for line, want in zip(steps[1:], expected)] == expected, steps
    assert "OBBW_CONTROLLER_URL=http://192.168.1.50" in env_file, "the search sets nothing in .env"
    assert (state / "up").read_text().splitlines()[-1].endswith("--force-recreate"), "restarted to use it"

    code, out, err, env_file, state = results["several"]
    assert code == 0 and "Found 2 controllers (" in out, (out, err)
    assert '1. "Cafe Bar" at 192.168.4.20 (firmware 1.0.0)' in out
    assert '2. "openbrewbyweight" at 192.168.4.194 (firmware 1.1.0)' in out
    assert env_file.splitlines()[-1] == "OBBW_CONTROLLER_NAME=Cafe Bar", "--yes takes the first one"

    code, out, err, env_file, state = results["twins"]
    assert code == 0 and 'More than one controller is called "openbrewbyweight"' in out, (out, err)
    assert "OBBW_CONTROLLER_URL=http://192.168.4.20" in env_file, "same names: its address instead"

    code, out, err, env_file, state = results["none"]
    assert code == 1 and "No controller answered (" in out and "Set OBBW_CONTROLLER_URL" in err, (out, err)
    code, out, err, env_file, state = results["skip"]
    assert code == 1 and "Not searching your network for it: 172.17.0.0/16 is larger than /22." in out, out
    assert "Searching" not in out and "Set OBBW_CONTROLLER_URL" in err
    assert all((result[4] / "scans").read_text().count("scan") == 1 for result in results.values()), \
        "one search per ./setup run"

print("Setup: .env migration and controller search OK")
