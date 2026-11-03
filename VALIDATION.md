# Validation gates

Classify changed paths with `./scripts/dev classify [paths...]`. Unknown paths
are R3 and an override can only raise risk. Complete logs and a JSON summary
are written to `artifacts/runs/<run-id>/`.

When several agents share this checkout, always pass the paths of your change
and read the `warning: changed path outside requested scope` lines: they name
other sessions' working-tree edits that your gate did not cover, so a clean
gate is never mistaken for a clean tree. Omitting paths classifies the whole
working tree and prints no warning.

Every change, including documentation-only edits, must be reviewed and
validated rigorously: run **all** gates that apply to the change's classified
risk, review the complete diff against the affected invariants, and record a
gate that cannot run as failed instead of skipping it silently. Passing a
subset of the applicable gates does not validate the change.

| Risk | Typical change | Required automated gate | Manual evidence |
| --- | --- | --- | --- |
| R0 | Documentation and metadata | contract: documentation links and anchors, context paths, no suppressions | none |
| R1 | Companion pages, pure logic (Stats, the dashboard filter, archive pages), tests, tooling | R0 + every linter, formatter, the strict type check and the security scan + the whole test suite with its coverage floor, in the test image | as identified |
| R2 | Persistence and migrations, the Web UI relay and screens, the La Marzocco client, the image, compose files, `./setup`, runtime dependencies | R1 + both images rebuilt + runtime pins checked against the image + dependency vulnerability audit | subsystem-dependent |
| R3 | The gateway (TLS, certificates, nginx), pairing, keys and the controller link, the firmware's shared fixtures, unknown paths | R2 + the shared fixtures compared with the firmware checkout | pairing with a real controller required |

The exact path lists live in `RISK_PATHS` in `scripts/dev`; see
[scripts](docs/SCRIPTS.md) for every command and
[static analysis](docs/STATIC_ANALYSIS.md) for what each tool checks.

Use `./scripts/dev validate [--risk R0..R3] [paths...]`. R1 and above run the
static analysis and the tests as two parallel lanes; at R2 and R3 the test
lane first rebuilds the images the tests run in. After a failure no lane
starts another step. Focused commands are
`./scripts/dev test lint|unit|audit|firmware`; `test unit` takes pytest
arguments (`./scripts/dev test unit tests/test_link.py -k erase`), and then
skips the coverage floor, which only the whole suite can meet.

## No suppressions

Findings are fixed, never silenced. No source carries `noqa`,
`type: ignore`, `nosec`, `pragma: no cover`, `eslint-disable`,
`stylelint-disable`, `prettier-ignore`, `shellcheck disable`,
`hadolint ignore`, `yamllint disable` or any other inline switch, and no tool
configuration ignores, excludes or downgrades a rule: no ignore lists, no
per-file ignores, no mypy overrides, no coverage exclusions. The
`suppressions` check enforces both on every gate, R0 included. If a finding
seems impossible or very costly to fix, stop and take the tradeoff to the
owner before touching any configuration. Third-party code is out of scope by
path; the repository has none.

## Dependencies and the network

Missing tools fail the profiles that need them with exit 127, and the message
names the explicit command that adds them. Nothing installs implicitly:

- `uv sync --frozen` installs the Python tools from `uv.lock`;
- `npm ci` installs the web linters from `package-lock.json`;
- `./scripts/dev image` builds the test image (`openbrewbyweight-companion:test`)
  and a runtime image (`openbrewbyweight-companion:validate`, never the `:local`
  tag `./setup` runs), fetching Alpine packages when Docker has not cached them.

The tests run in the test image with `--network none` and the checkout mounted
read-only. Two R2/R3 steps use the network on purpose and say so: the image
builds (Alpine's package index, when not cached) and the audit (the PyPI and
npm vulnerability databases). An offline R2/R3 run fails there; it never skips
them.

`uv.lock` is the single source of every Python package version. The image
installs `requirements/runtime.txt` (and the test image `requirements/test.txt`),
exports of the lock with every hash, so the type checker, the tests, the audit
and the shipped image all use the same versions. The `requirements` check
fails when an export differs from the lock, and `runtime-pins` when the
runtime image holds anything else. To update a package, run
`uv lock --upgrade-package <name>`, export again (the check prints the
command) and rebuild with `./scripts/dev image`. The base image is pinned by
digest in the `Dockerfile`; bump it deliberately for Alpine's updates.

## The firmware and Home Assistant

The companion ships as one product with the firmware and its Home Assistant
integration. `tests/fixtures` holds byte-identical copies of the firmware's
shared test vectors, pinned by hash in the tests; the R3 `firmware-fixtures`
step compares them with a firmware checkout, found through
`OPENBREWBYWEIGHT_FIRMWARE_DIR` or beside this repository as
`Open-Brew-by-Weight`. Without one, R3 fails with exit 127. R3 is not
release-ready while its manual evidence is pending.

## Reading a result

A zero exit code means the automated profile passed, not that the change was
tried against a real controller. Use the printed
`artifacts/runs/<run-id>/summary.json` and its `run.log` to see which steps
ran; `artifacts/runs/latest.json` is the most recent summary. Exit 127 means a
required dependency is missing: record the gate as failed and prepare the
dependency explicitly. Failed runs keep their evidence; steps that never
started leave no entry.

Classify concrete files, not a directory name. Do not lower risk to avoid an
unavailable tool or missing physical evidence.
