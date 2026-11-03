# Script reference

`./scripts/dev` is the single developer entry point. It needs Python 3.11 or
newer to start, never installs anything, and the tests it runs never use the
network. The [validation policy](../VALIDATION.md) says which gate a change
needs; [static analysis](STATIC_ANALYSIS.md) describes each tool.

## Prepare once

Install the pinned tools explicitly, then build the images:

```bash
uv sync --frozen
npm ci
./scripts/dev image
```

`uv sync --frozen` creates `.venv/` from `uv.lock` (the runtime packages at
the image's versions, plus ruff, mypy, bandit, pytest, coverage, pip-audit,
yamllint, shellcheck, shfmt and hadolint); `uv` also exports the lock for the
`requirements` check. `npm ci` installs Prettier, ESLint,
Stylelint and html-validate from `package-lock.json` into `node_modules/`.
`./scripts/dev image` builds the test image and a runtime image; run it again
after any change to the `Dockerfile` (the test profiles say so when the test
image predates it). `./scripts/dev doctor` lists every tool with its version
and whether the test image is current.

## Commands

| Task | Command |
| --- | --- |
| Report the tools | `./scripts/dev doctor` |
| List an area's focused paths | `./scripts/dev context gateway` |
| Classify paths | `./scripts/dev classify [PATH ...]` |
| Validate a change | `./scripts/dev validate [--risk R0..R3] [PATH ...]` |
| Run every linter and checker | `./scripts/dev test lint` |
| Run the tests with coverage | `./scripts/dev test unit` |
| Run some tests | `./scripts/dev test unit tests/test_link.py -k erase` |
| Audit the dependencies | `./scripts/dev test audit` |
| Compare the shared fixtures with the firmware | `./scripts/dev test firmware` |
| Build the images | `./scripts/dev image` |
| Run one contract check | `./scripts/dev check docs` |
| Remove run artifacts | `./scripts/dev clean --confirm` |

`--verbosity compact|normal|verbose` comes before the command. It defaults to
`normal` on a terminal and `compact` otherwise (`OPENBREWBYWEIGHT_VERBOSITY`
sets the default). Compact prints the outcome and the failing step's output.

## Profiles

`test lint` runs, in order:

| Step | What it runs |
| --- | --- |
| `suppressions` | no inline suppression in any source, no relaxed tool configuration |
| `ruff`, `ruff-format` | `ruff check` and `ruff format --check` on every Python source and `scripts/dev` |
| `mypy` | `mypy --strict` on `companion/`, `gateway/`, `tests/` and `scripts/` |
| `bandit` | the security scan of the code that ships: `companion/` and `gateway/` |
| `shellcheck`, `shfmt` | `./setup` and `gateway/entrypoint.sh` |
| `hadolint` | the `Dockerfile` |
| `yamllint` | the compose files and `.yamllint.yaml` |
| `compose` | `docker compose config` for each supported network setup, with `.env.example` |
| `requirements` | `requirements/runtime.txt` and `requirements/test.txt` are exactly what `uv.lock` exports |
| `web-format` | `prettier --check` on the pages, `gateway/strings.json`, `package.json` and `scripts/lint/` |
| `eslint`, `stylelint` | the scripts and styles inside the companion's three pages |
| `render-pages`, `html-validate` | renders every page as served, in every setup-page language, then validates the markup; the rendered pages stay in the run's `pages/` folder |

`test unit` runs pytest under coverage in the test image, with
`--network none` and the checkout mounted read-only at `/src`, and fails below
the coverage floor (`COVERAGE_FAIL_UNDER` in `scripts/dev`). With pytest
arguments it runs only those tests, without coverage.

`test audit` exports `uv.lock` with its hashes and runs `pip-audit` on every
locked package, then `npm audit` on `package-lock.json`. Both query public
vulnerability databases, so this profile needs the network.

`test firmware` compares each file in `tests/fixtures` that the firmware owns
with the firmware checkout (`OPENBREWBYWEIGHT_FIRMWARE_DIR`, or
`Open-Brew-by-Weight` beside this repository).

`image` builds `--target test` as `openbrewbyweight-companion:test` and the
shipped stage as `openbrewbyweight-companion:validate`, both labeled with the
hash of the `Dockerfile` and `requirements/`, then checks that the runtime
image's Python packages are exactly `requirements/runtime.txt`
(`runtime-pins`).

`validate` runs the R0 contract checks in process; at R1 and above it runs
`test lint` and `test unit` as two parallel lanes; R2 adds the audit to the
first lane and the image build before the tests; R3 adds the firmware
fixtures. The [risk table](../VALIDATION.md) lists the paths.

## Run artifacts

Every command except `check` writes `artifacts/runs/<run-id>/run.log` (the
complete output, secrets redacted) and `summary.json`: the command, risk,
status (`passed`, `failed` or `missing_dependency`), commit, duration, each
step's status and any manual validation still pending.
`artifacts/runs/latest.json` repeats the last summary. Exit codes: 0 passed,
1 failed, 2 invalid arguments, 127 a missing dependency.

## Web page formatting

The pages are formatted with the Prettier version pinned in `package.json`:
run `npm run format:web` after editing them, and `npm run format:web:check`
to check without writing. Python is formatted with `.venv/bin/ruff format`.
