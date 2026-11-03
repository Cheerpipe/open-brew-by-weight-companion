# Static analysis

What `./scripts/dev test lint` checks, with which configuration, and why. The
[validation policy](../VALIDATION.md) runs it at R1 and above; the
[script reference](SCRIPTS.md) lists its steps. Every tool is pinned:
the Python ones in `uv.lock`, the web ones in `package-lock.json`. Every
finding fails the run, warnings included, and nothing is suppressed (see
[No suppressions](../VALIDATION.md#no-suppressions)).

## Python

Scope: `companion/`, `gateway/`, `tests/` and `scripts/`, including
`scripts/dev`. The project's width is 100 columns, as Prettier's is.

**Ruff** (`[tool.ruff]` in `pyproject.toml`) formats every source and lints
it with a curated set of rule families, the way the firmware's clang-tidy
enables its bugprone, performance, modernize and analyzer families: every
selected rule passes on the whole tree.

| Selected | Covers |
| --- | --- |
| `F`, `E`, `W`, `PLE` | errors: undefined names, unused imports, syntax and runtime errors |
| `B`, `PLW`, `ARG`, `BLE`, `DTZ`, `ISC`, `RUF` | likely bugs: mutable defaults, loop closures, unused arguments, blind `except`, naive datetimes, string concatenation slips |
| `ASYNC` | asyncio pitfalls: blocking calls in coroutines, busy waits, timeouts |
| `LOG`, `G` | logging misuse and eager formatting |
| `UP`, `FURB`, `PTH`, `C4`, `SIM`, `PIE`, `FLY`, `RET`, `RSE`, `PERF` | modern idioms, `pathlib`, simpler code, performance |
| `I`, `N`, `A`, `PLC`, `TID`, `TC`, `EXE`, `YTT`, `T10`, `SLOT`, `ERA` | imports, naming, shadowed builtins, shebangs, debugger calls, commented-out code |
| `PT` | pytest idioms: one condition per assert, `pytest.raises` |
| `PGH` | blanket `noqa` and `type: ignore` |

Families not selected, and why:

- `S` (flake8-bandit): Bandit runs the same checks as its own step, on the
  code that ships. Its assert rule would also forbid pytest's own assert
  idiom in the tests.
- `ANN`: `mypy --strict` already requires every annotation.
- `D` (docstring conventions), `CPY` (license headers), `T20` (print), `EM`,
  `TRY003`, `FBT`, `COM`, `Q`: documentation, output and style conventions
  that the formatter or the project's own style decide.
- `PLR`, `C90` (complexity limits, magic values), `SLF` (private access): the
  companion's protocol handlers follow the firmware's structure and constants,
  and the tests reach into the objects they check.

**mypy** (`[tool.mypy]`) runs `--strict` with `warn_unreachable` and the
`deprecated`, `possibly-undefined`, `redundant-expr`, `truthy-bool` and
`unused-awaitable` error codes, against the runtime packages at the versions
the image ships.

**Bandit** scans `companion/` and `gateway/`, the code that runs on the
user's server. That code starts no process: certificates come from the
`cryptography` library, QR codes from `segno`, and the entrypoint, not
Python, runs nginx. The tests run offline inside the test image and are not
part of its scope.

## Web pages

The companion's three pages, `companion/page.html`, `companion/ui-off.html`
and `gateway/setup.html`, carry their own styles and scripts. Their
`@NAME@` placeholders are filled when they are served; the shared style of
`setup.html` replaces the `/* @STYLE@ */` comment in the other two.

- **Prettier** (`package.json`) formats the pages, `gateway/strings.json`,
  `package.json` and `scripts/lint/` at 100 columns.
- **ESLint** (`scripts/lint/eslint.config.mjs`) runs its full recommended set
  on the pages' scripts, through `eslint-plugin-html`, and on its own
  configuration. Inline configuration comments are refused.
- **Stylelint** (`scripts/lint/stylelint.json`) runs `stylelint-config-standard`
  on the pages' styles through `postcss-html`. One option is set: media
  queries use the `min-width` prefix notation, because the range notation
  needs Safari 16.4 and the pages, like the firmware Web UI, support Safari
  and iOS 15.4.
- **html-validate** (`scripts/lint/htmlvalidate.json`, the firmware's
  configuration) runs every recommended and accessibility rule on the pages
  as the companion serves them: `scripts/render_pages.py` renders them with
  the production code, the setup page in every language of
  `gateway/strings.json`.

## Shell, containers and YAML

- **ShellCheck** and **shfmt** check `./setup` and `gateway/entrypoint.sh`
  (tabs, shfmt's defaults).
- **hadolint** checks the `Dockerfile`: the base is pinned by digest, the
  software packages by minor version (`nginx~1.30`), and the yearly data
  packages (`tzdata`, `ca-certificates`) by a minimum version.
- **yamllint** (`.yamllint.yaml`) runs its default rule set at 100 columns on
  the compose files.
- `docker compose config` renders the project for each supported network
  setup (`compose.yaml` alone, with `compose.host.yaml`, and with
  `compose.existing-network.yaml`) from `.env.example`.

## Dependencies

`./scripts/dev test audit` runs `pip-audit` on every package `uv.lock` pins,
by hash, which are the packages the image ships, and `npm audit` on
`package-lock.json`. `package.json` overrides
`minimatch` to 11.0.4, the first release without GHSA-g3hv-75wg-m249, until
ESLint's own range allows it.
