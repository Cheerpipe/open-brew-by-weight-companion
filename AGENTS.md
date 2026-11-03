# Repository agent rules

## Language

Reason, plan, and write internal notes in English, regardless of the language
used in the prompt. Write the final user-facing reply in the same language as
the user's prompt.

English is the project's only content language: code, comments, documentation,
user-facing text, UI copy, tests, and commit messages are written in English,
no matter the language of the prompt. Never add content in any other language
to the project's artifacts; the only exceptions are proper nouns and test
fixtures that deliberately exercise non-English characters.

## Validation

Follow [the validation policy](VALIDATION.md) for every change, documentation
included:

- Classify the paths of your change with `./scripts/dev classify <paths>` and
  run `./scripts/dev validate <paths>`; never lower the risk. Read the
  `changed path outside requested scope` warnings: another session's edits are
  not covered by your gate.
- Run every gate the classified risk requires. A gate that cannot run (exit
  127, a missing tool, image or firmware checkout, no network for the R2/R3
  audit) is a failed gate: report it as failed, never as skipped, and prepare
  the dependency explicitly (`uv sync --frozen`, `npm ci`,
  `./scripts/dev image`) instead of lowering the risk.
- Findings are fixed in the code, never silenced: do not add `noqa`,
  `type: ignore`, `nosec`, `pragma: no cover`, `eslint-disable`,
  `stylelint-disable`, `prettier-ignore`, `shellcheck disable`,
  `hadolint ignore` or any other inline switch, and do not add ignore lists,
  per-file ignores, exclusions, mypy overrides or lower thresholds to any tool
  configuration. Do not rewrite code only to hide it from a checker. If a fix
  seems impossible or very costly, stop and explain the tradeoff to the user
  before touching any configuration.
- Tests run offline in the test image; never make a test install packages or
  reach the network. A new dependency is pinned in `pyproject.toml` and
  `uv.lock` (Python, at the version the image's Alpine package ships) or
  `package.json` and `package-lock.json` (web tooling).
- The companion ships with the firmware and its Home Assistant integration:
  keep `tests/fixtures` byte-identical to the firmware's files, and say in the
  report which firmware change a link or relay change follows. R3 changes are
  not done until their manual evidence (pairing with a real controller) is
  recorded.
- Report the gate's run id (`artifacts/runs/<run-id>/summary.json`) with the
  change.
