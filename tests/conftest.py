"""Shared pytest configuration for the companion's tests.

The tests run inside the test image without a network (./scripts/dev test);
pyproject.toml puts the repository root, gateway/ and tests/ on the path.
"""

if not __debug__:
    raise SystemExit("assertions are disabled (PYTHONOPTIMIZE); these checks would not run")
