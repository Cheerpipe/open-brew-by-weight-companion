FROM alpine:3.24 AS runtime

# Alpine 3.24's own packages only: nothing is installed with pip, so the tests
# run offline. nginx comes from the branch's package (the supervisor renders
# the whole config itself), and Python's sqlite3 module is built into python3.
# Software is pinned to the branch's minor versions, which take its patch
# updates; pyproject.toml names the exact Python package versions.
RUN apk add --no-cache nginx~1.30 python3~3.14 py3-zeroconf~0.147 py3-aiohttp~3.13 \
  py3-cryptography~47.0 ca-certificates openssl~3.5 libqrencode-tools~4.1 tzdata

# The commit the image is built from, for the version shown on the companion's pages.
ARG COMPANION_COMMIT=
ENV COMPANION_COMMIT=$COMPANION_COMMIT

COPY gateway/ /opt/gateway/
COPY companion/ /opt/companion/

VOLUME /data
STOPSIGNAL SIGTERM
# Local checks only: a health check never contacts the controller.
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s \
  CMD ["python3", "/opt/gateway/gateway.py", "check"]
ENTRYPOINT ["python3", "/opt/gateway/gateway.py"]

# The test image: the runtime plus pytest, coverage and bash (for ./setup's
# test), all Alpine packages. `./scripts/dev` builds it with --target test and
# runs it without a network; it is never shipped.
FROM runtime AS test
RUN apk add --no-cache bash~5.3 py3-coverage~7.14 py3-pytest~9.0

# The image `docker compose build` and ./setup build: the runtime alone.
FROM runtime
