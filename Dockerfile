# Alpine 3.24, pinned by digest: a rebuild never changes the base under a release.
FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS base

# nginx, Python and bash (gateway/entrypoint.sh) from the branch's packages, pinned to
# their minor versions, which still take the branch's patch updates. Time zones and trusted
# roots are data Alpine replaces with each year's release, so they have a floor instead.
RUN apk add --no-cache nginx~1.30 python3~3.14 bash~5.3 'ca-certificates>=20261020' \
  'tzdata>=2026e'

# The Python packages, from PyPI by the hashes in requirements/ (exported from uv.lock),
# into /opt/venv. PyPI has wheels for every package on amd64 and arm64; on 32-bit ARM,
# cryptography and cffi build from their verified sources, so only that build installs
# a compiler and Rust, and only in this stage.
FROM base AS packages
ARG TARGETARCH
ARG TARGETVARIANT
RUN apk add --no-cache py3-pip~26 \
  && if [ "$TARGETARCH$TARGETVARIANT" = armv7 ]; then \
    apk add --no-cache build-base~0.5 cargo~1.96 libffi-dev~3.5 openssl-dev~3.5 python3-dev~3.14; \
  fi \
  && python3 -m venv --without-pip /opt/venv
COPY requirements/runtime.txt /tmp/requirements/
RUN pip --python /opt/venv/bin/python install --no-cache-dir --no-deps --require-hashes \
  -r /tmp/requirements/runtime.txt

FROM base AS runtime
COPY --from=packages /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH

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
ENTRYPOINT ["/opt/gateway/entrypoint.sh"]

# The test image: the runtime plus pytest and coverage (PyPI, by hash) and OpenSSL's
# command line, which checks the certificates.
# `./scripts/dev image` builds it and the tests run in it without a network; it is
# never shipped.
FROM packages AS test-packages
COPY requirements/test.txt /tmp/requirements/
RUN pip --python /opt/venv/bin/python install --no-cache-dir --no-deps --require-hashes \
  -r /tmp/requirements/test.txt

FROM runtime AS test
COPY --from=test-packages /opt/venv /opt/venv
RUN apk add --no-cache openssl~3.5

# The image `docker compose build` and ./setup build: the runtime alone.
FROM runtime
