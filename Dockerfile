FROM alpine:3.24

# Alpine 3.24's own packages only: nothing is installed with pip, so the tests
# run offline. nginx comes from the branch's package (the supervisor renders
# the whole config itself), and Python's sqlite3 module is built into python3.
RUN apk add --no-cache nginx python3 py3-zeroconf py3-aiohttp py3-cryptography ca-certificates openssl libqrencode-tools tzdata

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
