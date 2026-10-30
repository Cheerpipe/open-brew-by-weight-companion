FROM nginx:1.28-alpine

# Alpine's own packages only: nothing is installed with pip, so the tests run offline.
RUN apk add --no-cache python3 py3-zeroconf py3-aiohttp py3-cryptography py3-sqlite3 ca-certificates openssl libqrencode-tools tzdata

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
