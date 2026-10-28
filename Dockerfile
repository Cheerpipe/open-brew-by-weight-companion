FROM nginx:1.28-alpine

# Alpine's own packages only: nothing is installed with pip, so the tests run offline.
RUN apk add --no-cache python3 py3-zeroconf py3-aiohttp py3-cryptography ca-certificates openssl libqrencode-tools

COPY gateway/ /opt/gateway/
COPY companion/ /opt/companion/

VOLUME /data
STOPSIGNAL SIGTERM
# Local checks only: a health check never contacts the controller.
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s \
  CMD ["python3", "/opt/gateway/gateway.py", "check"]
ENTRYPOINT ["python3", "/opt/gateway/gateway.py"]
