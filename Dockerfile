FROM nginx:1.28-alpine

RUN apk add --no-cache python3 py3-zeroconf openssl libqrencode-tools

COPY gateway/ /opt/gateway/

VOLUME /data
STOPSIGNAL SIGTERM
# Local checks only: a health check never contacts the controller.
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s \
  CMD ["python3", "/opt/gateway/gateway.py", "check"]
ENTRYPOINT ["python3", "/opt/gateway/gateway.py"]
