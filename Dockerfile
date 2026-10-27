FROM nginx:1.28-alpine

RUN apk add --no-cache python3 py3-zeroconf openssl

COPY gateway/ /opt/gateway/

VOLUME /data
STOPSIGNAL SIGTERM
ENTRYPOINT ["python3", "/opt/gateway/gateway.py"]
