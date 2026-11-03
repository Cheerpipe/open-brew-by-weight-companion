#!/bin/bash
# The container's entrypoint. The supervisor (gateway.py) renders nginx's
# configuration first; then nginx and the supervisor run side by side, the
# supervisor reloading nginx through its pid file. When either one stops, so
# does the other and the container, and Docker's restart policy starts both again.
set -euo pipefail

gateway=/opt/gateway/gateway.py
case "${1-}" in
check | scan | mdns-check) exec python3 "$gateway" "$@" ;;
"") ;;
*)
	echo "usage: entrypoint.sh [check [--controller] | scan | mdns-check [name.local]]" >&2
	exit 2
	;;
esac

run=${COMPANION_RUN_DIR:-${GATEWAY_RUN_DIR:-/run/gateway}}
python3 "$gateway" prepare

stopping=0
nginx -c "$run/nginx.conf" -g 'daemon off;' &
nginx=$!
python3 "$gateway" &
supervisor=$!
trap 'stopping=1; kill -TERM "$supervisor" "$nginx" 2>/dev/null || true' TERM INT

wait -n || true
if [ "$stopping" = 0 ]; then
	if kill -0 "$nginx" 2>/dev/null; then
		echo "the supervisor stopped; stopping nginx" >&2
	else
		echo "nginx stopped; stopping the supervisor" >&2
	fi
	kill -TERM "$supervisor" "$nginx" 2>/dev/null || true
fi
wait || true
[ "$stopping" = 1 ]
