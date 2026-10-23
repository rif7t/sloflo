#!/usr/bin/env bash
# Single-machine stand-in for a second host: a client netns connected to the
# root namespace over a veth pair, so load traffic really crosses an interface
# that XDP can attach to.
#
#   sudo tests/netns_setup.sh up     # create
#   sudo tests/netns_setup.sh down   # tear down
#
# Then:
#   python3 tests/server.py                                   # listens on 0.0.0.0:8080
#   sudo ./rlimit -iface sloflo0 -csv plots/live_trace_xdp.csv
#   sudo ip netns exec sloflo-client ab -n 5000 -c 500 http://10.200.0.1:8080/
set -euo pipefail

NS=sloflo-client
case "${1:-}" in
up)
	ip netns add "$NS"
	ip link add sloflo0 type veth peer name sloflo1
	ip link set sloflo1 netns "$NS"
	ip addr add 10.200.0.1/24 dev sloflo0
	ip link set sloflo0 up
	ip netns exec "$NS" ip addr add 10.200.0.2/24 dev sloflo1
	ip netns exec "$NS" ip link set sloflo1 up
	ip netns exec "$NS" ip link set lo up
	echo "client ns '$NS' ready: server 10.200.0.1:8080, client 10.200.0.2"
	;;
down)
	ip netns del "$NS" 2>/dev/null || true
	ip link del sloflo0 2>/dev/null || true
	;;
*)
	echo "usage: $0 up|down" >&2
	exit 1
	;;
esac
