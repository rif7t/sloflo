#!/usr/bin/env bash
# One-machine live test: veth+netns client -> python server -> XDP limiter.
#
#   sudo tests/run_live.sh [xdp|observe] [step|neutral] [time-scale] [run-label]
#
# Writes plots/live_<profile>_<mode>.{trace,phases,requests}.csv and a .log.
# Cleans up on exit. Then: python3 plots/plot_live.py plots/live_<profile>_<mode>
set -euo pipefail

MODE=${1:-xdp}
PROFILE=${2:-step}
SCALE=${3:-1}
RUN=${4:-}   # optional label so repeats do not overwrite each other
ROOT=$(cd "$(dirname "$0")/.." && pwd)
NS=sloflo-client
OUT="$ROOT/plots/live_${PROFILE}_${MODE}${RUN:+_$RUN}"
BIN=$(mktemp -d)/rlimit

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
[[ $MODE == xdp || $MODE == observe ]] || { echo "mode must be xdp|observe" >&2; exit 1; }

cleanup() {
	set +e
	[[ -n ${RL_PID:-} ]] && kill -INT "$RL_PID" 2>/dev/null && wait "$RL_PID" 2>/dev/null
	[[ -n ${SRV_PID:-} ]] && kill "$SRV_PID" 2>/dev/null
	"$ROOT/tests/netns_setup.sh" down
}
trap cleanup EXIT

(cd "$ROOT" && go build -o "$BIN" ./cmd/rlimit)
"$ROOT/tests/netns_setup.sh" down
"$ROOT/tests/netns_setup.sh" up

# 1s of work, 150 at a time: ~150 req/s capacity, below MaxConcurrency (250) so the
# gradient, not the cap, has to find the limit; c=800 means ~5.3s, past ab/client timeouts
python3 "$ROOT/tests/server.py" --service 1 --capacity 150 &
SRV_PID=$!
sleep 1

# -server-addr: other services on this host (e.g. coredns health checks) also use :8080
FLAGS=(-iface sloflo0 -server-addr 10.200.0.1 -csv "$OUT.trace.csv")
[[ $MODE == observe ]] && FLAGS+=(-observe-only)
"$BIN" "${FLAGS[@]}" >"$OUT.log" 2>&1 &
RL_PID=$!
sleep 2
kill -0 "$RL_PID" || { echo "controller failed to start:"; cat "$OUT.log"; exit 1; }

ip netns exec "$NS" python3 "$ROOT/tests/load_profile.py" --profile "$PROFILE" --scale "$SCALE" --out "$OUT"

sleep 1
echo "trace: $OUT.trace.csv ($(($(wc -l <"$OUT.trace.csv") - 1)) samples)"
