#!/bin/bash
# End-to-end test of the app's enrollment client against a real eap-enroll
# server with a fake OpenBao. See README.md.
#
#   e2e/run.sh /path/to/eap-enroll
set -euo pipefail
if [ $# -ne 1 ] || [ ! -x "$1" ]; then
  echo "usage: $0 /path/to/eap-enroll" >&2
  exit 2
fi
BIN=$(realpath "$1")
cd "$(dirname "$0")/.."
OUT=build/e2e
rm -rf "$OUT/run"
mkdir -p "$OUT"
(cd e2e/harness && go build -o "../../$OUT/e2e-harness" .)

# EndToEndTest moves the app's clock 300 days ahead to make the device
# credential due, while the server issues on real time: Wi-Fi certificates
# issued after the jump must still be valid on the app's clock.
"$OUT/e2e-harness" -dir "$OUT/run" -eap-enroll "$BIN" -wifi-ttl 8760h >"$OUT/harness.log" 2>&1 &
HARNESS=$!
trap 'kill $HARNESS 2>/dev/null; wait $HARNESS 2>/dev/null; rm -f "$OUT/run/control"' EXIT
for _ in $(seq 100); do
  [ -s "$OUT/run/control" ] && break
  kill -0 $HARNESS 2>/dev/null || { cat "$OUT/harness.log" >&2; exit 1; }
  sleep 0.1
done
[ -s "$OUT/run/control" ] || { echo "harness didn't start" >&2; exit 1; }

EAP_ENROLL_E2E_CONTROL=$(cat "$OUT/run/control") \
  ./gradlew testDebugUnitTest --tests 'eu.appwerf.eapenroll.EndToEndTest' --rerun-tasks -q
echo "End-to-end tests passed. Server log: $OUT/run/server.log"
