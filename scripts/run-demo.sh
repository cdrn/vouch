#!/usr/bin/env bash
#
# Starts anvil + the vouch signer service. The RN app then talks to
# the signer at http://localhost:8089 (or the LAN IP of this machine
# if you're running on a phone).
#
# After this script is up:
#   cd client && npx expo start --dev-client
# then build to your device via `npx expo run:ios` or EAS.

set -euo pipefail
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1

ROOT=$(cd "$(dirname "$0")/.." && pwd)

cleanup() {
    [[ -n "${ANVIL_PID:-}" ]] && kill "$ANVIL_PID" 2>/dev/null || true
    [[ -n "${SIGNER_PID:-}" ]] && kill "$SIGNER_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "→ starting anvil on :8545"
anvil --chain-id 31337 --port 8545 > /tmp/vouch-anvil-run.log 2>&1 &
ANVIL_PID=$!
for _ in {1..20}; do
    cast block-number --rpc-url http://127.0.0.1:8545 > /dev/null 2>&1 && break
    sleep 0.2
done

echo "→ building signer"
(cd "$ROOT" && cargo build -p vouch-signer --quiet)

echo "→ starting signer on :8089"
VOUCH_REPO_ROOT="$ROOT" "$ROOT/target/debug/vouch-signer" \
    > /tmp/vouch-signer-run.log 2>&1 &
SIGNER_PID=$!
for _ in {1..40}; do
    curl -sf http://127.0.0.1:8089/v0/dkg -X OPTIONS > /dev/null 2>&1 && break
    sleep 0.2
done

LAN_IP=$(ipconfig getifaddr en0 2>/dev/null || ifconfig | grep -A1 'flags=' | grep 'inet ' | grep -v 127.0.0.1 | head -1 | awk '{print $2}')

cat <<EOF

──────────────────────────────────────────────────────────────────
  anvil   → http://127.0.0.1:8545     log: /tmp/vouch-anvil-run.log
  signer  → http://127.0.0.1:8089     log: /tmp/vouch-signer-run.log
  LAN IP  → ${LAN_IP:-<not detected>} (use http://\$LAN_IP:8089 from a phone)

  next: cd client && npx expo start --dev-client
        then: i (iOS) or a (Android) — must be a dev-client build
        (Expo Go won't work because we ship native modules for NFC)

  ctrl-c to tear everything down.
──────────────────────────────────────────────────────────────────
EOF

# Block here so the trap handlers fire on ctrl-c.
wait
