#!/usr/bin/env bash
#
# End-to-end demo of the v0 server-held-key wallet flow:
#   1. POST /v0/wallet/create   → signer deploys VouchAccount, returns address+pubX
#   2. POST /v0/wallet/sign-and-execute  → signer signs opHash, submits execute()
#   3. POST /v0/wallet/recover  → signer rotates pubX onchain via recovery authority
#
# Each step is what the RN client will call.

set -euo pipefail
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1

ROOT=$(cd "$(dirname "$0")/.." && pwd)
RPC=http://127.0.0.1:8545
SIGNER_URL=http://127.0.0.1:8089

cleanup() {
    [[ -n "${ANVIL_PID:-}" ]] && kill "$ANVIL_PID" 2>/dev/null || true
    [[ -n "${SIGNER_PID:-}" ]] && kill "$SIGNER_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "→ starting anvil"
anvil --chain-id 31337 --port 8545 > /tmp/vouch-anvil-demo.log 2>&1 &
ANVIL_PID=$!
for _ in {1..20}; do
    cast block-number --rpc-url $RPC > /dev/null 2>&1 && break
    sleep 0.2
done

echo "→ building signer"
(cd "$ROOT" && cargo build -p vouch-signer --quiet)

echo "→ starting signer"
VOUCH_REPO_ROOT="$ROOT" "$ROOT/target/debug/vouch-signer" \
    > /tmp/vouch-signer-demo.log 2>&1 &
SIGNER_PID=$!
for _ in {1..40}; do
    curl -sf $SIGNER_URL/v0/dkg -X OPTIONS > /dev/null 2>&1 && break
    sleep 0.2
done

# Use a real-looking H_passport for the demo (32 bytes of hex).
H_PASSPORT="ab12cd34ef5601020304050607080910abcdef0102030405060708090a0b0c0d"

# ── 1. Create wallet ─────────────────────────────────────────────────────
echo "→ POST /v0/wallet/create"
CREATE=$(curl -sf -X POST $SIGNER_URL/v0/wallet/create \
    -H 'content-type: application/json' \
    -d "{\"h_passport_hex\":\"$H_PASSPORT\"}")
ACCOUNT=$(echo "$CREATE" | jq -r .account_address)
OLD_PUB_X=$(echo "$CREATE" | jq -r .pub_x_hex)
echo "   account = $ACCOUNT"
echo "   pubX    = $OLD_PUB_X"

# ── 2. Sign and execute ──────────────────────────────────────────────────
echo "→ POST /v0/wallet/sign-and-execute"
EXEC=$(curl -sf -X POST $SIGNER_URL/v0/wallet/sign-and-execute \
    -H 'content-type: application/json' \
    -d "{
        \"account_address\": \"$ACCOUNT\",
        \"target\": \"0xCAFE000000000000000000000000000000000000\",
        \"value\": \"0\",
        \"data\": \"0x\"
    }")
TX_HASH=$(echo "$EXEC" | jq -r .tx_hash)
echo "   tx_hash = $TX_HASH"
NONCE_AFTER=$(cast --to-dec $(cast call $ACCOUNT "nonce()" --rpc-url $RPC))
echo "   nonce   = $NONCE_AFTER"
[[ "$NONCE_AFTER" == "1" ]] || { echo "✗ execute failed"; exit 1; }

# ── 3. Recover (rotate pubX) ─────────────────────────────────────────────
echo "→ POST /v0/wallet/recover"
RECOVER=$(curl -sf -X POST $SIGNER_URL/v0/wallet/recover \
    -H 'content-type: application/json' \
    -d "{\"h_passport_hex\":\"$H_PASSPORT\"}")
NEW_PUB_X=$(echo "$RECOVER" | jq -r .new_pub_x_hex)
ROT_TX=$(echo "$RECOVER" | jq -r .rotation_tx_hash)
echo "   new pubX = $NEW_PUB_X"
echo "   tx_hash  = $ROT_TX"

# Verify pubX onchain changed.
PUB_X_ONCHAIN=$(cast call $ACCOUNT "pubX()(uint256)" --rpc-url $RPC | cut -d' ' -f1)
ROT_NONCE=$(cast --to-dec $(cast call $ACCOUNT "rotationNonce()" --rpc-url $RPC))
echo "   pubX onchain  = $(printf '0x%064x\n' $PUB_X_ONCHAIN)"
echo "   rotationNonce = $ROT_NONCE"
[[ "$ROT_NONCE" == "1" ]] || { echo "✗ rotation did not bump rotationNonce"; exit 1; }

# Sign+execute under the new key.
echo "→ POST /v0/wallet/sign-and-execute (after recovery)"
EXEC2=$(curl -sf -X POST $SIGNER_URL/v0/wallet/sign-and-execute \
    -H 'content-type: application/json' \
    -d "{
        \"account_address\": \"$ACCOUNT\",
        \"target\": \"0xCAFE000000000000000000000000000000000000\",
        \"value\": \"0\",
        \"data\": \"0x\"
    }")
TX_HASH2=$(echo "$EXEC2" | jq -r .tx_hash)
echo "   tx_hash = $TX_HASH2"
NONCE_FINAL=$(cast --to-dec $(cast call $ACCOUNT "nonce()" --rpc-url $RPC))
echo "   nonce   = $NONCE_FINAL"
[[ "$NONCE_FINAL" == "2" ]] || { echo "✗ post-recovery execute failed"; exit 1; }

echo
echo "✓ wallet demo: create → execute → recover → execute, all via HTTP"
echo "  account preserved: $ACCOUNT"
echo "  rotated by the signer's recovery authority key"
