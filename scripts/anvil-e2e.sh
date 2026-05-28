#!/usr/bin/env bash
#
# End-to-end demo: boot anvil, deploy VouchAccount, sign an opHash via
# vouch-frost (2-of-2 FROST DKG → BIP340 schnorr), submit execute() to
# the SCA, verify the nonce bumped.
#
# Proves the offchain stack and the onchain stack actually compose
# against a real EVM, not just inside forge tests.

set -euo pipefail

export FOUNDRY_DISABLE_NIGHTLY_WARNING=1
ROOT=$(cd "$(dirname "$0")/.." && pwd)
RPC=http://localhost:8545
# anvil's default account 0 private key — deterministic, only used in the
# local dev chain. Never use this on a real network.
DEPLOYER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
PUB_X=0x1dadf16e4070045223c0e8b48af3c9dfe70188ab731359b37bf86650be5d037e
TARGET=0xCAFE000000000000000000000000000000000000
CHAINID=31337

cleanup() {
    if [[ -n "${ANVIL_PID:-}" ]]; then
        kill "$ANVIL_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "→ starting anvil (chainid=$CHAINID)"
anvil --chain-id $CHAINID --port 8545 > /tmp/vouch-anvil.log 2>&1 &
ANVIL_PID=$!
# wait for anvil to accept connections
for _ in {1..20}; do
    if cast block-number --rpc-url $RPC > /dev/null 2>&1; then break; fi
    sleep 0.2
done

echo "→ pre-building gen_test_vector example (avoids cargo run noise later)"
(cd "$ROOT" && cargo build -p vouch-frost --example gen_test_vector --quiet)

# Recovery authority — for the e2e demo, the deployer doubles as the
# signer's recovery key. In production the signer service holds this key
# in a TEE and only signs rotation messages after verifying a passport.
RECOVERY_AUTH=$(cast wallet address --private-key $DEPLOYER_KEY)
echo "→ deploying VouchAccount(pubX=$PUB_X, recovery=$RECOVERY_AUTH)"
# NB: --constructor-args is greedy under foundry's CLI parser; it must come last.
DEPLOY_OUT=$(cd "$ROOT/contracts" && forge create "src/VouchAccount.sol:VouchAccount" \
    --rpc-url $RPC \
    --private-key $DEPLOYER_KEY \
    --broadcast \
    --json \
    --constructor-args $PUB_X $RECOVERY_AUTH)
ACCOUNT=$(echo "$DEPLOY_OUT" | jq -r '.deployedTo')
echo "   account: $ACCOUNT"

echo "→ computing opHash for (target=$TARGET, value=0, data=0x, nonce=0, chainid=$CHAINID, this=$ACCOUNT)"
DATA_HASH=$(cast keccak 0x)
ENCODED=$(cast abi-encode \
    "f(address,uint256,bytes32,uint256,uint256,address)" \
    $TARGET 0 $DATA_HASH 0 $CHAINID $ACCOUNT)
OP_HASH=$(cast keccak "$ENCODED")
echo "   opHash:  $OP_HASH"

echo "→ signing opHash via vouch-frost (deterministic 2-of-2 DKG + sign)"
SIG_OUT=$("$ROOT/target/debug/examples/gen_test_vector" "${OP_HASH#0x}")
SIG=$(echo "$SIG_OUT" | cut -d: -f2)
echo "   sig:     0x$SIG"

echo "→ submitting execute() to $ACCOUNT"
cast send "$ACCOUNT" \
    "execute(address,uint256,bytes,bytes)" \
    $TARGET 0 0x "0x$SIG" \
    --rpc-url $RPC \
    --private-key $DEPLOYER_KEY \
    > /tmp/vouch-execute.log

FINAL_NONCE=$(cast call "$ACCOUNT" "nonce()" --rpc-url $RPC)
FINAL_NONCE_DEC=$(cast --to-dec "$FINAL_NONCE")
echo "   nonce after execute: $FINAL_NONCE_DEC"

if [[ "$FINAL_NONCE_DEC" == "1" ]]; then
    echo
    echo "✓ end-to-end: vouch-frost sig accepted by VouchAccount on anvil"
    exit 0
else
    echo
    echo "✗ FAIL: nonce did not increment (expected 1, got $FINAL_NONCE_DEC)"
    exit 1
fi
