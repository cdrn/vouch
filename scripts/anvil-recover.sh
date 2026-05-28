#!/usr/bin/env bash
#
# End-to-end demo of the passport-recovery loop, fully onchain:
#   1. deploy VouchAccount with the seed-0 joint pubkey + a recovery
#      authority address (deployer's address, for the demo)
#   2. sign + execute a userop with the seed-0 FROST key → nonce 0→1
#   3. simulate a fresh-device DKG by generating the seed-1 joint pubkey
#   4. signer-side: sign the SCA's rotationDigest(newPubX) with the
#      recovery authority's ECDSA key (EIP-191 prefixed)
#   5. submit rotatePubKey(newPubX, sig) → pubX becomes newPubX
#   6. sign + execute a fresh userop under the new key → nonce 1→2
#
# Proves the threshold property holds across a recovery: the *account*
# (and its address, its history, its balance) is preserved while the
# joint pubkey rotates to a fresh key bound to a new device.

set -euo pipefail
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1

ROOT=$(cd "$(dirname "$0")/.." && pwd)
RPC=http://localhost:8545
DEPLOYER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
TARGET=0xCAFE000000000000000000000000000000000000
CHAINID=31337

cleanup() { [[ -n "${ANVIL_PID:-}" ]] && kill "$ANVIL_PID" 2>/dev/null || true; }
trap cleanup EXIT

# parse "pubX:sig" output from gen_test_vector
parse_pub() { echo "$1" | cut -d: -f1; }
parse_sig() { echo "$1" | cut -d: -f2; }

compute_op_hash() {
    local account=$1 nonce_val=$2
    local data_hash=$(cast keccak 0x)
    local encoded=$(cast abi-encode \
        "f(address,uint256,bytes32,uint256,uint256,address)" \
        $TARGET 0 $data_hash $nonce_val $CHAINID $account)
    cast keccak "$encoded"
}

echo "→ starting anvil"
anvil --chain-id $CHAINID --port 8545 > /tmp/vouch-anvil-recover.log 2>&1 &
ANVIL_PID=$!
for _ in {1..20}; do
    cast block-number --rpc-url $RPC > /dev/null 2>&1 && break
    sleep 0.2
done

echo "→ pre-building gen_test_vector"
(cd "$ROOT" && cargo build -p vouch-frost --example gen_test_vector --quiet)

# seed 0 = "old device" joint pubkey
PUB_X_OLD=$("$ROOT/target/debug/examples/gen_test_vector" \
    --seed 0 0000000000000000000000000000000000000000000000000000000000000000 \
    | cut -d: -f1)
PUB_X_OLD=0x$PUB_X_OLD

RECOVERY_AUTH=$(cast wallet address --private-key $DEPLOYER_KEY)
echo "→ deploying VouchAccount"
echo "   pubX (old) = $PUB_X_OLD"
echo "   recovery   = $RECOVERY_AUTH"

DEPLOY=$(cd "$ROOT/contracts" && forge create "src/VouchAccount.sol:VouchAccount" \
    --rpc-url $RPC --private-key $DEPLOYER_KEY --broadcast --json \
    --constructor-args $PUB_X_OLD $RECOVERY_AUTH)
ACCOUNT=$(echo "$DEPLOY" | jq -r '.deployedTo')
echo "   account    = $ACCOUNT"

# ── 1. Sign + execute with old key ──────────────────────────────────────
OP_HASH=$(compute_op_hash $ACCOUNT 0)
echo "→ [old key] opHash = $OP_HASH"
SIG_OLD=$("$ROOT/target/debug/examples/gen_test_vector" \
    --seed 0 ${OP_HASH#0x} | cut -d: -f2)
cast send $ACCOUNT "execute(address,uint256,bytes,bytes)" \
    $TARGET 0 0x "0x$SIG_OLD" \
    --rpc-url $RPC --private-key $DEPLOYER_KEY > /dev/null
NONCE_BEFORE=$(cast --to-dec $(cast call $ACCOUNT "nonce()" --rpc-url $RPC))
echo "   nonce now  = $NONCE_BEFORE"
[[ "$NONCE_BEFORE" == "1" ]] || { echo "✗ old-key execute failed"; exit 1; }

# ── 2. Recovery: rotate to the new key ──────────────────────────────────
# "New device" joint pubkey from seed-1 DKG.
PUB_X_NEW=$("$ROOT/target/debug/examples/gen_test_vector" \
    --seed 1 0000000000000000000000000000000000000000000000000000000000000000 \
    | cut -d: -f1)
PUB_X_NEW=0x$PUB_X_NEW
echo "→ recovery: rotating to pubX (new) = $PUB_X_NEW"

# Compute the rotationDigest the recovery authority signs over.
ROT_DIGEST=$(cast call $ACCOUNT "rotationDigest(uint256)(bytes32)" \
    $PUB_X_NEW --rpc-url $RPC)
echo "   rotation digest = $ROT_DIGEST"

# Sign with EIP-191 prefix (cast wallet sign does this when --no-hash
# is omitted and input is hex bytes).
ROT_SIG=$(cast wallet sign --private-key $DEPLOYER_KEY $ROT_DIGEST)
echo "   rotation sig    = $ROT_SIG"

cast send $ACCOUNT "rotatePubKey(uint256,bytes)" \
    $PUB_X_NEW "$ROT_SIG" \
    --rpc-url $RPC --private-key $DEPLOYER_KEY > /dev/null

PUB_X_AFTER=$(cast call $ACCOUNT "pubX()(uint256)" --rpc-url $RPC | cut -d' ' -f1)
ROT_NONCE=$(cast --to-dec $(cast call $ACCOUNT "rotationNonce()" --rpc-url $RPC))
echo "   pubX onchain    = $PUB_X_AFTER"
echo "   rotationNonce   = $ROT_NONCE"
[[ "$ROT_NONCE" == "1" ]] || { echo "✗ rotation did not bump rotationNonce"; exit 1; }

# ── 3. Sign + execute with new key ──────────────────────────────────────
OP_HASH2=$(compute_op_hash $ACCOUNT $NONCE_BEFORE)
echo "→ [new key] opHash = $OP_HASH2"
SIG_NEW=$("$ROOT/target/debug/examples/gen_test_vector" \
    --seed 1 ${OP_HASH2#0x} | cut -d: -f2)
cast send $ACCOUNT "execute(address,uint256,bytes,bytes)" \
    $TARGET 0 0x "0x$SIG_NEW" \
    --rpc-url $RPC --private-key $DEPLOYER_KEY > /dev/null
NONCE_AFTER=$(cast --to-dec $(cast call $ACCOUNT "nonce()" --rpc-url $RPC))
echo "   nonce now  = $NONCE_AFTER"
[[ "$NONCE_AFTER" == "2" ]] || { echo "✗ new-key execute failed"; exit 1; }

echo
echo "✓ recovery e2e: account address $ACCOUNT preserved across rotation"
echo "  old pubX → new pubX (rotated by recovery authority)"
echo "  old-key execute (nonce 0) and new-key execute (nonce 1) both accepted"
