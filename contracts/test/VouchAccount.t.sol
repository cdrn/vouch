// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {VouchAccount} from "../src/VouchAccount.sol";

contract VouchAccountTest is Test {
    /// Pinned account address so the opHash baked into the sign-and-execute
    /// test is deterministic. `vm.etch` puts the deployed bytecode here.
    address constant ACCOUNT_ADDR = 0x1234567890123456789012345678901234567890;
    /// Joint pubkey from the vouch-frost deterministic test vector
    /// (gen_test_vector example, ChaCha20 seed = [0; 32]).
    uint256 constant PUB_X =
        0x1dadf16e4070045223c0e8b48af3c9dfe70188ab731359b37bf86650be5d037e;
    /// Recovery authority — derived from a known test private key.
    uint256 constant RECOVERY_AUTH_PRIVKEY = 0xa11ce;

    VouchAccount account;
    address recoveryAuth;

    function setUp() public {
        recoveryAuth = vm.addr(RECOVERY_AUTH_PRIVKEY);
        VouchAccount tmp = new VouchAccount(PUB_X, recoveryAuth);
        vm.etch(ACCOUNT_ADDR, address(tmp).code);
        // vm.etch copies code (and immutables baked into code) but not
        // storage. Initialise pubX in slot 0 manually.
        vm.store(ACCOUNT_ADDR, bytes32(uint256(0)), bytes32(PUB_X));
        account = VouchAccount(payable(ACCOUNT_ADDR));
        vm.chainId(31337);
    }

    function test_PubKeyStoredAtDeploy() public view {
        assertEq(account.pubX(), PUB_X);
        assertEq(account.recoveryAuthority(), recoveryAuth);
    }

    function test_ConstructorRejectsZeroPubKey() public {
        vm.expectRevert(VouchAccount.InvalidPubKey.selector);
        new VouchAccount(0, recoveryAuth);
    }

    function test_ConstructorRejectsZeroRecoveryAuthority() public {
        vm.expectRevert(VouchAccount.ZeroRecoveryAuthority.selector);
        new VouchAccount(PUB_X, address(0));
    }

    /// End-to-end: deploy + execute with a real vouch-frost-aggregated
    /// schnorr signature over the contract's computed opHash.
    function test_ExecuteWithVouchFrostSig() public {
        address target = 0xCAFE000000000000000000000000000000000000;
        uint256 value = 0;
        bytes memory data = "";

        bytes32 h = account.opHash(target, value, data, 0);
        assertEq(
            h,
            0xbf641d18901a7bad108d514807a16f20d1785bb849e60966ec124a890572cfcd,
            "opHash drifted - regenerate the baked signature"
        );

        bytes memory sig =
            hex"57f79e02eaed93119963b89fc96455005b6f9d4209111454a0def9cf1f5ad299"
            hex"93bd21dde2e12e892dd8fa3f7b2140db3bc169be4ed2852994ff0b9486c05fa3";

        account.execute(target, value, data, sig);
        assertEq(account.nonce(), 1, "nonce must increment after execute");
    }

    function test_ExecuteWithBadSigReverts() public {
        bytes memory badSig = new bytes(64);
        vm.expectRevert(VouchAccount.InvalidSignature.selector);
        account.execute(address(0xCAFE), 0, "", badSig);
    }

    // ───── rotation tests ────────────────────────────────────────────────

    function test_RotateAcceptsAuthorizedSig() public {
        uint256 newPubX = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef;
        bytes memory sig = _signRotation(newPubX, RECOVERY_AUTH_PRIVKEY);

        account.rotatePubKey(newPubX, sig);
        assertEq(account.pubX(), newPubX, "pubX must rotate");
        assertEq(account.rotationNonce(), 1, "rotationNonce must increment");
    }

    function test_RotateRejectsWrongSigner() public {
        uint256 newPubX = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef;
        bytes memory sig = _signRotation(newPubX, 0xb0b);
        vm.expectRevert(VouchAccount.InvalidRecoverySignature.selector);
        account.rotatePubKey(newPubX, sig);
    }

    function test_RotateRejectsReplay() public {
        uint256 newPubX = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef;
        bytes memory sig = _signRotation(newPubX, RECOVERY_AUTH_PRIVKEY);
        account.rotatePubKey(newPubX, sig);
        // rotationNonce bumped, same sig should now fail.
        vm.expectRevert(VouchAccount.InvalidRecoverySignature.selector);
        account.rotatePubKey(newPubX, sig);
    }

    function test_RotateRejectsZeroPubKey() public {
        bytes memory sig = _signRotation(0, RECOVERY_AUTH_PRIVKEY);
        vm.expectRevert(VouchAccount.InvalidPubKey.selector);
        account.rotatePubKey(0, sig);
    }

    function test_RotateRejectsMalformedSig() public {
        vm.expectRevert(VouchAccount.MalformedRecoverySig.selector);
        account.rotatePubKey(uint256(1), new bytes(64));
    }

    function _signRotation(uint256 newPubX, uint256 privkey)
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest = account.rotationDigest(newPubX);
        bytes32 ethDigest =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privkey, ethDigest);
        return abi.encodePacked(r, s, v);
    }
}
