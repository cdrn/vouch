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

    VouchAccount account;

    function setUp() public {
        bytes memory code = vm.getDeployedCode("VouchAccount.sol:VouchAccount");
        vm.etch(ACCOUNT_ADDR, code);
        account = VouchAccount(payable(ACCOUNT_ADDR));
        // foundry's default chainid is 31337 — the opHash below assumes this.
        vm.chainId(31337);
    }

    function test_InitializeRejectsNonSelf() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert(VouchAccount.OnlySelf.selector);
        account.initialize(PUB_X);
    }

    function test_InitializeFromSelfSucceeds() public {
        vm.prank(ACCOUNT_ADDR);
        account.initialize(PUB_X);
        assertEq(account.pubX(), PUB_X);
        assertTrue(account.initialized());
    }

    function test_InitializeOnceOnly() public {
        vm.prank(ACCOUNT_ADDR);
        account.initialize(PUB_X);
        vm.prank(ACCOUNT_ADDR);
        vm.expectRevert(VouchAccount.AlreadyInitialized.selector);
        account.initialize(PUB_X);
    }

    function test_InitializeRejectsZeroPubKey() public {
        vm.prank(ACCOUNT_ADDR);
        vm.expectRevert(VouchAccount.InvalidPubKey.selector);
        account.initialize(0);
    }

    function test_ExecuteUninitializedReverts() public {
        bytes memory sig = new bytes(64);
        vm.expectRevert(VouchAccount.NotInitialized.selector);
        account.execute(address(0), 0, "", sig);
    }

    /// End-to-end: deploy + init + execute with a real vouch-frost-aggregated
    /// schnorr signature over the contract's computed opHash.
    ///
    /// The signature below was produced by:
    ///   1. computing opHash for (target=0xCAFE..., value=0, data="", nonce=0,
    ///      chainid=31337, account=0x1234...) → 0xbf641d18...72cfcd
    ///   2. cargo run -p vouch-frost --example gen_test_vector -- bf641d18...72cfcd
    function test_ExecuteWithVouchFrostSig() public {
        vm.prank(ACCOUNT_ADDR);
        account.initialize(PUB_X);

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

        // Execute. With no code at target, the call still succeeds (calling
        // an EOA returns true with empty data).
        account.execute(target, value, data, sig);

        assertEq(account.nonce(), 1, "nonce must increment after execute");
    }

    function test_ExecuteWithBadSigReverts() public {
        vm.prank(ACCOUNT_ADDR);
        account.initialize(PUB_X);

        bytes memory badSig = new bytes(64);
        vm.expectRevert(VouchAccount.InvalidSignature.selector);
        account.execute(address(0xCAFE), 0, "", badSig);
    }
}
