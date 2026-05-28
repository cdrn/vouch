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
        // Build the runtime code by deploying with PUB_X, then etch at the
        // pinned address — this gives us deterministic address + immutable.
        VouchAccount tmp = new VouchAccount(PUB_X);
        vm.etch(ACCOUNT_ADDR, address(tmp).code);
        // Copy the immutable slot too. Foundry's vm.etch copies code but
        // immutables are baked into the runtime code, so this just works.
        account = VouchAccount(payable(ACCOUNT_ADDR));
        vm.chainId(31337);
    }

    function test_PubKeyStoredAtDeploy() public view {
        assertEq(account.pubX(), PUB_X);
    }

    function test_ConstructorRejectsZeroPubKey() public {
        vm.expectRevert(VouchAccount.InvalidPubKey.selector);
        new VouchAccount(0);
    }

    /// End-to-end: deploy + execute with a real vouch-frost-aggregated
    /// schnorr signature over the contract's computed opHash.
    ///
    /// The signature below was produced by:
    ///   1. computing opHash for (target=0xCAFE..., value=0, data="", nonce=0,
    ///      chainid=31337, account=0x1234...) → 0xbf641d18...72cfcd
    ///   2. cargo run -p vouch-frost --example gen_test_vector -- bf641d18...72cfcd
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
}
