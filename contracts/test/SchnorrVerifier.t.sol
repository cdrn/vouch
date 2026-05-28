// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {SchnorrVerifier} from "../src/SchnorrVerifier.sol";

/// @notice Wrap the library so we can `vm.expectRevert` / measure gas through a call.
contract VerifierHarness {
    function verify(bytes32 msg32, uint256 pubX, bytes calldata sig)
        external
        view
        returns (bool)
    {
        return SchnorrVerifier.verify(msg32, pubX, sig);
    }
}

contract SchnorrVerifierTest is Test {
    VerifierHarness internal harness;

    function setUp() public {
        harness = new VerifierHarness();
    }

    /// Sanity: confirm the BIP340 tag hash constant matches sha256("BIP0340/challenge").
    function test_PointAddress_Vector0_R() public view {
        // Confirms pointAddress() correctly reconstructs Y and derives address.
        uint256 rX = 0xE907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215;
        address expected = 0x2553f6510438F3CbaD0DFBDAdB36782604341C13;
        assertEq(SchnorrVerifier.pointAddress(rX), expected, "R_x must derive to expected address");
    }

    function test_TagHashConstant() public pure {
        assertEq(
            sha256("BIP0340/challenge"),
            SchnorrVerifier.BIP340_CHALLENGE_TAG,
            "BIP340 challenge tag hash mismatch"
        );
    }

    // BIP340 test vector 0 from the spec.
    // https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
    function test_BIP340_Vector_0() public view {
        bytes32 msg32 = bytes32(0);
        uint256 pubX = 0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9;
        bytes memory sig =
            hex"E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
            hex"25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0";
        assertTrue(harness.verify(msg32, pubX, sig), "vector 0 must verify");
    }

    function test_BIP340_Vector_1() public view {
        bytes32 msg32 = 0x243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89;
        uint256 pubX = 0xDFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659;
        bytes memory sig =
            hex"6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
            hex"8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A";
        assertTrue(harness.verify(msg32, pubX, sig), "vector 1 must verify");
    }

    /// Real signature produced by vouch-frost (2-of-2 DKG + sign over a
    /// fixed message with a deterministic ChaCha20 RNG seeded to zeros).
    /// Closes the loop: a sig coming out of our offchain stack verifies
    /// against this verifier. Regenerate with:
    ///   cargo run -p vouch-frost --example gen_test_vector
    function test_VouchFrostGeneratedSignature() public view {
        bytes32 msg32 = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef;
        uint256 pubX = 0x1dadf16e4070045223c0e8b48af3c9dfe70188ab731359b37bf86650be5d037e;
        bytes memory sig =
            hex"ab518f51525328fc680f83742e5f855a877064a66aefcfe43b452df62c8940f8"
            hex"c866a737c181026eca83138261e66f8006db4c7e0c700347293ab70c1fd137e3";
        assertTrue(harness.verify(msg32, pubX, sig), "vouch-frost sig must verify");
    }

    function test_RejectsFlippedSigByte() public view {
        bytes32 msg32 = bytes32(0);
        uint256 pubX = 0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9;
        bytes memory sig =
            hex"E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
            hex"25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C1"; // last byte +1
        assertFalse(harness.verify(msg32, pubX, sig), "tampered sig must not verify");
    }

    function test_RejectsWrongPubKey() public view {
        bytes32 msg32 = bytes32(0);
        // wrong pubkey (vector 1's key with vector 0's message+sig)
        uint256 pubX = 0xDFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659;
        bytes memory sig =
            hex"E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
            hex"25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0";
        assertFalse(harness.verify(msg32, pubX, sig), "wrong key must not verify");
    }

    function test_RejectsTamperedMessage() public view {
        bytes32 msg32 = bytes32(uint256(1)); // not the original zero message
        uint256 pubX = 0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9;
        bytes memory sig =
            hex"E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
            hex"25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0";
        assertFalse(harness.verify(msg32, pubX, sig), "wrong message must not verify");
    }

    function test_RejectsBadLength() public view {
        bytes32 msg32 = bytes32(0);
        uint256 pubX = 0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9;
        bytes memory sig = hex"DEADBEEF";
        assertFalse(harness.verify(msg32, pubX, sig), "<64 byte sig must not verify");
    }

    function test_RejectsZeroPubX() public view {
        bytes32 msg32 = bytes32(0);
        bytes memory sig =
            hex"E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
            hex"25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0";
        assertFalse(harness.verify(msg32, 0, sig), "pubX=0 must not verify");
    }
}
