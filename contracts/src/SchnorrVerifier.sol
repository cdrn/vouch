// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title BIP340-compatible Schnorr signature verifier for secp256k1.
/// @notice Verifies 64-byte BIP340 schnorr signatures (R_x || s) using
///         the ecrecover-as-EC-mul trick popularized by Chainflip and
///         Tornado Cash. Signatures from frost-secp256k1-tr verify here.
/// @dev    Sig format matches BIP340 exactly: 64 bytes, x-only encoding
///         for both R and P, even-Y convention. Challenge uses tagged
///         sha256 per BIP340.
library SchnorrVerifier {
    /// secp256k1 group order.
    uint256 internal constant N =
        0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;

    /// secp256k1 field prime.
    uint256 internal constant FP =
        0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f;

    /// (FP + 1) / 4 — sqrt exponent (FP ≡ 3 mod 4, so y = rhs^((p+1)/4)).
    uint256 internal constant FP_PLUS_1_OVER_4 =
        0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c;

    /// sha256("BIP0340/challenge") — the tag used in BIP340's tagged hash.
    bytes32 internal constant BIP340_CHALLENGE_TAG =
        0x7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c;

    /// @notice Verify a 64-byte BIP340 schnorr signature.
    /// @param msg32 32-byte message digest (BIP340 requires exactly 32 bytes).
    /// @param pubX  x-only public key (x-coordinate; even Y assumed).
    /// @param sig   64 bytes = R_x (32 BE) || s (32 BE).
    /// @return ok   True iff the signature verifies.
    function verify(bytes32 msg32, uint256 pubX, bytes calldata sig)
        internal
        view
        returns (bool ok)
    {
        if (sig.length != 64) return false;
        if (pubX == 0 || pubX >= FP) return false;
        // pubX must fit ecrecover's r slot; legitimate pubX >= N is
        // astronomically unlikely (~2^-224) but we reject it explicitly.
        if (pubX >= N) return false;

        uint256 rX;
        uint256 s;
        assembly {
            rX := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 0x20))
        }
        if (rX == 0 || rX >= FP) return false;
        if (s == 0 || s >= N) return false;

        // Reconstruct R's full point from R_x (assuming even Y per BIP340)
        // and derive its Ethereum address — that's what the ecrecover
        // trick's output gets compared against.
        address rAddress = pointAddress(rX);
        if (rAddress == address(0)) return false;

        // BIP340 challenge: e = sha256(tag || tag || R_x || P_x || m) mod n
        uint256 e = uint256(
            sha256(
                abi.encodePacked(
                    BIP340_CHALLENGE_TAG,
                    BIP340_CHALLENGE_TAG,
                    bytes32(rX),
                    bytes32(pubX),
                    msg32
                )
            )
        ) % N;
        if (e == 0) return false;

        // ecrecover trick:
        //   ecrecover(h, v, r, s_ec) returns address of Q where
        //     Q = r^(-1) * (s_ec * R_pt - h * G)
        //   and R_pt is the curve point with x=r, y-parity from v.
        // Set R_pt = P (the pubkey): r = pubX, v = 27 (even Y, BIP340).
        // Want Q = s*G - e*P (so address(Q) should equal rAddress, since
        //   BIP340 verification says R = s*G - e*P).
        // Solve:
        //   s_ec * pubX^(-1) = -e   →  s_ec = (N - e) * pubX mod N
        //   -h * pubX^(-1)   =  s   →  h    = (N - s) * pubX mod N
        uint256 h = mulmod(N - s, pubX, N);
        uint256 sEc = mulmod(N - e, pubX, N);
        if (h == 0 || sEc == 0) return false;

        address recovered = ecrecover(bytes32(h), 27, bytes32(pubX), bytes32(sEc));
        return recovered == rAddress;
    }

    /// @notice Derive the Ethereum address of the curve point (x, y)
    ///         where y is the even square root of x³ + 7 mod p.
    /// @return The 20-byte address, or address(0) if x is not on the curve.
    function pointAddress(uint256 x) internal view returns (address) {
        // y² = x³ + 7 (mod p)
        uint256 rhs = addmod(mulmod(mulmod(x, x, FP), x, FP), 7, FP);

        // y = sqrt(rhs) = rhs^((p+1)/4) mod p, valid since p ≡ 3 mod 4.
        uint256 y = modExp(rhs, FP_PLUS_1_OVER_4, FP);

        // Check: y² == rhs (rejects x values not on the curve).
        if (mulmod(y, y, FP) != rhs) return address(0);

        // Pick the even Y (BIP340 convention).
        if (y & 1 == 1) y = FP - y;

        // Ethereum address = last 20 bytes of keccak256(x || y) (both BE).
        return address(uint160(uint256(keccak256(abi.encodePacked(x, y)))));
    }

    /// @notice 256-bit modular exponentiation via the modexp precompile.
    function modExp(uint256 base, uint256 exponent, uint256 modulus)
        internal
        view
        returns (uint256 result)
    {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x20) // length of base
            mstore(add(ptr, 0x20), 0x20) // length of exponent
            mstore(add(ptr, 0x40), 0x20) // length of modulus
            mstore(add(ptr, 0x60), base)
            mstore(add(ptr, 0x80), exponent)
            mstore(add(ptr, 0xa0), modulus)
            if iszero(staticcall(gas(), 0x05, ptr, 0xc0, ptr, 0x20)) { revert(0, 0) }
            result := mload(ptr)
        }
    }
}
