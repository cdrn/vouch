// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {SchnorrVerifier} from "./SchnorrVerifier.sol";

/// @title  Vouch smart account (v0, pre-7702).
/// @notice Standalone SCA that executes arbitrary calls authorized by a
///         FROST-aggregated BIP340 schnorr signature over the op hash.
///         The joint pubkey is rotatable via an ECDSA signature from a
///         baked-in recovery authority — that's how passport-based
///         recovery completes the loop onchain.
/// @dev    7702 variant (where this code runs in an EOA's address space)
///         needs a per-EOA storage init pathway and will live alongside.
contract VouchAccount {
    /// Current BIP340 x-only joint public key. Mutates on recovery via
    /// rotatePubKey().
    uint256 public pubX;
    /// ECDSA address that can authorize pubX rotations. Set at deploy,
    /// immutable. Trust assumption: this address belongs to the signer
    /// service, which only signs rotation messages after verifying a
    /// passport zk-proof (or, in v0, an H_passport commitment).
    address public immutable recoveryAuthority;
    /// Replay nonce for execute().
    uint256 public nonce;
    /// Replay nonce for rotatePubKey(); included in the digest so the
    /// recovery authority's signature can't be reused.
    uint256 public rotationNonce;

    event Executed(
        uint256 indexed nonce,
        address indexed target,
        uint256 value,
        bytes data,
        bytes returnData
    );
    event PubKeyRotated(uint256 indexed rotationNonce, uint256 newPubX);

    error InvalidPubKey();
    error InvalidSignature();
    error InvalidRecoverySignature();
    error CallFailed(bytes returnData);
    error ZeroRecoveryAuthority();
    error MalformedRecoverySig();

    constructor(uint256 _pubX, address _recoveryAuthority) {
        if (_pubX == 0) revert InvalidPubKey();
        if (_recoveryAuthority == address(0)) revert ZeroRecoveryAuthority();
        pubX = _pubX;
        recoveryAuthority = _recoveryAuthority;
    }

    /// @notice Compute the op hash that the user signs with the joint key.
    function opHash(address target, uint256 value, bytes calldata data, uint256 nonceVal)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(target, value, keccak256(data), nonceVal, block.chainid, address(this))
        );
    }

    function execute(address target, uint256 value, bytes calldata data, bytes calldata sig)
        external
        returns (bytes memory ret)
    {
        uint256 current = nonce;
        bytes32 h = opHash(target, value, data, current);
        if (!SchnorrVerifier.verify(h, pubX, sig)) revert InvalidSignature();

        nonce = current + 1;

        bool ok;
        (ok, ret) = target.call{value: value}(data);
        if (!ok) revert CallFailed(ret);

        emit Executed(current, target, value, data, ret);
    }

    /// @notice Compute the digest the recovery authority signs to
    ///         authorize a pubX rotation. Bound to this contract, the
    ///         rotation nonce, the chain id, and a fixed domain tag.
    function rotationDigest(uint256 newPubX) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("vouch.VouchAccount.rotate.v1"),
                address(this),
                newPubX,
                rotationNonce,
                block.chainid
            )
        );
    }

    /// @notice Rotate the joint pubkey. Authorized by an ECDSA signature
    ///         from `recoveryAuthority` over the EIP-191-prefixed
    ///         rotationDigest. Bumps rotationNonce so the same sig can't
    ///         be replayed.
    /// @param  newPubX  the joint pubkey produced by the recovery DKG
    /// @param  sig      65-byte ECDSA signature (r || s || v) over the
    ///                  EIP-191-prefixed rotation digest
    function rotatePubKey(uint256 newPubX, bytes calldata sig) external {
        if (newPubX == 0) revert InvalidPubKey();
        if (sig.length != 65) revert MalformedRecoverySig();

        bytes32 digest = rotationDigest(newPubX);
        bytes32 ethDigest =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        address recovered = ecrecover(ethDigest, v, r, s);
        if (recovered == address(0) || recovered != recoveryAuthority) {
            revert InvalidRecoverySignature();
        }

        pubX = newPubX;
        emit PubKeyRotated(rotationNonce, newPubX);
        rotationNonce++;
    }

    receive() external payable {}
}
