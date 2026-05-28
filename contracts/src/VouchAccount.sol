// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {SchnorrVerifier} from "./SchnorrVerifier.sol";

/// @title  Vouch smart account (v0, pre-7702).
/// @notice Standalone SCA that executes arbitrary calls authorized by a
///         FROST-aggregated BIP340 schnorr signature over the op hash.
/// @dev    The joint pubkey is fixed at deploy time via constructor →
///         immutable. The 7702 variant (where this contract's code
///         runs in an EOA's address space) needs a per-EOA storage
///         init pathway and will live in a separate contract.
contract VouchAccount {
    /// BIP340 x-only joint public key. Bound at construction.
    uint256 public immutable pubX;
    /// Strictly increasing replay nonce.
    uint256 public nonce;

    event Executed(
        uint256 indexed nonce,
        address indexed target,
        uint256 value,
        bytes data,
        bytes returnData
    );

    error InvalidPubKey();
    error InvalidSignature();
    error CallFailed(bytes returnData);

    constructor(uint256 _pubX) {
        if (_pubX == 0) revert InvalidPubKey();
        pubX = _pubX;
    }

    /// @notice Compute the 32-byte op hash the user signs with the joint key.
    /// @dev    Binds to chain id and account address so signatures from
    ///         one account/chain cannot be replayed elsewhere.
    function opHash(address target, uint256 value, bytes calldata data, uint256 nonceVal)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(target, value, keccak256(data), nonceVal, block.chainid, address(this))
        );
    }

    /// @notice Execute a single call authorized by `sig`.
    /// @param  target  destination address
    /// @param  value   wei to forward
    /// @param  data    calldata for the destination
    /// @param  sig     64-byte BIP340 schnorr signature over opHash(...)
    /// @return ret     destination's returndata
    function execute(address target, uint256 value, bytes calldata data, bytes calldata sig)
        external
        returns (bytes memory ret)
    {
        uint256 current = nonce;
        bytes32 h = opHash(target, value, data, current);
        if (!SchnorrVerifier.verify(h, pubX, sig)) revert InvalidSignature();

        // Bump nonce BEFORE the external call to block reentrant replay.
        nonce = current + 1;

        bool ok;
        (ok, ret) = target.call{value: value}(data);
        if (!ok) revert CallFailed(ret);

        emit Executed(current, target, value, data, ret);
    }

    receive() external payable {}
}
