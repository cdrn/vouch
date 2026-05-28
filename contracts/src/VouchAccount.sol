// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {SchnorrVerifier} from "./SchnorrVerifier.sol";

/// @title  Vouch smart account (v0, pre-7702).
/// @notice Minimal SCA that executes arbitrary calls authorized by a
///         FROST-aggregated BIP340 schnorr signature over the op hash.
/// @dev    For v0, deployed as a standalone contract. The EIP-7702
///         delegation flow (where this contract's code runs in an EOA
///         address) is identical at the storage level — only the
///         init pathway changes. Session keys, 4337 EntryPoint
///         integration, and rotation come later.
contract VouchAccount {
    /// BIP340 x-only public key the contract verifies against. Set
    /// exactly once via [`initialize`].
    uint256 public pubX;
    bool public initialized;
    /// Strictly increasing nonce; included in the op hash to prevent replay.
    uint256 public nonce;

    event Initialized(uint256 pubX);
    event Executed(
        uint256 indexed nonce,
        address indexed target,
        uint256 value,
        bytes data,
        bytes returnData
    );

    error AlreadyInitialized();
    error NotInitialized();
    error InvalidPubKey();
    error OnlySelf();
    error InvalidSignature();
    error CallFailed(bytes returnData);

    /// @notice One-shot initializer; must be called by the contract's
    ///         own address (i.e., from a self-call via the bootstrap
    ///         key K in the 7702 model, or by a deployer that wraps the
    ///         constructor in a self-call in v0 standalone mode).
    function initialize(uint256 _pubX) external {
        if (initialized) revert AlreadyInitialized();
        if (msg.sender != address(this)) revert OnlySelf();
        if (_pubX == 0) revert InvalidPubKey();
        pubX = _pubX;
        initialized = true;
        emit Initialized(_pubX);
    }

    /// @notice Compute the 32-byte op hash that the user is expected
    ///         to sign with the joint FROST key.
    /// @dev    Binds to chain id and account address so a signature
    ///         from one account/chain can't be replayed elsewhere.
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
        if (!initialized) revert NotInitialized();

        uint256 current = nonce;
        bytes32 h = opHash(target, value, data, current);
        if (!SchnorrVerifier.verify(h, pubX, sig)) revert InvalidSignature();

        // Bump nonce BEFORE the external call to prevent reentrant replay.
        nonce = current + 1;

        bool ok;
        (ok, ret) = target.call{value: value}(data);
        if (!ok) revert CallFailed(ret);

        emit Executed(current, target, value, data, ret);
    }

    receive() external payable {}
}
