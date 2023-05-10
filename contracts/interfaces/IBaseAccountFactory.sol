// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

interface IBaseAccountFactory {
    /// @notice Emitted when a new Account is created.
    event AccountCreated(address indexed account, address indexed accountAdmin);

    /// @notice Emitted when a new signer is added to an Account.
    event SignerAdded(address indexed account, address indexed signer);

    /// @notice Emitted when a new signer is added to an Account.
    event SignerRemoved(address indexed account, address indexed signer);

    /// @notice Deploys a new Account for admin.
    function createAccount(address admin, bytes calldata _data) external returns (address account);

    /// @notice Callback function for an Account to register its signers.
    function addSigner(address signer) external;

    /// @notice Callback function for an Account to un-register its signers.
    function removeSigner(address signer) external;
}