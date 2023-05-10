// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

interface IBaseAccountFactory {
    /// @notice Emitted when a new Account is created.
    event AccountCreated(address indexed account, address indexed accountAdmin);

    /// @notice Deploys a new Account for admin.
    function createAccount(address admin, bytes calldata _data) external returns (address account);

    /// @notice Returns the address of the Account implementation.
    function accountImplementation() external view returns (address);

    /// @notice Returns the address of an Account that would be deployed with the given admin signer.
    function getAddress(address adminSigner) external view returns (address);
}