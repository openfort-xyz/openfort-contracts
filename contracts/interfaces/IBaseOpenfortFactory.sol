// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IBaseOpenfortFactory {
    /// @notice Emitted when a new Account is created.
    event AccountCreated(address indexed account, address indexed accountAdmin);

    /// @notice Error when an address parameter is 0.
    error ZeroAddressNotAllowed();

    /// @notice Deploys a new Account for admin.
    function createAccountWithNonce(address _admin, bytes calldata _nonce) external returns (address account);

    /// @notice Returns the address of the Account implementation.
    function accountImplementation() external view returns (address);

    /// @notice Returns the address of an Account that would be deployed with the given admin and nonce.
    function getAddressWithNonce(address _admin, bytes calldata _nonce) external view returns (address);
}
