// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

// Base account contract to inherit from
import {BaseOpenfortAccount} from "../BaseOpenfortAccount.sol";

/**
 * @title StaticOpenfortAccount (Non-upgradeable)
 * @author Eloi<eloi@openfort.xyz>
 * @notice Minimal smart contract wallet with session keys following the ERC-4337 standard.
 * The EntryPoint can be updated via updateEntryPoint().
 * It inherits from:
 *  - BaseOpenfortAccount
 */
contract StaticOpenfortAccount is BaseOpenfortAccount {
    event EntryPointUpdated(address oldEntryPoint, address newEntryPoint);

    /*
     * @notice Initialize the smart contract wallet.
     */
    function initialize(address _defaultAdmin, address _entrypoint, bytes calldata) public initializer {
        if (_defaultAdmin == address(0) || _entrypoint == address(0)) {
            revert ZeroAddressNotAllowed();
        }
        emit EntryPointUpdated(entrypointContract, _entrypoint);
        _transferOwnership(_defaultAdmin);
        entrypointContract = _entrypoint;
    }

    /**
     * Update the EntryPoint address
     */
    function updateEntryPoint(address _newEntrypoint) external onlyOwner {
        if (_newEntrypoint == address(0)) {
            revert ZeroAddressNotAllowed();
        }
        emit EntryPointUpdated(entrypointContract, _newEntrypoint);
        entrypointContract = _newEntrypoint;
    }
}
