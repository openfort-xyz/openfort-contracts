// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

// Base account contract to inherit from
import {BaseUpgradeableOpenfortAccount} from "../BaseUpgradeableOpenfortAccount.sol";

/**
 * @title StaticOpenfortAccount (Non-upgradeable)
 * @author Eloi<eloi@openfort.xyz>
 * @notice Minimal smart contract wallet with session keys following the ERC-4337 standard.
 * It inherits from:
 *  - BaseUpgradeableOpenfortAccount
 */
contract StaticOpenfortAccount is BaseUpgradeableOpenfortAccount {
    event EntryPointUpdated(address oldEntryPoint, address newEntryPoint);

    constructor(address _entrypoint) {
        entrypointContract = _entrypoint;
    }

    /*
     * @notice Initializes the smart contract wallet.
     */
    function initialize(address _defaultAdmin, address _entrypoint, bytes calldata) public override initializer {
        require(_defaultAdmin != address(0), "_defaultAdmin cannot be 0");
        require(_entrypoint != address(0), "_entrypoint cannot be 0");
        emit EntryPointUpdated(entrypointContract, _entrypoint);
        _transferOwnership(_defaultAdmin);
        entrypointContract = _entrypoint;
    }

    /**
     * Update the EntryPoint address
     */
    function updateEntryPoint(address _newEntrypoint) external onlyOwner {
        require(_newEntrypoint != address(0), "_newEntrypoint cannot be 0");
        emit EntryPointUpdated(entrypointContract, _newEntrypoint);
        entrypointContract = _newEntrypoint;
    }
}
