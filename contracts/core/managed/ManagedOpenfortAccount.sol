// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

// Base account contract to inherit from
import {BaseOpenfortAccount} from "../BaseOpenfortAccount.sol";

/**
 * @title ManagedOpenfortAccount (Non-upgradeable)
 * @author Eloi<eloi@openfort.xyz>
 * @notice Minimal smart contract wallet with session keys following the ERC-4337 standard.
 * It inherits from:
 *  - BaseOpenfortAccount
 */
contract ManagedOpenfortAccount is BaseOpenfortAccount {

    /*
     * @notice Initialize the smart contract wallet.
     */
    function initialize(address _defaultAdmin, address _entrypoint, bytes calldata) public override initializer {
        if (_defaultAdmin == address(0) || _entrypoint == address(0)) {
            revert ZeroAddressNotAllowed();
        }
        _transferOwnership(_defaultAdmin);
        entrypointContract = _entrypoint;
    }
}
