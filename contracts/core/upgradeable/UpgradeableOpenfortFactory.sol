// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

// Base factory contract to inherit from
import {BaseUpgradeableOpenfortFactory} from "../BaseUpgradeableOpenfortFactory.sol";
// Smart wallet implementation to use
import {UpgradeableOpenfortAccount} from "./UpgradeableOpenfortAccount.sol";

/**
 * @title UpgradeableOpenfortFactory (Non-upgradeable)
 * @author Eloi<eloi@openfort.xyz>
 * @notice Factory to deploy UpgradeableOpenfortAccounts
 * It inherits from:
 *  - BaseUpgradeableOpenfortFactory because it is following the base implementation for factories
 */
contract UpgradeableOpenfortFactory is BaseUpgradeableOpenfortFactory {
    constructor(address _entrypoint) BaseUpgradeableOpenfortFactory(address(new UpgradeableOpenfortAccount()), _entrypoint) {}

    /*
     * @dev Called in `createAccount`. Initializes the account contract created in `createAccount`.
     */
    function _initializeAccount(address _account, address _admin, address _entrypointContract, bytes calldata _data)
        internal
        override
    {
        UpgradeableOpenfortAccount(payable(_account)).initialize(_admin, _entrypointContract, _data);
    }
}
