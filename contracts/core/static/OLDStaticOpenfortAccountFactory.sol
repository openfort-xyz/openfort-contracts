// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

// Base factory contract to inherit from
import {BaseOpenfortFactory, IEntryPoint} from "../BaseOpenfortFactory.sol";
// Smart wallet implementation to use
import {OLDStaticOpenfortAccount} from "./OLDStaticOpenfortAccount.sol";

/**
 * @title StaticOpenfortFactory (Non-upgradeable)
 * @author Eloi<eloi@openfort.xyz>
 * @notice Factory to deploy StaticOpenfortAccounts
 * It inherits from:
 *  - BaseOpenfortFactory because it is following the base implementation for factories
 */
contract OLDStaticOpenfortFactory is BaseOpenfortFactory {
    constructor(IEntryPoint _entrypoint)
        BaseOpenfortFactory(address(new OLDStaticOpenfortAccount(_entrypoint, address(this))))
    {}

    /*
     * @dev Called in `createAccount`. Initializes the account contract created in `createAccount`.
     */
    function _initializeAccount(address _account, address _admin, bytes calldata _data) internal override {
        OLDStaticOpenfortAccount(payable(_account)).initialize(_admin, _data);
    }
}
