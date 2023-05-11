// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import {BaseAccount} from "account-abstraction/core/BaseAccount.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {BaseOpenfortFactory} from "../BaseOpenfortFactory.sol";

// Smart wallet implementation
import {StaticAccount} from "./StaticAccount.sol";

/**
  * @title StaticAccountFactory (Non-upgradeable)
  * @author Eloi<eloi@openfort.xyz>
  * @notice Factory to deploy StaticAccounts
  * It inherits from:
  *  - BaseOpenfortFactory because it is following the base implementation for factories
  */
contract StaticAccountFactory is BaseOpenfortFactory {
    constructor(IEntryPoint _entrypoint) BaseOpenfortFactory(address(new StaticAccount(_entrypoint, address(this)))) {}

    /*
     * @dev Called in `createAccount`. Initializes the account contract created in `createAccount`.
     */
    function _initializeAccount(
        address _account,
        address _admin,
        bytes calldata _data
    ) internal override {
        StaticAccount(payable(_account)).initialize(_admin, _data);
    }
}
