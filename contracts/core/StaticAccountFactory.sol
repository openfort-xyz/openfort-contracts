// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {BaseAccountFactory} from "./BaseAccountFactory.sol";
import {BaseAccount} from "account-abstraction/core/BaseAccount.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

// Smart wallet implementation
import {StaticAccount} from "./StaticAccount.sol";

contract StaticAccountFactory is BaseAccountFactory {
    constructor(IEntryPoint _entrypoint) BaseAccountFactory(address(new StaticAccount(_entrypoint, address(this)))) {}

    /// @dev Called in `createAccount`. Initializes the account contract created in `createAccount`.
    function _initializeAccount(
        address _account,
        address _admin,
        bytes calldata _data
    ) internal override {
        StaticAccount(payable(_account)).initialize(_admin, _data);
    }
}
