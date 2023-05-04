// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import {BaseAccount, UserOperation} from "account-abstraction/core/BaseAccount.sol";

/**
 * BaseOpenfort account implementation.
 * This contract provides the basic logic for implementing the BaseAccount/IAccount interface - validateUserOp
 * Specific account implementation should inherit it and provide the account-specific logic
 */
abstract contract BaseOpenfort is BaseAccount {

}
