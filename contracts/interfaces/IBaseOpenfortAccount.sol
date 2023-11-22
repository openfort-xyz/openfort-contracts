// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

interface IBaseOpenfortAccount is IAccount {
    function owner() external view returns (address);

    function getDeposit() external view returns (uint256);

    /**
     * return the entryPoint used by this account.
     * subclass should return the current entryPoint used by this account.
     */
    function entryPoint() external view returns (IEntryPoint);
}
