// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {BaseRecoverableAccount, IEntryPoint} from "../base/BaseRecoverableAccount.sol";

/**
 * @title ManagedOpenfortAccount (Upgradeable via Beacon)
 * @notice Smart contract wallet managed via Beacon with session keys following the ERC-4337 standard.
 * It inherits from:
 *  - BaseRecoverableAccount
 */
contract ManagedOpenfortAccount is BaseRecoverableAccount {
    address private constant ENTRYPOINTCONTRACT = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    /**
     * Return the current EntryPoint
     */
    function entryPoint() public pure override returns (IEntryPoint) {
        return IEntryPoint(ENTRYPOINTCONTRACT);
    }
}
