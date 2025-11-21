// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {BaseRecoverableAccount, IEntryPoint} from "../core/base/BaseRecoverableAccount.sol";

/**
 * @title MockV2ManagedOpenfortAccount (Upgradeable via Beacon)
 * @notice Smart contract wallet managed via Beacon with session keys following the ERC-4337 standard.
 * It inherits from:
 *  - BaseRecoverableAccount
 */
contract MockV2ManagedOpenfortAccount is BaseRecoverableAccount {
    address private constant ENTRYPOINTCONTRACT = 0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF;

    /**
     * Return the current EntryPoint
     */
    function entryPoint() public pure override returns (IEntryPoint) {
        return IEntryPoint(ENTRYPOINTCONTRACT);
    }

    /**
     * Disabled method to avoid recoverability
     */
    function getLock() external pure override returns (uint256 _releaseAfter) {
        (_releaseAfter);
        revert("disabled!");
    }

    /**
     * Disabled method to avoid recoverability
     */
    function startRecovery(address _recoveryAddress) external pure override {
        (_recoveryAddress);
        revert("disabled!");
    }
}
