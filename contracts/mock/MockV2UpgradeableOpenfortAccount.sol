// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

// Base account contract to inherit from and EntryPoint interface
import {BaseRecoverableAccount, IEntryPoint} from "../core/base/BaseRecoverableAccount.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title MockV2UpgradeableOpenfortAccount
 * @notice Mock contract to test upgradeability
 * It inherits from:
 *  - BaseRecoverableAccount
 *  - UUPSUpgradeable
 */
contract MockV2UpgradeableOpenfortAccount is BaseRecoverableAccount, UUPSUpgradeable {
    /**
     * Update the EntryPoint address
     */
    function updateEntryPoint(address _newEntrypoint) external {
        _authorizeUpgrade(_newEntrypoint);
        revert("disabled!");
    }

    /**
     * Return 42 to demonstrate that the logic has been updated
     */
    function easterEgg() external pure returns (uint256) {
        return 42;
    }

    /**
     * Return the modified EntryPoint
     */
    function entryPoint() public pure override returns (IEntryPoint) {
        return IEntryPoint(0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF);
    }

    function _authorizeUpgrade(address) internal override {}
}
