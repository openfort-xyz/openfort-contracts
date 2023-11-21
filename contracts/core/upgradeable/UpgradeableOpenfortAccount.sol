// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

// Base account contract to inherit from and EntryPoint interface
import {BaseRecoverableAccount, IEntryPoint} from "../base/BaseRecoverableAccount.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title UpgradeableOpenfortAccount
 * @notice Minimal smart contract wallet with session keys following the ERC-4337 standard.
 * It inherits from:
 *  - BaseRecoverableAccount
 *  - UUPSUpgradeable
 */
contract UpgradeableOpenfortAccount is BaseRecoverableAccount, UUPSUpgradeable {
    function _authorizeUpgrade(address) internal override onlyOwner {}

    /**
     * Return the current EntryPoint
     */
    function entryPoint() public view override returns (IEntryPoint) {
        return IEntryPoint(entrypointContract);
    }

    /**
     * Update the EntryPoint address
     */
    function updateEntryPoint(address _newEntrypoint) external onlyOwner {
        if (_newEntrypoint == address(0)) revert ZeroAddressNotAllowed();
        emit EntryPointUpdated(entrypointContract, _newEntrypoint);
        entrypointContract = _newEntrypoint;
    }
}
