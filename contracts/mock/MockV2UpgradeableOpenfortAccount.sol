// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {
    Ownable2StepUpgradeable,
    OwnableUpgradeable
} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

// Base account contract to inherit from
import {BaseOpenfortAccount, IEntryPoint} from "../core/BaseOpenfortAccount.sol";

/**
 * @title MockV2UpgradeableOpenfortAccount
 * @notice Minimal smart contract wallet with session keys following the ERC-4337 standard.
 * It inherits from:
 *  - BaseOpenfortAccount
 *  - UUPSUpgradeable
 */
contract MockV2UpgradeableOpenfortAccount is BaseOpenfortAccount, Ownable2StepUpgradeable, UUPSUpgradeable {
    address internal entrypointContract;
    /*
     * @notice Initialize the smart contract wallet.
     */

    function initialize(address _defaultAdmin, address _entrypoint) public initializer {
        if (_defaultAdmin == address(0) || _entrypoint == address(0)) {
            revert ZeroAddressNotAllowed();
        }
        _transferOwnership(_defaultAdmin);
        entrypointContract = _entrypoint;
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    function owner() public view virtual override(BaseOpenfortAccount, OwnableUpgradeable) returns (address) {
        return OwnableUpgradeable.owner();
    }

    /**
     * Return the current EntryPoint
     */
    function entryPoint() public pure override returns (IEntryPoint) {
        return IEntryPoint(address(0));
    }
}
