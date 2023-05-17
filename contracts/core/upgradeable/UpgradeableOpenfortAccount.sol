// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

// Base account contract to inherit from
import {BaseUpgradeableOpenfortAccount, IEntryPoint} from "../BaseUpgradeableOpenfortAccount.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title UpgradeableOpenfortAccount
 * @author Eloi<eloi@openfort.xyz>
 * @notice Minimal smart contract wallet with session keys following the ERC-4337 standard.
 * It inherits from:
 *  - BaseUpgradeableOpenfortAccount
 */
contract UpgradeableOpenfortAccount is BaseUpgradeableOpenfortAccount, UUPSUpgradeable {
    constructor() {
        _disableInitializers();
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}
