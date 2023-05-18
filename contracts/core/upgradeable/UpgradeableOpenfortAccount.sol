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
        entrypointContract = address(0);
        _disableInitializers();
    }

    /*
     * @notice Initializes the smart contract wallet.
     */
    function initialize(address _defaultAdmin, address _entrypoint, bytes calldata) public override initializer {
        require(_defaultAdmin != address(0), "_defaultAdmin cannot be 0");
        require(_entrypoint != address(0), "_entrypoint cannot be 0");
        _transferOwnership(_defaultAdmin);
        entrypointContract = _entrypoint;
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}
