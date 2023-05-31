// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

// Base account contract to inherit from
import {BaseOpenfortAccount, IEntryPoint} from "../BaseOpenfortAccount.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title UpgradeableOpenfortAccount
 * @author Eloi<eloi@openfort.xyz>
 * @notice Minimal smart contract wallet with session keys following the ERC-4337 standard.
 * It inherits from:
 *  - BaseOpenfortAccount
 *  - UUPSUpgradeable
 */
contract UpgradeableOpenfortAccount is BaseOpenfortAccount, UUPSUpgradeable {
    address internal entrypointContract;

    event EntryPointUpdated(address oldEntryPoint, address newEntryPoint);

    /*
     * @notice Initialize the smart contract wallet.
     */
    function initialize(address _defaultAdmin, address _entrypoint, bytes calldata) public initializer {
        if (_defaultAdmin == address(0) || _entrypoint == address(0)) {
            revert ZeroAddressNotAllowed();
        }
        emit EntryPointUpdated(entrypointContract, _entrypoint);
        _transferOwnership(_defaultAdmin);
        entrypointContract = _entrypoint;
    }

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
        if (_newEntrypoint == address(0)) {
            revert ZeroAddressNotAllowed();
        }
        emit EntryPointUpdated(entrypointContract, _newEntrypoint);
        entrypointContract = _newEntrypoint;
    }
}
