// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Base account contract to inherit from
import {BaseOpenfortAccount, IEntryPoint} from "../BaseOpenfortAccount.sol";

/**
 * @title ManagedOpenfortAccount (Upgradeable via Beacon)
 * @author Eloi<eloi@openfort.xyz>
 * @notice Smart contract wallet managed via Beacon with session keys following the ERC-4337 standard.
 * It inherits from:
 *  - BaseOpenfortAccount
 */
contract ManagedOpenfortAccount is BaseOpenfortAccount {
    address private constant ENTRYPOINTCONTRACT = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    /*
     * @notice Initialize the smart contract wallet.
     */
    function initialize(address _defaultAdmin, bytes calldata) public initializer {
        if (_defaultAdmin == address(0)) {
            revert ZeroAddressNotAllowed();
        }
        _transferOwnership(_defaultAdmin);
    }

    /**
     * Return the current EntryPoint
     */
    function entryPoint() public pure override returns (IEntryPoint) {
        return IEntryPoint(ENTRYPOINTCONTRACT);
    }
}
