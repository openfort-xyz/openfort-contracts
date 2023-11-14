// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

// Base account contract to inherit from and EntryPoint interface
import {BaseOpenfortAccount, IEntryPoint} from "../BaseOpenfortAccount.sol";

/**
 * @title ManagedOpenfortAccount (Upgradeable via Beacon)
 * @notice Smart contract wallet managed via Beacon with session keys following the ERC-4337 standard.
 * It inherits from:
 *  - BaseOpenfortAccount
 */
contract ManagedOpenfortAccount is BaseOpenfortAccount {
    address private constant ENTRYPOINTCONTRACT = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    /*
     * @notice Initialize the smart contract wallet.
     */
    function initialize(address _defaultAdmin) public initializer {
        if (_defaultAdmin == address(0)) {
            revert ZeroAddressNotAllowed();
        }
        _transferOwnership(_defaultAdmin);
        __EIP712_init("Openfort", "0.5");
    }

    /**
     * Return the current EntryPoint
     */
    function entryPoint() public pure override returns (IEntryPoint) {
        return IEntryPoint(ENTRYPOINTCONTRACT);
    }
}
