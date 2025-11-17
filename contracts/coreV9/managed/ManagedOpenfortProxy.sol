// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {BeaconProxy} from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";

/**
 * @title ManagedOpenfortProxy (Non-upgradeable)
 * @notice Contract to create a beacon proxy. It determines the implementation contract.
 * It inherits from:
 *  - BeaconProxy
 */
contract ManagedOpenfortProxy is BeaconProxy {
    constructor(address _beaconAddress, bytes memory _data) BeaconProxy(_beaconAddress, _data) {}

    function implementation() external view returns (address) {
        return _implementation();
    }
}
