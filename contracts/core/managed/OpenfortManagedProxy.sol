// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {BeaconProxy} from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";

/**
 * @title OpenfortManagedProxy (Non-upgradeable)
 * @notice Contract to create the beacon. It determines the implementation contract.
 * It inherits from:
 *  - BeaconProxy
 */
contract OpenfortManagedProxy is BeaconProxy {
    constructor(address beacon, bytes memory data) BeaconProxy(beacon, data) {}

    function implementation() external view returns (address) {
        return _implementation();
    }
}
