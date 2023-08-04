// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {BeaconProxy} from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";

/**
 * @title OpenfortBeaconProxy (Non-upgradeable)
 * @author Eloi<eloi@openfort.xyz>
 * @notice Contract to create the Beacon to determine implementation contract, which is where they will delegate all function calls.
 * It inherits from:
 *  - BeaconProxy
 */
contract OpenfortBeaconProxy is BeaconProxy {
    constructor(address beacon, bytes memory data) BeaconProxy(beacon, data) {}

    function implementation() external view returns (address) {
        return _implementation();
    }
}
