// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";

/**
 * @title OpenfortBeacon (Non-upgradeable)
 * @author Eloi<eloi@openfort.xyz>
 * @notice Contract to create the Beacon to determine implementation contract, which is where they will delegate all function calls.
 * It inherits from:
 *  - UpgradeableBeacon
 */
contract OpenfortBeacon is UpgradeableBeacon {
    constructor(address implementation_) UpgradeableBeacon(implementation_) {}
}
