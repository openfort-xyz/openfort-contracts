// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";

/**
 * @title OpenfortBeacon (Non-upgradeable)
 * @author Eloi<eloi@openfort.xyz>
 * @notice Contract to 
 * 
 * It inherits from:
 *  - 
 */
contract OpenfortBeacon is UpgradeableBeacon {
    constructor(address implementation_) UpgradeableBeacon(implementation_) {}
}
