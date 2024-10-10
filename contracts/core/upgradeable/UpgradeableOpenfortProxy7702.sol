// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UpgradeableOpenfortAccount} from "./UpgradeableOpenfortAccount.sol";

/**
 * @title UpgradeableOpenfortProxy7702 (Non-upgradeable)
 * @notice Proxy contract that support 7702 initialization
 * It inherits from:
 *  - ERC1967Proxy
 */
contract UpgradeableOpenfortProxy7702 is ERC1967Proxy {
    constructor(address _logic, bytes memory _data) ERC1967Proxy(_logic, _data) {}

    function implementation() external view returns (address) {
        return _implementation();
    }

    function initializeAccount(
        address _implementation,
        address _entrypoint,
        uint256 _recoveryPeriod,
        uint256 _securityPeriod,
        uint256 _securityWindow,
        uint256 _lockPeriod,
        address _initialGuardian
    ) public {
        // only callable by the EOA itself in an eip-7702 delegation
        require(msg.sender == address(this));

        // set implementation in the storage of the EOA
        _upgradeTo(_implementation);

        UpgradeableOpenfortAccount(payable(address(this))).initialize(
            msg.sender, _entrypoint, _recoveryPeriod, _securityPeriod, _securityWindow, _lockPeriod, _initialGuardian
        );
    }
}
