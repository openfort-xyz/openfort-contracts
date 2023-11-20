// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {IBaseOpenfortFactory} from "../../interfaces/IBaseOpenfortFactory.sol";

/**
 * @title BaseOpenfortFactory (Non-upgradeable)
 * @notice Contract to create an on-chain factory to deploy new OpenfortAccounts.
 * It inherits from:
 *  - IBaseOpenfortFactory
 */
abstract contract BaseOpenfortFactory is IBaseOpenfortFactory {
    address public entrypointContract;
    address public accountImplementation;
    uint256 public recoveryPeriod;
    uint256 public securityPeriod;
    uint256 public securityWindow;
    uint256 public lockPeriod;
    address public openfortGuardian;

    error InsecurePeriod();

    constructor(
        address _entrypoint,
        address _accountImplementation,
        uint256 _recoveryPeriod,
        uint256 _securityPeriod,
        uint256 _securityWindow,
        uint256 _lockPeriod,
        address _openfortGuardian
    ) {
        if (_entrypoint == address(0) || _accountImplementation == address(0) || _openfortGuardian == address(0)) {
            revert ZeroAddressNotAllowed();
        }
        if (_lockPeriod < _recoveryPeriod || _recoveryPeriod < _securityPeriod + _securityWindow) {
            revert InsecurePeriod();
        }
        entrypointContract = _entrypoint;
        accountImplementation = _accountImplementation;
        recoveryPeriod = _recoveryPeriod;
        securityPeriod = _securityPeriod;
        securityWindow = _securityWindow;
        lockPeriod = _lockPeriod;
        openfortGuardian = _openfortGuardian;
    }
}
