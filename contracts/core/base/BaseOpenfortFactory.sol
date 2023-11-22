// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {IBaseOpenfortFactory} from "../../interfaces/IBaseOpenfortFactory.sol";

/**
 * @title BaseOpenfortFactory (Non-upgradeable)
 * @notice Contract to create an on-chain factory to deploy new OpenfortAccounts.
 * It inherits from:
 *  - IBaseOpenfortFactory
 *  - Ownable2Step
 */
abstract contract BaseOpenfortFactory is IBaseOpenfortFactory, Ownable2Step {
    address public entrypointContract;
    address internal _implementation;
    uint256 public recoveryPeriod;
    uint256 public securityPeriod;
    uint256 public securityWindow;
    uint256 public lockPeriod;
    address public openfortGuardian;

    error InsecurePeriod();

    constructor(
        address _owner,
        address _entrypoint,
        address _accountImplementation,
        uint256 _recoveryPeriod,
        uint256 _securityPeriod,
        uint256 _securityWindow,
        uint256 _lockPeriod,
        address _openfortGuardian
    ) {
        if (
            _owner == address(0) || _entrypoint == address(0) || _accountImplementation == address(0)
                || _openfortGuardian == address(0)
        ) {
            revert ZeroAddressNotAllowed();
        }
        if (_lockPeriod < _recoveryPeriod || _recoveryPeriod < _securityPeriod + _securityWindow) {
            revert InsecurePeriod();
        }
        _transferOwnership(_owner);
        entrypointContract = _entrypoint;
        _implementation = _accountImplementation;
        recoveryPeriod = _recoveryPeriod;
        securityPeriod = _securityPeriod;
        securityWindow = _securityWindow;
        lockPeriod = _lockPeriod;
        openfortGuardian = _openfortGuardian;
    }

    /**
     * @dev Returns the current implementation address.
     */
    function implementation() external view virtual override returns (address) {
        return _implementation;
    }

    /**
     * @dev {See IBaseOpenfortFactory}
     */
    function addStake(uint32 unstakeDelaySec) external payable onlyOwner {
        IEntryPoint(entrypointContract).addStake{value: msg.value}(unstakeDelaySec);
    }

    /**
     * @dev {See IBaseOpenfortFactory}
     */
    function unlockStake() external onlyOwner {
        IEntryPoint(entrypointContract).unlockStake();
    }

    /**
     * @dev {See IBaseOpenfortFactory}
     */
    function withdrawStake(address payable withdrawAddress) external onlyOwner {
        IEntryPoint(entrypointContract).withdrawStake(withdrawAddress);
    }
}
