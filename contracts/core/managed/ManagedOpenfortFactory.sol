// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {ManagedOpenfortAccount} from "./ManagedOpenfortAccount.sol";
import {OpenfortManagedProxy} from "./OpenfortManagedProxy.sol";
import {BaseOpenfortFactory} from "../base/BaseOpenfortFactory.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

/**
 * @title ManagedOpenfortFactory (Non-upgradeable)
 * @notice Contract to create an on-chain factory to deploy new ManagedOpenfortAccounts.
 * It uses OpenZeppelin's Create2 and OpenfortManagedProxy libraries.
 * It inherits from:
 *  - IBaseOpenfortFactory
 *  - UpgradeableBeacon to also work as the beacon
 */
contract ManagedOpenfortFactory is BaseOpenfortFactory, UpgradeableBeacon {
    constructor(
        address _owner,
        address _entrypoint,
        address _accountImplementation,
        uint256 _recoveryPeriod,
        uint256 _securityPeriod,
        uint256 _securityWindow,
        uint256 _lockPeriod,
        address _openfortGuardian
    )
        BaseOpenfortFactory(
            _entrypoint,
            _accountImplementation,
            _recoveryPeriod,
            _securityPeriod,
            _securityWindow,
            _lockPeriod,
            _openfortGuardian
        )
        UpgradeableBeacon(_accountImplementation)
    {
        if (_owner == address(0)) {
            revert ZeroAddressNotAllowed();
        }
        _transferOwnership(_owner);
    }

    /*
     * @notice Deploy a new account for _admin with a nonce.
     */
    function createAccountWithNonce(address _admin, bytes32 _nonce) external returns (address account) {
        bytes32 salt = keccak256(abi.encode(_admin, _nonce));
        account = getAddressWithNonce(_admin, _nonce);

        if (account.code.length != 0) return account;

        emit AccountCreated(account, _admin);

        account = address(new OpenfortManagedProxy{salt: salt}(address(this), ""));
        ManagedOpenfortAccount(payable(account)).initialize(
            _admin, entrypointContract, recoveryPeriod, securityPeriod, securityWindow, lockPeriod, openfortGuardian
        );
    }

    /*
     * @notice Return the address of an account that would be deployed with the given admin signer and nonce.
     */
    function getAddressWithNonce(address _admin, bytes32 _nonce) public view returns (address) {
        bytes32 salt = keccak256(abi.encode(_admin, _nonce));
        return Create2.computeAddress(
            salt, keccak256(abi.encodePacked(type(OpenfortManagedProxy).creationCode, abi.encode(address(this), "")))
        );
    }

    /**
     * @dev {See BaseOpenfortFactory}
     */
    function addStake(uint32 unstakeDelaySec) external payable onlyOwner {
        IEntryPoint(entrypointContract).addStake{value: msg.value}(unstakeDelaySec);
    }

    /**
     * @dev {See BaseOpenfortFactory}
     */
    function unlockStake() external onlyOwner {
        IEntryPoint(entrypointContract).unlockStake();
    }

    /**
     * @dev {See BaseOpenfortFactory}
     */
    function withdrawStake(address payable withdrawAddress) external onlyOwner {
        IEntryPoint(entrypointContract).withdrawStake(withdrawAddress);
    }
}
