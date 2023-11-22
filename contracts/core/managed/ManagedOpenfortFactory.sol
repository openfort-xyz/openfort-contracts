// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {IBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {ManagedOpenfortAccount} from "./ManagedOpenfortAccount.sol";
import {ManagedOpenfortProxy} from "./ManagedOpenfortProxy.sol";
import {BaseOpenfortFactory, Address} from "../base/BaseOpenfortFactory.sol";

/**
 * @title ManagedOpenfortFactory (Non-upgradeable)
 * @notice Contract to create an on-chain factory to deploy new ManagedOpenfortAccounts.
 * It inherits from:
 *  - BaseOpenfortFactory
 *  - IBeacon to work as the beacon
 */
contract ManagedOpenfortFactory is BaseOpenfortFactory, IBeacon {
    /**
     * @dev Emitted when the implementation returned by the beacon is changed.
     */
    event Upgraded(address indexed implementation);

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
            _owner,
            _entrypoint,
            _accountImplementation,
            _recoveryPeriod,
            _securityPeriod,
            _securityWindow,
            _lockPeriod,
            _openfortGuardian
        )
    {
        _setImplementation(_accountImplementation);
    }

    /*
     * @notice Deploy a new account for _admin with a nonce.
     */
    function createAccountWithNonce(address _admin, bytes32 _nonce) external returns (address account) {
        bytes32 salt = keccak256(abi.encode(_admin, _nonce));
        account = getAddressWithNonce(_admin, _nonce);

        if (account.code.length != 0) return account;

        emit AccountCreated(account, _admin);

        account = address(new ManagedOpenfortProxy{salt: salt}(address(this), ""));
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
            salt, keccak256(abi.encodePacked(type(ManagedOpenfortProxy).creationCode, abi.encode(address(this), "")))
        );
    }

    /**
     * @dev Returns the current implementation address.
     */
    function implementation() public view virtual override(BaseOpenfortFactory, IBeacon) returns (address) {
        return _implementation;
    }

    /**
     * @dev Upgrades the beacon to a new implementation.
     *
     * Emits an {Upgraded} event.
     *
     * Requirements:
     *
     * - msg.sender must be the owner of the contract.
     * - `newImplementation` must be a contract.
     */
    function upgradeTo(address newImplementation) public virtual onlyOwner {
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);
    }

    /**
     * @dev Sets the implementation contract address for this beacon
     *
     * Requirements:
     *
     * - `newImplementation` must be a contract.
     */
    function _setImplementation(address newImplementation) private {
        require(Address.isContract(newImplementation), "ManagedOpenfortFactory: implementation is not a contract");
        _implementation = newImplementation;
    }
}
