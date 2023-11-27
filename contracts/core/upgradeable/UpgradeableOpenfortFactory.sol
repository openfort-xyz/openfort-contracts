// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {UpgradeableOpenfortAccount} from "./UpgradeableOpenfortAccount.sol";
import {UpgradeableOpenfortProxy} from "./UpgradeableOpenfortProxy.sol";
import {BaseOpenfortFactory} from "../base/BaseOpenfortFactory.sol";

/**
 * @title UpgradeableOpenfortFactory (Non-upgradeable)
 * @notice Contract to create an on-chain factory to deploy new UpgradeableOpenfortAccounts.
 * It inherits from:
 *  - BaseOpenfortFactory
 */
contract UpgradeableOpenfortFactory is BaseOpenfortFactory {
    uint256 public recoveryPeriod;
    uint256 public securityPeriod;
    uint256 public securityWindow;
    uint256 public lockPeriod;

    error TooManyInitialGuardians();

    constructor(
        address _owner,
        address _entrypoint,
        address _accountImplementation,
        uint256 _recoveryPeriod,
        uint256 _securityPeriod,
        uint256 _securityWindow,
        uint256 _lockPeriod
    ) BaseOpenfortFactory(_owner, _entrypoint, _accountImplementation) {
        if (_lockPeriod < _recoveryPeriod || _recoveryPeriod < _securityPeriod + _securityWindow) {
            revert InsecurePeriod();
        }
        recoveryPeriod = _recoveryPeriod;
        securityPeriod = _securityPeriod;
        securityWindow = _securityWindow;
        lockPeriod = _lockPeriod;
    }

    /*
     * @notice Deploy a new account for _admin with a nonce.
     */
    function createAccountWithNonce(address _admin, bytes32 _nonce, address[] _initialGuardians)
        external
        returns (address account)
    {
        bytes32 salt = keccak256(abi.encode(_admin, _nonce));
        account = getAddressWithNonce(_admin, _nonce);

        if (account.code.length > 0) return account;

        emit AccountCreated(account, _admin);
        account = address(new UpgradeableOpenfortProxy{salt: salt}(_implementation, ""));
        uint256 initialGuardiansNumber = _initialGuardians.length;
        if (initialGuardiansNumber > 5) revert TooManyInitialGuardians();
        for (uint256 i = 0; i < initialGuardiansNumber; i++) {
            if (_initialGuardians[i] == address(0)) revert ZeroAddressNotAllowed();
        }
        UpgradeableOpenfortAccount(payable(account)).initialize(
            _admin, entrypointContract, recoveryPeriod, securityPeriod, securityWindow, lockPeriod, _initialGuardians
        );
    }

    /*
     * @notice Return the address of an account that would be deployed with the given admin signer and nonce.
     */
    function getAddressWithNonce(address _admin, bytes32 _nonce) public view returns (address) {
        bytes32 salt = keccak256(abi.encode(_admin, _nonce));
        return Create2.computeAddress(
            salt,
            keccak256(abi.encodePacked(type(UpgradeableOpenfortProxy).creationCode, abi.encode(_implementation, "")))
        );
    }
}
