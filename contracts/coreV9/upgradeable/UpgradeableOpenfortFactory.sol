// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

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
    address public initialGuardian;

    error TooManyInitialGuardians();

    /**
     * @dev Emitted when the initial guardian is changed.
     */
    event InitialGuardianUpdated(address indexed oldInitialGuardian, address indexed newInitialGuardian);

    constructor(
        address _owner,
        address _entrypoint,
        address _accountImplementation,
        uint256 _recoveryPeriod,
        uint256 _securityPeriod,
        uint256 _securityWindow,
        uint256 _lockPeriod,
        address _initialGuardian
    ) BaseOpenfortFactory(_owner, _entrypoint, _accountImplementation) {
        if (_lockPeriod < _recoveryPeriod || _recoveryPeriod < _securityPeriod + _securityWindow) {
            revert InsecurePeriod();
        }
        recoveryPeriod = _recoveryPeriod;
        securityPeriod = _securityPeriod;
        securityWindow = _securityWindow;
        lockPeriod = _lockPeriod;
        if (_initialGuardian == address(0)) revert ZeroAddressNotAllowed();
        initialGuardian = _initialGuardian;
    }

    function updateInitialGuardian(address _newInitialGuardian) external onlyOwner {
        if (_newInitialGuardian == address(0)) revert ZeroAddressNotAllowed();
        emit InitialGuardianUpdated(initialGuardian, _newInitialGuardian);
        initialGuardian = _newInitialGuardian;
    }

    /*
     * @notice Deploy a new account for _admin with a _nonce.
     */
    function createAccountWithNonce(address _admin, bytes32 _nonce, bool _initializeGuardian)
        external
        returns (address account)
    {
        bytes32 salt = keccak256(abi.encode(_admin, _nonce));
        account = getAddressWithNonce(_admin, _nonce);

        if (account.code.length > 0) return account;

        emit AccountCreated(account, _admin);
        account = address(new UpgradeableOpenfortProxy{salt: salt}(_implementation, ""));

        UpgradeableOpenfortAccount(payable(account))
            .initialize(
                _admin,
                entrypointContract,
                recoveryPeriod,
                securityPeriod,
                securityWindow,
                lockPeriod,
                _initializeGuardian ? initialGuardian : address(0)
            );
    }

    /*
     * @notice Return the address of an account that would be deployed with the given _admin signer and _nonce.
     */
    function getAddressWithNonce(address _admin, bytes32 _nonce) public view returns (address) {
        bytes32 salt = keccak256(abi.encode(_admin, _nonce));
        return Create2.computeAddress(
            salt,
            keccak256(abi.encodePacked(type(UpgradeableOpenfortProxy).creationCode, abi.encode(_implementation, "")))
        );
    }
}
