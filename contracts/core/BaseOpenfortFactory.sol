// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {BaseAccount, UserOperation} from "account-abstraction/core/BaseAccount.sol";

// Interfaces
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {IBaseOpenfortFactory} from "../interfaces/IBaseOpenfortFactory.sol";

/**
  * @title BaseOpenfortFactory (Non-upgradeable)
  * @author Eloi<eloi@openfort.xyz>
  * @notice Abstract contract to create account factories
  * It inherits from:
  *  - IBaseOpenfortFactory
  */
abstract contract BaseOpenfortFactory is IBaseOpenfortFactory {
    address public immutable accountImplementation;

    constructor(address _accountImpl) {
        accountImplementation = _accountImpl;
    }

    /*
     * @notice Deploy a new Account for _admin.
     */
    function createAccount(address _admin, bytes calldata _data) external virtual override returns (address) {
        address impl = accountImplementation;
        bytes32 salt = keccak256(abi.encode(_admin));
        address account = Clones.predictDeterministicAddress(impl, salt);

        if (account.code.length > 0) {
            return account;
        }

        account = Clones.cloneDeterministic(impl, salt);

        _initializeAccount(account, _admin, _data);

        emit AccountCreated(account, _admin);

        return account;
    }

    /*
     * @notice Deploy a new Account for _admin and a given nonce.
     */
    function createAccountWithNonce(address _admin, bytes calldata _data, uint256 nonce) external virtual override returns (address) {
        address impl = accountImplementation;
        bytes32 salt = keccak256(abi.encode(_admin, nonce));
        address account = Clones.predictDeterministicAddress(impl, salt);

        if (account.code.length > 0) {
            return account;
        }

        account = Clones.cloneDeterministic(impl, salt);

        _initializeAccount(account, _admin, _data);

        emit AccountCreated(account, _admin);

        return account;
    }

    /*
     * @notice Return the address of an Account that would be deployed with the given admin signer.
     */
    function getAddress(address _adminSigner) public view returns (address) {
        bytes32 salt = keccak256(abi.encode(_adminSigner));
        return Clones.predictDeterministicAddress(accountImplementation, salt);
    }

    /*
     * @notice Return the address of an Account that would be deployed with the given admin signer and nonce.
     */
    function getAddressWithNonce(address _adminSigner, uint256 nonce) public view returns (address) {
        bytes32 salt = keccak256(abi.encode(_adminSigner, nonce));
        return Clones.predictDeterministicAddress(accountImplementation, salt);
    }

    /*
     * @dev Called in `createAccount`.
     * Initializes the account contract created in `createAccount`.
     */
    function _initializeAccount(
        address _account,
        address _admin,
        bytes calldata _data
    ) internal virtual;
}
