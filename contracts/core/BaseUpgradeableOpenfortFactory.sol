// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import {ClonesUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/ClonesUpgradeable.sol";

// Interfaces
import {IBaseOpenfortFactory} from "../interfaces/IBaseOpenfortFactory.sol";

/**
 * @title BaseUpgradeableOpenfortFactory (Non-upgradeable)
 * @author Eloi<eloi@openfort.xyz>
 * @notice Abstract contract to create account factories
 * It inherits from:
 *  - IBaseOpenfortFactory
 */
abstract contract BaseUpgradeableOpenfortFactory is IBaseOpenfortFactory {
    address public immutable entrypointContract;
    address public immutable accountImplementation;

    constructor(address _accountImpl, address _entrypoint) {
        require(_accountImpl != address(0), "_accountImpl cannot be 0");
        require(_entrypoint != address(0), "_entrypoint cannot be 0");
        entrypointContract = _entrypoint;
        accountImplementation = _accountImpl;
    }

    /*
     * @notice Deploy a new Account for _admin.
     */
    function createAccount(address _admin, bytes calldata _data) external virtual override returns (address) {
        address impl = accountImplementation;
        bytes32 salt = keccak256(abi.encode(_admin));
        address account = ClonesUpgradeable.predictDeterministicAddress(impl, salt);

        if (account.code.length > 0) {
            return account;
        }

        account = ClonesUpgradeable.cloneDeterministic(impl, salt);

        _initializeAccount(account, _admin, entrypointContract, _data);

        emit AccountCreated(account, _admin);

        return account;
    }

    /*
     * @notice Deploy a new Account for _admin and a given nonce.
     */
    function createAccountWithNonce(address _admin, bytes calldata _data, uint256 nonce)
        external
        virtual
        override
        returns (address)
    {
        address impl = accountImplementation;
        bytes32 salt = keccak256(abi.encode(_admin, nonce));
        address account = ClonesUpgradeable.predictDeterministicAddress(impl, salt);

        if (account.code.length > 0) {
            return account;
        }

        account = ClonesUpgradeable.cloneDeterministic(impl, salt);

        _initializeAccount(account, _admin, entrypointContract, _data);

        emit AccountCreated(account, _admin);

        return account;
    }

    /*
     * @notice Return the address of an Account that would be deployed with the given admin signer.
     */
    function getAddress(address _adminSigner) public view returns (address) {
        bytes32 salt = keccak256(abi.encode(_adminSigner));
        return ClonesUpgradeable.predictDeterministicAddress(accountImplementation, salt);
    }

    /*
     * @notice Return the address of an Account that would be deployed with the given admin signer and nonce.
     */
    function getAddressWithNonce(address _adminSigner, uint256 nonce) public view returns (address) {
        bytes32 salt = keccak256(abi.encode(_adminSigner, nonce));
        return ClonesUpgradeable.predictDeterministicAddress(accountImplementation, salt);
    }

    /*
     * @dev Called in `createAccount`.
     * Initializes the account contract created in `createAccount`.
     */
    function _initializeAccount(address _account, address _admin, address _entrypointContract, bytes calldata _data)
        internal
        virtual;
}
