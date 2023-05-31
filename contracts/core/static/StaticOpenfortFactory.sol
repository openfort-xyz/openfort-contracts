// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
// Smart wallet implementation to use
import {StaticOpenfortAccount} from "./StaticOpenfortAccount.sol";
// Interfaces
import {IBaseOpenfortFactory} from "../../interfaces/IBaseOpenfortFactory.sol";

/**
 * @title StaticOpenfortFactory (Non-upgradeable)
 * @author Eloi<eloi@openfort.xyz>
 * @notice Contract to create an on-chain factory to deploy new StaticOpenfortAccounts using OpenZeppelin's Clones library.
 * As explained by OZ: The Clones library provides a way to deploy minimal non-upgradeable proxies for cheap.
 * This can be useful for applications that require deploying many instances of the same contract (for example one per user, or one per task).
 * These instances are designed to be both cheap to deploy, and cheap to call.
 * The drawback being that they are not upgradeable.
 * It inherits from:
 *  - IBaseOpenfortFactory
 */
contract StaticOpenfortFactory is IBaseOpenfortFactory {
    address public immutable entrypointContract;
    address public immutable accountImplementation;

    constructor(address _entrypoint, address _accountImplementation) {
        if (_entrypoint == address(0) || _accountImplementation == address(0)) {
            revert ZeroAddressNotAllowed();
        }
        entrypointContract = _entrypoint;
        accountImplementation = _accountImplementation;
    }

    /*
     * @notice Deploy a new account for _admin.
     */
    function createAccount(address _admin, bytes calldata _data) external returns (address account) {
        address impl = accountImplementation;
        bytes32 salt = keccak256(abi.encode(_admin));
        account = Clones.predictDeterministicAddress(impl, salt);

        if (account.code.length > 0) {
            return account;
        }

        emit AccountCreated(account, _admin);
        account = Clones.cloneDeterministic(impl, salt);
        _initializeAccount(account, _admin, entrypointContract, _data);
    }

    /*
     * @notice Deploy a new account for _admin and a given nonce.
     */
    function createAccountWithNonce(address _admin, bytes calldata _data, uint256 nonce)
        external
        returns (address account)
    {
        address impl = accountImplementation;
        bytes32 salt = keccak256(abi.encode(_admin, nonce));
        account = Clones.predictDeterministicAddress(impl, salt);

        if (account.code.length > 0) {
            return account;
        }

        emit AccountCreated(account, _admin);
        account = Clones.cloneDeterministic(impl, salt);
        _initializeAccount(account, _admin, entrypointContract, _data);
    }

    /*
     * @notice Return the address of an account that would be deployed with the given admin signer.
     */
    function getAddress(address _adminSigner) public view returns (address) {
        bytes32 salt = keccak256(abi.encode(_adminSigner));
        return Clones.predictDeterministicAddress(accountImplementation, salt);
    }

    /*
     * @notice Return the address of an account that would be deployed with the given admin signer and nonce.
     */
    function getAddressWithNonce(address _adminSigner, uint256 nonce) public view returns (address) {
        bytes32 salt = keccak256(abi.encode(_adminSigner, nonce));
        return Clones.predictDeterministicAddress(accountImplementation, salt);
    }

    /*
     * @dev Called in `createAccount`. Initializes the account contract created in `createAccount`.
     */
    function _initializeAccount(address _account, address _admin, address _entrypointContract, bytes calldata _data)
        internal
    {
        StaticOpenfortAccount(payable(_account)).initialize(_admin, _entrypointContract, _data);
    }
}
