// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {BaseAccount, UserOperation} from "account-abstraction/core/BaseAccount.sol";

// Interfaces
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {IBaseAccountFactory} from "../interfaces/IBaseAccountFactory.sol";

/**
 * BaseAccountFactory
 * 
 * 
 */
abstract contract BaseAccountFactory is IBaseAccountFactory {
    address public immutable accountImplementation;

    constructor(address _accountImpl) {
        accountImplementation = _accountImpl;
    }

    /// @notice Deploys a new Account for admin.
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

    /// @notice Returns the address of an Account that would be deployed with the given admin signer.
    function getAddress(address _adminSigner) public view returns (address) {
        bytes32 salt = keccak256(abi.encode(_adminSigner));
        return Clones.predictDeterministicAddress(accountImplementation, salt);
    }

    /* @dev Called in `createAccount`.
     * Initializes the account contract created in `createAccount`.
     */
    function _initializeAccount(
        address _account,
        address _admin,
        bytes calldata _data
    ) internal virtual;
}
