// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
// Smart wallet implementation to use
import {UpgradeableOpenfortAccount} from "./UpgradeableOpenfortAccount.sol";
import {OpenfortUpgradeableProxy} from "./OpenfortUpgradeableProxy.sol";
// Interfaces
import {IBaseOpenfortFactory} from "../../interfaces/IBaseOpenfortFactory.sol";

/**
 * @title UpgradeableOpenfortFactory (Non-upgradeable)
 * @author Eloi<eloi@openfort.xyz>
 * @notice Contract to create an on-chain factory to deploy new UpgradeableOpenfortAccounts.
 * It uses OpenZeppelin's Create2 and OpenfortUpgradeableProxy libraries.
 * It inherits from:
 *  - IBaseOpenfortFactory
 */
contract UpgradeableOpenfortFactory is IBaseOpenfortFactory {
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
     * @notice Deploy a new account for _admin with a nonce.
     */
    function createAccountWithNonce(address _admin, bytes32 _nonce) external returns (address account) {
        bytes32 salt = keccak256(abi.encode(_admin, _nonce));
        account = getAddressWithNonce(_admin, _nonce);

        if (account.code.length > 0) {
            return account;
        }

        emit AccountCreated(account, _admin);
        account = address(
            new OpenfortUpgradeableProxy{salt: salt}(
                accountImplementation,
                abi.encodeCall(UpgradeableOpenfortAccount.initialize, (_admin, entrypointContract))
            )
        );
    }

    /*
     * @notice Return the address of an account that would be deployed with the given admin signer and nonce.
     */
    function getAddressWithNonce(address _admin, bytes32 _nonce) public view returns (address) {
        bytes32 salt = keccak256(abi.encode(_admin, _nonce));
        return Create2.computeAddress(
            salt,
            keccak256(
                abi.encodePacked(
                    type(OpenfortUpgradeableProxy).creationCode,
                    abi.encode(
                        accountImplementation,
                        abi.encodeCall(UpgradeableOpenfortAccount.initialize, (_admin, entrypointContract))
                    )
                )
            )
        );
    }
}
