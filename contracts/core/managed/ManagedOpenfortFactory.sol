// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {BeaconProxy} from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
// Smart wallet implementation to use
import {ManagedOpenfortAccount} from "./ManagedOpenfortAccount.sol";
import {OpenfortBeacon} from "./OpenfortBeacon.sol";
// Interfaces
import {IBaseOpenfortFactory} from "../../interfaces/IBaseOpenfortFactory.sol";

/**
 * @title ManagedOpenfortFactory (Non-upgradeable)
 * @author Eloi<eloi@openfort.xyz>
 * @notice Contract to create an on-chain factory to deploy new ManagedOpenfortAccounts.
 * It uses OpenZeppelin's Create2 and BeaconProxy libraries.
 * It inherits from:
 *  - IBaseOpenfortFactory
 */
contract ManagedOpenfortFactory is IBaseOpenfortFactory {
    address public immutable entrypointContract;
    address public immutable openfortBeacon;

    constructor(address _entrypoint, address _openfortBeacon) {
        if (_entrypoint == address(0) || _openfortBeacon == address(0)) {
            revert ZeroAddressNotAllowed();
        }
        entrypointContract = _entrypoint;
        openfortBeacon = _openfortBeacon;
    }

    /*
     * @notice Deploy a new Account for _admin.
     */
    function createAccount(address _admin, bytes calldata _data) external returns (address account) {
        bytes32 salt = keccak256(abi.encode(_admin));
        account = getAddress(_admin);

        if (account.code.length > 0) {
            return account;
        }

        emit AccountCreated(account, _admin);
        account = address(
            new BeaconProxy{salt: salt}(
            openfortBeacon,
            abi.encodeCall(ManagedOpenfortAccount.initialize, (_admin, entrypointContract, _data))
            )
        );
    }

    /*
     * @notice Deploy a new account for _admin with a nonce.
     */
    function createAccountWithNonce(address _admin, bytes calldata _data, uint256 nonce)
        external
        returns (address account)
    {
        bytes32 salt = keccak256(abi.encode(_admin, nonce));
        account = getAddressWithNonce(_admin, nonce);

        if (account.code.length > 0) {
            return account;
        }

        emit AccountCreated(account, _admin);
        account = address(
            new BeaconProxy{salt: salt}(
                openfortBeacon,
                abi.encodeCall(ManagedOpenfortAccount.initialize, (_admin, entrypointContract, _data))
            )
        );
    }

    /*
     * @notice Return the address of an account that would be deployed with the given admin signer.
     */
    function getAddress(address _admin) public view returns (address) {
        bytes32 salt = keccak256(abi.encode(_admin));
        return Create2.computeAddress(
            bytes32(salt),
            keccak256(
                abi.encodePacked(
                    type(BeaconProxy).creationCode,
                    abi.encode(
                        openfortBeacon,
                        abi.encodeCall(ManagedOpenfortAccount.initialize, (_admin, entrypointContract, ""))
                    )
                )
            )
        );
    }

    /*
     * @notice Return the address of an account that would be deployed with the given admin signer and nonce.
     */
    function getAddressWithNonce(address _admin, uint256 nonce) public view returns (address) {
        bytes32 salt = keccak256(abi.encode(_admin, nonce));
        return Create2.computeAddress(
            bytes32(salt),
            keccak256(
                abi.encodePacked(
                    type(BeaconProxy).creationCode,
                    abi.encode(
                        openfortBeacon,
                        abi.encodeCall(ManagedOpenfortAccount.initialize, (_admin, entrypointContract, ""))
                    )
                )
            )
        );
    }

    function accountImplementation() external view override returns (address) {
        return OpenfortBeacon(openfortBeacon).implementation();
    }
}
