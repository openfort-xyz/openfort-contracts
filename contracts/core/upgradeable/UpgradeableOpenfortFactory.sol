// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/utils/Create2.sol";
// Smart wallet implementation to use
import {UpgradeableOpenfortAccount} from "./UpgradeableOpenfortAccount.sol";
// Interfaces
import {IBaseOpenfortFactory} from "../../interfaces/IBaseOpenfortFactory.sol";

/**
 * @title UpgradeableOpenfortFactory (Non-upgradeable)
 * @author Eloi<eloi@openfort.xyz>
 * @notice Factory to deploy UpgradeableOpenfortAccounts
 * It inherits from:
 *  - IBaseOpenfortFactory
 */
contract UpgradeableOpenfortFactory is IBaseOpenfortFactory {
    address public immutable entrypointContract;
    address public immutable accountImplementation;

    constructor(address _entrypoint) {
        require(_entrypoint != address(0), "_entrypoint cannot be 0");
        entrypointContract = _entrypoint;
        accountImplementation = address(new UpgradeableOpenfortAccount());
    }

    /*
     * @notice Deploy a new Account for _admin.
     */
    function createAccount(address _admin, bytes calldata _data) external returns (address) {
        bytes32 salt = keccak256(abi.encode(_admin));
        address account = getAddress(_admin);

        if (account.code.length > 0) {
            return account;
        }

        UpgradeableOpenfortAccount newUpgradeableOpenfortAccount = UpgradeableOpenfortAccount(
            payable(
                new ERC1967Proxy{salt : bytes32(salt)}(
                address(accountImplementation),
                abi.encodeCall(UpgradeableOpenfortAccount.initialize, (_admin, entrypointContract, _data))
                )
            )
        );

        emit AccountCreated(account, _admin);

        return address(newUpgradeableOpenfortAccount);
    }

    /*
     * @notice Deploy a new Account for _admin.
     */
    function createAccountWithNonce(address _admin, bytes calldata _data, uint256 nonce) external returns (address) {
        bytes32 salt = keccak256(abi.encode(_admin, nonce));
        address account = getAddressWithNonce(_admin, nonce);

        if (account.code.length > 0) {
            return account;
        }

        UpgradeableOpenfortAccount newUpgradeableOpenfortAccount = UpgradeableOpenfortAccount(
            payable(
                new ERC1967Proxy{salt : bytes32(salt)}(
                address(accountImplementation),
                abi.encodeCall(UpgradeableOpenfortAccount.initialize, (_admin, entrypointContract, _data))
                )
            )
        );

        emit AccountCreated(account, _admin);

        return address(newUpgradeableOpenfortAccount);
    }

    /*
     * @notice Return the address of an Account that would be deployed with the given admin signer.
     */
    function getAddress(address _admin) public view returns (address) {
        bytes32 salt = keccak256(abi.encode(_admin));
        return Create2.computeAddress(
            bytes32(salt),
            keccak256(
                abi.encodePacked(
                    type(ERC1967Proxy).creationCode,
                    abi.encode(
                        address(accountImplementation),
                        abi.encodeCall(UpgradeableOpenfortAccount.initialize, (_admin, entrypointContract, ""))
                    )
                )
            )
        );
    }

    /*
     * @notice Return the address of an Account that would be deployed with the given admin signer.
     */
    function getAddressWithNonce(address _admin, uint256 nonce) public view returns (address) {
        bytes32 salt = keccak256(abi.encode(_admin, nonce));
        return Create2.computeAddress(
            bytes32(salt),
            keccak256(
                abi.encodePacked(
                    type(ERC1967Proxy).creationCode,
                    abi.encode(
                        address(accountImplementation),
                        abi.encodeCall(UpgradeableOpenfortAccount.initialize, (_admin, entrypointContract, ""))
                    )
                )
            )
        );
    }
}
