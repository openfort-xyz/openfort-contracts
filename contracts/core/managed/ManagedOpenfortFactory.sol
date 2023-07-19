// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";

// Smart wallet implementation to use
import {ManagedOpenfortAccount} from "./ManagedOpenfortAccount.sol";
import {OpenfortBeaconProxy} from "./OpenfortBeaconProxy.sol";

// Interfaces
import {IBaseOpenfortFactory} from "../../interfaces/IBaseOpenfortFactory.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

/**
 * @title ManagedOpenfortFactory (Non-upgradeable)
 * @author Eloi<eloi@openfort.xyz>
 * @notice Contract to create an on-chain factory to deploy new ManagedOpenfortAccounts.
 * It uses OpenZeppelin's Create2 and OpenfortBeaconProxy libraries.
 * It inherits from:
 *  - IBaseOpenfortFactory
 *  - UpgradeableBeacon to also work as the beacon
 */
contract ManagedOpenfortFactory is IBaseOpenfortFactory, UpgradeableBeacon {
    address internal entrypointContract;

    constructor(address _owner, address _entrypoint, address _implementation) UpgradeableBeacon(_implementation) {
        _transferOwnership(_owner);
        entrypointContract = _entrypoint;
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
            new OpenfortBeaconProxy{salt: salt}(
                address(this),
                abi.encodeCall(ManagedOpenfortAccount.initialize, (_admin))
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
                    type(OpenfortBeaconProxy).creationCode,
                    abi.encode(address(this), abi.encodeCall(ManagedOpenfortAccount.initialize, (_admin)))
                )
            )
        );
    }

    function accountImplementation() external view override returns (address) {
        return implementation();
    }

    /**
     * Add stake for this factory.
     * This method can also carry eth value to add to the current stake.
     * @param unstakeDelaySec - the unstake delay for this factory. Can only be increased.
     */
    function addStake(uint32 unstakeDelaySec) external payable onlyOwner {
        IEntryPoint(entrypointContract).addStake{value : msg.value}(unstakeDelaySec);
    }
}
