// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
// Smart wallet implementation to use
import {RecoverableOpenfortAccount} from "./RecoverableOpenfortAccount.sol";
import {OpenfortRecoverableProxy} from "./OpenfortRecoverableProxy.sol";
// Interfaces
import {IBaseOpenfortFactory} from "../../interfaces/IBaseOpenfortFactory.sol";

/**
 * @title RecoverableOpenfortFactory (Non-upgradeable)
 * @notice Contract to create an on-chain factory to deploy new RecoverableOpenfortAccounts.
 * It uses OpenZeppelin's Create2 and OpenfortRecoverableProxy libraries.
 * It inherits from:
 *  - IBaseOpenfortFactory
 */
contract RecoverableOpenfortFactory is IBaseOpenfortFactory {
    address public immutable entrypointContract;
    address public immutable accountImplementation;
    uint256 public immutable recoveryPeriod;
    uint256 public immutable securityPeriod;
    uint256 public immutable securityWindow;
    uint256 public immutable lockPeriod;
    address public immutable openfortGuardian;

    error InsecurePeriod();

    constructor(
        address _entrypoint,
        address _accountImplementation,
        uint256 _recoveryPeriod,
        uint256 _securityPeriod,
        uint256 _securityWindow,
        uint256 _lockPeriod,
        address _openfortGuardian
    ) {
        if (_entrypoint == address(0) || _accountImplementation == address(0) || _openfortGuardian == address(0)) {
            revert ZeroAddressNotAllowed();
        }
        if (_lockPeriod < _recoveryPeriod || _recoveryPeriod < _securityPeriod + _securityWindow) {
            revert InsecurePeriod();
        }
        entrypointContract = _entrypoint;
        accountImplementation = _accountImplementation;
        recoveryPeriod = _recoveryPeriod;
        securityPeriod = _securityPeriod;
        securityWindow = _securityWindow;
        lockPeriod = _lockPeriod;
        openfortGuardian = _openfortGuardian;
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
            new OpenfortRecoverableProxy{salt: salt}(
                accountImplementation,
                abi.encodeCall(
                    RecoverableOpenfortAccount.initialize,
                    (
                        _admin,
                        entrypointContract,
                        recoveryPeriod,
                        securityPeriod,
                        securityWindow,
                        lockPeriod,
                        openfortGuardian)
                    )
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
                    type(OpenfortRecoverableProxy).creationCode,
                    abi.encode(
                        accountImplementation,
                        abi.encodeCall(
                            RecoverableOpenfortAccount.initialize,
                            (
                                _admin,
                                entrypointContract,
                                recoveryPeriod,
                                securityPeriod,
                                securityWindow,
                                lockPeriod,
                                openfortGuardian
                            )
                        )
                    )
                )
            )
        );
    }
}
