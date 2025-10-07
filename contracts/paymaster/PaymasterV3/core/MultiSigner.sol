// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {ManagerAccessControl} from "./ManagerAccessControl.sol";
import {EnumerableSet} from "@oz-v5.4.0/utils/structs/EnumerableSet.sol";

/**
 * Helper class for creating a contract with multiple valid signers.
 */
abstract contract MultiSigner is ManagerAccessControl {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           USING                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
    using EnumerableSet for EnumerableSet.AddressSet;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
    error MultiSigner__SignerNotExist();
    error MultiSigner__SignerAlreadyExist();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Emitted when a signer is added.
    event SignerAdded(address signer);

    /// @notice Emitted when a signer is removed.
    event SignerRemoved(address signer);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STORAGE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Mapping of valid signers.
    mapping(address account => bool isValidSigner) public signers;
    EnumerableSet.AddressSet private _signerSet;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CONSTRUCTOR                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    constructor(address[] memory _initialSigners) {
        for (uint256 i = 0; i < _initialSigners.length;) {
            signers[_initialSigners[i]] = true;
            _signerSet.add(_initialSigners[i]);
            emit SignerAdded(_initialSigners[i]);
            unchecked {
                i++;
            }
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      ADMIN FUNCTIONS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function removeSigner(address _signer) public onlyAdminOrManager {
        signers[_signer] = false;
        bool isExist = _signerSet.remove(_signer);
        if (!isExist) revert MultiSigner__SignerNotExist();
        emit SignerRemoved(_signer);
    }

    function addSigner(address _signer) public onlyAdminOrManager {
        signers[_signer] = true;
        bool isExist = _signerSet.add(_signer);
        if (!isExist) revert MultiSigner__SignerAlreadyExist();
        emit SignerAdded(_signer);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    ENUMERATION HELPERS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Total number of current signers.
    function signerCount() public view returns (uint256) {
        return _signerSet.length();
    }

    /// @notice Get signer at a specific index (0 <= index < signerCount()).
    function signerAt(uint256 index) public view returns (address) {
        return _signerSet.at(index);
    }

    /// @notice Return all signers as an array (copies to memory).
    function getSigners() public view returns (address[] memory) {
        return _signerSet.values();
    }
}
