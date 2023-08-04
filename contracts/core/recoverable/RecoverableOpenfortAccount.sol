// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

// Base account contract to inherit from and EntryPoint interface
import {BaseOpenfortAccount, IEntryPoint, SafeCastUpgradeable, ECDSAUpgradeable} from "../BaseOpenfortAccount.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/**
 * @title RecoverableOpenfortAccount
 * @author Eloi<eloi@openfort.xyz>
 * @notice Openfort account with session keys, guardians and pausability following the ERC-4337 standard.
 * It inherits from:
 *  - BaseOpenfortAccount
 *  - UUPSUpgradeable
 */
contract RecoverableOpenfortAccount is BaseOpenfortAccount, UUPSUpgradeable {
    using ECDSAUpgradeable for bytes32;

    address internal entrypointContract;

    // Period during which the owner can cancel a guardian proposal/revocation in seconds (7 days)
    uint256 internal recoveryPeriod;
    // Default lock period (cannot be modified)
    uint256 internal lockPeriod;
    // The security period to add/remove guardians
    uint256 internal securityPeriod;
    // The security window
    uint256 internal securityWindow;

    struct GuardianInfo {
        bool exists; // Whether the guardian is active/exists or not
        uint256 index; // Position of the guardian
        uint256 pending; // Timestamp when the addition or removal of a guardian can take place
    }

    struct GuardiansConfig {
        address[] guardians; // list of guardian addresses
        mapping(address => GuardianInfo) info; // info about guardians
        uint256 lock; // Lock's release timestamp
    }

    struct RecoveryConfig {
        address recoveryAddress; // Address to which ownership should be transferred
        uint64 executeAfter; // Timestamp after which the recovery process can be finalized
        uint32 guardiansRequired; // Number of guardian signatures needed to recover
    }

    GuardiansConfig internal guardiansConfig;
    RecoveryConfig public recoveryDetails;

    // keccak256("Recover(address recoveryAddress,uint64 executeAfter,uint32 guardiansRequired)");
    bytes32 public constant RECOVER_TYPEHASH = 0x9f7aca777caf11405930359f601a4db01fad1b2d79ef3f2f9e93c835e9feffa5;

    event EntryPointUpdated(address oldEntryPoint, address newEntryPoint);
    event Locked(bool isLocked);
    event GuardianProposed(address indexed guardian, uint256 executeAfter);
    event GuardianAdded(address indexed guardian);
    event GuardianProposalCancelled(address indexed guardian);
    event GuardianRevocationRequested(address indexed guardian, uint256 executeAfter);
    event GuardianRevoked(address indexed guardian);
    event GuardianRevocationCancelled(address indexed guardian);
    event RecoveryExecuted(address indexed recoveryAddress, uint64 executeAfter);
    event RecoveryCompleted(address indexed recoveryAddress);
    event RecoveryCanceled(address indexed recoveryAddress);

    error AccountLocked();
    error AccountNotLocked();
    error CannotUnlock();
    error InsecurePeriod();
    error MustBeGuardian();
    error DuplicatedGuardian();
    error GuardianCannotBeOwner();
    error DuplicatedProposal();
    error UnknownProposal();
    error PendingProposalNotOver();
    error PendingProposalExpired();
    error DuplicatedRevoke();
    error UnknownRevoke();
    error PendingRevokeNotOver();
    error PendingRevokeExpired();
    error NoOngoingRecovery();
    error OngoingRecovery();
    error InvalidRecoverySignatures();
    error InvalidSignatureAmount();

    /*
     * @notice Initialize the smart contract account.
     */
    function initialize(
        address _defaultAdmin,
        address _entrypoint,
        uint256 _recoveryPeriod,
        uint256 _securityPeriod,
        uint256 _securityWindow,
        uint256 _lockPeriod,
        address _openfortGuardian
    ) public initializer {
        if (_defaultAdmin == address(0) || _entrypoint == address(0) || _openfortGuardian == address(0)) {
            revert ZeroAddressNotAllowed();
        }
        if (_lockPeriod < _recoveryPeriod || _recoveryPeriod < _securityPeriod + _securityWindow) {
            revert InsecurePeriod();
        }
        emit EntryPointUpdated(entrypointContract, _entrypoint);
        _transferOwnership(_defaultAdmin);
        entrypointContract = _entrypoint;
        __EIP712_init("Openfort", "0.4");

        recoveryPeriod = _recoveryPeriod;
        lockPeriod = _lockPeriod;
        securityWindow = _securityWindow;
        securityPeriod = _securityPeriod;

        guardiansConfig.guardians.push(_openfortGuardian);
        guardiansConfig.info[_openfortGuardian].exists = true;
        guardiansConfig.info[_openfortGuardian].index = 0;
        guardiansConfig.info[_openfortGuardian].pending = 0;
        emit GuardianAdded(_openfortGuardian);
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    /**
     * Return the current EntryPoint
     */
    function entryPoint() public view override returns (IEntryPoint) {
        return IEntryPoint(entrypointContract);
    }

    /**
     * Update the EntryPoint address
     */
    function updateEntryPoint(address _newEntrypoint) external onlyOwner {
        if (_newEntrypoint == address(0)) revert ZeroAddressNotAllowed();
        emit EntryPointUpdated(entrypointContract, _newEntrypoint);
        entrypointContract = _newEntrypoint;
    }

    /**
     * Locking functionalities *
     */

    /**
     * @notice Helper method to check if a wallet is locked.
     */
    function isLocked() public view returns (bool) {
        return guardiansConfig.lock > block.timestamp;
    }

    /**
     * @notice Returns the release time of a wallet lock or 0 if the wallet is unlocked.
     * @return _releaseAfter The epoch time at which the lock will release (in seconds).
     */
    function getLock() external view returns (uint256 _releaseAfter) {
        _releaseAfter = isLocked() ? guardiansConfig.lock : 0;
    }

    /**
     * @notice Lets a guardian lock a wallet.
     */
    function lock() external {
        if (!isGuardian(msg.sender)) revert MustBeGuardian();
        if (isLocked()) revert AccountLocked();
        _setLock(block.timestamp + lockPeriod);
    }

    /**
     * @notice Lets a guardian unlock a locked wallet.
     */
    function unlock() external {
        if (!isGuardian(msg.sender)) revert MustBeGuardian();
        if (!isLocked()) revert AccountNotLocked();
        _setLock(0);
    }

    /**
     * @notice Internal function to modify the lock status.
     */
    function _setLock(uint256 _releaseAfter) internal {
        emit Locked(_releaseAfter != 0);
        guardiansConfig.lock = _releaseAfter;
    }

    /**
     * Guardians functionalities *
     */

    /**
     * @notice Returns the number of guardians for the Openfort account.
     * @return the number of guardians.
     */
    function guardianCount() public view returns (uint256) {
        return guardiansConfig.guardians.length;
    }

    /**
     * @notice Gets the list of guardians for the Openfort account.
     * @return the list of guardians.
     */
    function getGuardians() external view returns (address[] memory) {
        address[] memory guardians = new address[](guardiansConfig.guardians.length);
        for (uint256 i = 0; i < guardiansConfig.guardians.length;) {
            guardians[i] = guardiansConfig.guardians[i];
            unchecked {
                ++i; // gas optimization
            }
        }
        return guardians;
    }

    /**
     * @notice Checks if an account is a guardian for an Openfort account.
     * @param _guardian The guardian address to query
     * @return true if the account is a guardian for the account.
     */
    function isGuardian(address _guardian) public view returns (bool) {
        return guardiansConfig.info[_guardian].exists;
    }

    /**
     * @notice Checks if an address is a guardian or an account authorised to sign on behalf of a smart-contract guardian.
     * @param _guardian the address to test
     * @return _isGuardian `true` if the address is a guardian for the wallet otherwise `false`.
     */
    function isGuardianOrGuardianSigner(address _guardian) external pure returns (bool _isGuardian) {
        (_guardian);
        _isGuardian = false; // ToDo for smart contract wallets acting as guardians in the future
    }

    /**
     * @notice Lets the owner propose a guardian to its Openfort account.
     * The first guardian is added immediately (see constructor). All following proposals must be confirmed
     * by calling the confirmGuardianProposal() method. Only the owner can add guardians.
     * @param _guardian The guardian to propose.
     */
    function proposeGuardian(address _guardian) external onlyOwner {
        if (isLocked()) revert AccountLocked();
        if (owner() == _guardian) revert GuardianCannotBeOwner();
        if (isGuardian(_guardian)) revert DuplicatedGuardian();

        // Guardians must either be an EOA or a contract with an owner() (ERC-173)
        // method that returns an address with a 25000 gas stipend.
        // Note that this test is not meant to be strict and can be bypassed by custom malicious contracts.
        (bool success,) = _guardian.call{gas: 25000}(abi.encodeWithSignature("owner()"));
        require(success, "Must be an EOA or an ownable wallet");

        if (
            guardiansConfig.info[_guardian].pending != 0
                && block.timestamp < guardiansConfig.info[_guardian].pending + securityWindow
        ) {
            revert DuplicatedProposal();
        }
        guardiansConfig.info[_guardian].pending = block.timestamp + securityPeriod;
        emit GuardianProposed(_guardian, guardiansConfig.info[_guardian].pending);
    }

    /**
     * @notice Confirms the pending proposal of a guardian to an account.
     * The method must be called during the confirmation window and can be called by anyone.
     * @param _guardian The guardian to be confirmed.
     */
    function confirmGuardianProposal(address _guardian) external {
        if (isLocked()) revert AccountLocked();
        if (guardiansConfig.info[_guardian].pending == 0) revert UnknownProposal();
        if (guardiansConfig.info[_guardian].pending > block.timestamp) revert PendingProposalNotOver();
        if (block.timestamp > guardiansConfig.info[_guardian].pending + securityWindow) revert PendingProposalExpired();
        if (isGuardian(_guardian)) revert DuplicatedGuardian();

        guardiansConfig.guardians.push(_guardian);
        guardiansConfig.info[_guardian].exists = true;
        guardiansConfig.info[_guardian].index = guardiansConfig.guardians.length;
        guardiansConfig.info[_guardian].pending = 0;
        emit GuardianAdded(_guardian);
    }

    /**
     * @notice Lets the owner cancel a pending guardian addition.
     * @param _guardian The guardian which proposal will be cancelled.
     */
    function cancelGuardianProposal(address _guardian) external onlyOwner {
        if (isLocked()) revert AccountLocked();
        if (guardiansConfig.info[_guardian].pending == 0) revert UnknownProposal();
        guardiansConfig.info[_guardian].pending = 0;
        emit GuardianProposalCancelled(_guardian);
    }

    /**
     * @notice Lets the owner revoke a guardian from its wallet.
     * @dev Revocation must be confirmed by calling the confirmGuardianRevocation() method.
     * @param _guardian The guardian to revoke.
     */
    function revokeGuardian(address _guardian) external onlyOwner {
        if (!isGuardian(_guardian)) revert MustBeGuardian();
        if (
            guardiansConfig.info[_guardian].pending > 0
                && block.timestamp < guardiansConfig.info[_guardian].pending + securityWindow
        ) revert DuplicatedRevoke();
        // TODO need to allow if confirmation window passed
        guardiansConfig.info[_guardian].pending = block.timestamp + securityPeriod;
        emit GuardianRevocationRequested(_guardian, guardiansConfig.info[_guardian].pending);
    }

    /**
     * @notice Confirms the pending revocation of a guardian to an Openfort account.
     * The method must be called during the confirmation window and can be called by anyone.
     * @param _guardian The guardian to confirm the revocation.
     */
    function confirmGuardianRevocation(address _guardian) external {
        if (guardiansConfig.info[_guardian].pending == 0) revert UnknownRevoke();
        if (!isGuardian(_guardian)) revert MustBeGuardian();
        if (guardiansConfig.info[_guardian].pending > block.timestamp) revert PendingRevokeNotOver();
        if (block.timestamp > guardiansConfig.info[_guardian].pending + securityWindow) revert PendingRevokeExpired();

        address lastGuardian = guardiansConfig.guardians[guardiansConfig.guardians.length - 1];
        if (_guardian != lastGuardian) {
            uint256 targetIndex = guardiansConfig.info[_guardian].index;
            guardiansConfig.guardians[targetIndex] = lastGuardian;
            guardiansConfig.info[lastGuardian].index = targetIndex;
        }

        guardiansConfig.guardians.pop(); // ALERT! beta: review this logic!
        delete guardiansConfig.info[_guardian];

        emit GuardianRevoked(_guardian);
    }

    /**
     * @notice Lets the owner cancel a pending guardian revocation.
     * @param _guardian The guardian to cancel its revocation.
     */
    function cancelGuardianRevocation(address _guardian) external onlyOwner {
        if (isLocked()) revert AccountLocked();
        if (guardiansConfig.info[_guardian].pending == 0) revert UnknownRevoke();
        guardiansConfig.info[_guardian].pending = 0;
        emit GuardianRevocationCancelled(_guardian);
    }

    /**
     * Recovery functionalities *
     */

    /**
     * Require the account to be in recovery or not according to the _isRecovery argument
     */
    function _requireRecovery(bool _isRecovery) internal view {
        if (_isRecovery && recoveryDetails.executeAfter == 0) {
            revert NoOngoingRecovery();
        }
        if (!_isRecovery && recoveryDetails.executeAfter > 0) {
            revert OngoingRecovery();
        }
    }

    /**
     * @notice Lets the guardians start the execution of the recovery procedure.
     * Once triggered the recovery is pending for the security period before it can be finalised.
     * Must be confirmed by N guardians, where N = ceil(Nb Guardians / 2).
     * @param _recoveryAddress The address to which ownership should be transferred.
     */
    function startRecovery(address _recoveryAddress) external {
        if (!isGuardian(msg.sender)) revert MustBeGuardian();
        _requireRecovery(false);
        if (isGuardian(_recoveryAddress)) revert GuardianCannotBeOwner();
        uint64 executeAfter = uint64(block.timestamp + recoveryPeriod);
        recoveryDetails = RecoveryConfig(_recoveryAddress, executeAfter, uint32(Math.ceilDiv(guardianCount(), 2)));
        _setLock(block.timestamp + lockPeriod);
        emit RecoveryExecuted(_recoveryAddress, executeAfter);
    }

    /**
     * @notice Finalizes an ongoing recovery procedure if the security period (executeAfter) is over.
     * The method is public and callable by anyone.
     * @param _signatures Array of guardian signatures concatenated.
     * @notice The arguments should be ordered by the address of the guardian signing the message
     */
    function completeRecovery(bytes[] calldata _signatures) external {
        _requireRecovery(true);
        require(uint64(block.timestamp) > recoveryDetails.executeAfter, "Ongoing recovery period");

        require(recoveryDetails.guardiansRequired > 0, "No guardians set on wallet");
        if (recoveryDetails.guardiansRequired != _signatures.length) revert InvalidSignatureAmount();

        if (!_validateSignatures(_signatures)) revert InvalidRecoverySignatures();

        address recoveryOwner = recoveryDetails.recoveryAddress;
        delete recoveryDetails;

        // End sessions here?

        _transferOwnership(recoveryOwner);
        _setLock(0);

        emit RecoveryCompleted(recoveryOwner);
    }

    /**
     * @notice Validates the array of signatures provided.
     * @param _signatures The array of guardian signatures to perform the recovery.
     * @return A boolean indicating whether the signatures are valid, not repeated and from the guardians.
     */
    function _validateSignatures(bytes[] calldata _signatures) internal view returns (bool) {
        // We don't use a nonce here because the executeAfter serves as it
        bytes32 structHash = keccak256(
            abi.encode(
                RECOVER_TYPEHASH,
                recoveryDetails.recoveryAddress,
                recoveryDetails.executeAfter,
                recoveryDetails.guardiansRequired
            )
        );
        address lastSigner = _hashTypedDataV4(structHash).recover(_signatures[0]);
        if (!isGuardian(lastSigner)) return false; // Signer must be a guardian
        for (uint256 i = 1; i < _signatures.length;) {
            address signer = _hashTypedDataV4(structHash).recover(_signatures[i]);
            if (signer <= lastSigner) return false; // Signers must be different
            if (!isGuardian(signer)) return false; // Signer must be a guardian
            lastSigner = signer;
            unchecked {
                ++i;
            } // gas optimization
        }
        return true;
    }

    /**
     * @notice Lets the owner cancel an ongoing recovery procedure.
     */
    function cancelRecovery() external onlyOwner {
        _requireRecovery(true);
        address recoveryOwner = recoveryDetails.recoveryAddress;
        emit RecoveryCanceled(recoveryOwner);
        delete recoveryDetails;
        _setLock(0);
    }

    /**
     * @notice Lets the owner initiate a transfer of the account ownership. It is a 2 step process
     * @param _newOwner The address to which ownership should be transferred. It cannot be a guardian
     */
    function transferOwnership(address _newOwner) public override {
        if (isLocked()) revert AccountLocked();
        if (isGuardian(_newOwner)) revert GuardianCannotBeOwner();
        super.transferOwnership(_newOwner);
    }
}
