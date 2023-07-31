// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Base account contract to inherit from and EntryPoint interface
import {BaseOpenfortAccount, IEntryPoint, SafeCastUpgradeable} from "../BaseOpenfortAccount.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title RecoverableOpenfortAccount
 * @author Eloi<eloi@openfort.xyz>
 * @notice Openfort account with session keys, guardians and pausability following the ERC-4337 standard.
 * It inherits from:
 *  - BaseOpenfortAccount
 *  - UUPSUpgradeable
 */
contract RecoverableOpenfortAccount is BaseOpenfortAccount, UUPSUpgradeable {
    address internal entrypointContract;

    // Period during which the owner can cancel a guardian proposal/revokation in seconds (7 days)
    uint256 internal recoveryPeriod;
    // Lock period
    uint256 internal lockPeriod;
    // The security period to add/remove guardians
    // Minimum period between the lock and an unlock. Must be greater or equal to the security period.
    uint256 internal securityPeriod;
    // The security window
    uint256 internal securityWindow;

    struct GuardianInfo {
        bool exists;
        uint256 index;
        uint256 pending;
    }

    struct GuardianStorageConfig {
        // the list of guardians
        address[] guardians;
        // the info about guardians
        mapping(address => GuardianInfo) info;
        // the lock's release timestamp
        uint256 lock;
    }

    struct RecoveryConfig {
        address recoveryAddress; // Address to which ownership should be transferred
        uint64 executeAfter; //
        uint32 guardianCount;
    }

    GuardianStorageConfig internal guardiansConfig;
    RecoveryConfig internal guardianRecoveryConfig;

    event EntryPointUpdated(address oldEntryPoint, address newEntryPoint);
    event Locked(bool isLocked);
    event GuardianProposed(address indexed guardian, uint256 executeAfter);
    event GuardianAdded(address indexed guardian);
    event GuardianProposalCancelled(address indexed guardian);
    event GuardianRevokationRequested(address indexed guardian, uint256 executeAfter);
    event GuardianRevoked(address indexed guardian);
    event GuardianRevokationCancelled(address indexed guardian);
    event RecoveryExecuted(address indexed _recovery, uint64 executeAfter);
    event RecoveryFinalized(address indexed _recovery);
    event RecoveryCanceled(address indexed _recovery);

    error AccountLocked();
    error AccountNotLocked();
    error CannotUnlock();
    error InsecurePeriod();
    error MustBeGuardian();
    error DuplicatedGuardian();
    error DuplicatedProposal();
    error GuardianCannotBeOwner();
    error NoOngoingRecovery();
    error OngoingRecovery();

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
        if (_newEntrypoint == address(0)) {
            revert ZeroAddressNotAllowed();
        }
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
        return isLocked() ? guardiansConfig.lock : 0;
    }

    /**
     * @notice Lets a guardian lock a wallet.
     */
    function lock() external onlyGuardian {
        if (isLocked()) revert AccountLocked();
        _setLock(block.timestamp + lockPeriod);
    }

    /**
     * @notice Lets a guardian unlock a locked wallet.
     */
    function unlock() external onlyGuardian {
        if (!isLocked()) revert AccountNotLocked();
        _setLock(0);
    }

    function _setLock(uint256 _releaseAfter) internal {
        guardiansConfig.lock = _releaseAfter;
        emit Locked(_releaseAfter != 0);
    }

    /**
     * Guardians functionalities *
     */

    /**
     * @notice Throws if the caller is not a guardian for the account.
     */
    modifier onlyGuardian() {
        if (!isGuardian(msg.sender)) revert MustBeGuardian();
        _;
    }

    /**
     * @notice Returns the number of guardians for an Openfort account.
     * @return the number of guardians.
     */
    function guardianCount() external view returns (uint256) {
        return guardiansConfig.guardians.length;
    }

    /**
     * @notice Gets the list of guaridans for an Openfort account.
     * @return the list of guardians.
     */
    function getGuardians() external view returns (address[] memory) {
        address[] memory guardians = new address[](guardiansConfig.guardians.length);
        for (uint256 i = 0; i < guardiansConfig.guardians.length; i++) {
            guardians[i] = guardiansConfig.guardians[i];
        }
        return guardians;
    }

    /**
     * @notice Checks if an account is a guardian for an Openfort account.
     * @param _guardian The account
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
            !(guardiansConfig.info[_guardian].pending == 0)
                && block.timestamp < guardiansConfig.info[_guardian].pending + securityWindow
        ) {
            revert DuplicatedProposal();
        }
        guardiansConfig.info[_guardian].pending = block.timestamp + securityPeriod;
        emit GuardianProposed(_guardian, block.timestamp + securityPeriod);
    }

    /**
     * @notice Confirms the pending proposal of a guardian to an account.
     * The method must be called during the confirmation window and can be called by anyone to enable orchestration.
     * @param _guardian The guardian to be confirmed.
     */
    function confirmGuardianProposal(address _guardian) external {
        if (isLocked()) revert AccountLocked();
        require(guardiansConfig.info[_guardian].pending > 0, "Unknown pending proposal");
        require(guardiansConfig.info[_guardian].pending < block.timestamp, "Pending proposal not over");
        require(block.timestamp < guardiansConfig.info[_guardian].pending + securityWindow, "Pending proposal expired");

        guardiansConfig.guardians.push(_guardian);
        guardiansConfig.info[_guardian].exists = true;
        guardiansConfig.info[_guardian].index = guardiansConfig.guardians.length;
        delete guardiansConfig.info[_guardian].pending;
        emit GuardianAdded(_guardian);
    }

    /**
     * @notice Lets the owner cancel a pending guardian addition.
     * @param _guardian The guardian which proposal will be cancelled.
     */
    function cancelGuardianProposal(address _guardian) external onlyOwner {
        if (isLocked()) revert AccountLocked();
        require(guardiansConfig.info[_guardian].pending > 0, "Unknown pending proposal");
        delete guardiansConfig.info[_guardian].pending;
        emit GuardianProposalCancelled(_guardian);
    }

    /**
     * @notice Lets the owner revoke a guardian from its wallet.
     * @dev Revokation must be confirmed by calling the confirmGuardianRevokation() method.
     * @param _guardian The guardian to revoke.
     */
    function revokeGuardian(address _guardian) external onlyOwner {
        require(isGuardian(_guardian), "Must be existing guardian");
        require(
            guardiansConfig.info[_guardian].pending == 0
                || block.timestamp > guardiansConfig.info[_guardian].pending + securityWindow,
            "Duplicate pending revoke"
        ); // TODO need to allow if confirmation window passed
        guardiansConfig.info[_guardian].pending = block.timestamp + securityPeriod;
        emit GuardianRevokationRequested(_guardian, block.timestamp + securityPeriod);
    }

    /**
     * @notice Confirms the pending revokation of a guardian to an Openfrort account.
     * The method must be called during the confirmation window and can be called by anyone to enable orchestration.
     * @param _guardian The guardian to confirm the revocation.
     */
    function confirmGuardianRevokation(address _guardian) external {
        require(guardiansConfig.info[_guardian].pending > 0, "Unknown pending revoke");
        require(guardiansConfig.info[_guardian].pending < block.timestamp, "Pending revoke not over");
        require(block.timestamp < guardiansConfig.info[_guardian].pending + securityWindow, "Pending revoke expired");

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
     * @notice Lets the owner cancel a pending guardian revokation.
     * @param _guardian The guardian to cancel its revocation.
     */
    function cancelGuardianRevokation(address _guardian) external onlyOwner {
        if (isLocked()) revert AccountLocked();
        require(guardiansConfig.info[_guardian].pending > 0, "Unknown pending revoke");
        delete guardiansConfig.info[_guardian].pending;
        emit GuardianRevokationCancelled(_guardian);
    }

    /**
     * Recovery functionalities *
     */

    /**
     * Require the account to be in recovery or not according to the _isRecovery argument
     */
    function _requireRecovery(bool _isRecovery) internal view {
        if (_isRecovery && guardianRecoveryConfig.executeAfter == 0) {
            revert NoOngoingRecovery();
        }
        if (!_isRecovery && guardianRecoveryConfig.executeAfter > 0) {
            revert OngoingRecovery();
        }
    }

    /**
     * @notice Lets the guardians start the execution of the recovery procedure.
     * Once triggered the recovery is pending for the security period before it can be finalised.
     * Must be confirmed by N guardians, where N = ceil(Nb Guardians / 2).
     * @param _recoveryAddress The address to which ownership should be transferred.
     */
    function executeRecovery(address _recoveryAddress) external {
        _requireRecovery(false);
        require(!isGuardian(_recoveryAddress), "Recovery address cannot be a guardian");
        uint64 executeAfter = uint64(block.timestamp + recoveryPeriod);
        guardianRecoveryConfig =
            RecoveryConfig(_recoveryAddress, executeAfter, uint32(guardianRecoveryConfig.guardianCount));
        _setLock(block.timestamp + lockPeriod);
        emit RecoveryExecuted(_recoveryAddress, executeAfter);
    }

    /**
     * @notice Finalizes an ongoing recovery procedure if the security period is over.
     * The method is public and callable by anyone to enable orchestration.
     */
    function finalizeRecovery() external {
        _requireRecovery(true);
        require(uint64(block.timestamp) > guardianRecoveryConfig.executeAfter, "Ongoing recovery period");
        address recoveryOwner = guardianRecoveryConfig.recoveryAddress;

        // End sessions here?

        _transferOwnership(recoveryOwner);
        _setLock(0);

        emit RecoveryFinalized(recoveryOwner);
    }

    /**
     * @notice Lets the owner cancel an ongoing recovery procedure.
     */
    function cancelRecovery() external onlyOwner {
        _requireRecovery(true);
        address recoveryOwner = guardianRecoveryConfig.recoveryAddress;

        _setLock(0);

        emit RecoveryCanceled(recoveryOwner);
    }

    /**
     * @notice Lets the owner initiate a transfer of the account ownership. It is a 2 step process
     * @param _newOwner The address to which ownership should be transferred.
     */
    function transferOwnership(address _newOwner) public override {
        if (isLocked()) revert AccountLocked();
        if (isGuardian(_newOwner)) revert GuardianCannotBeOwner();
        super.transferOwnership(_newOwner);
    }
}