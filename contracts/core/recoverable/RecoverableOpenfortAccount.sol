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

    struct GuardianStorageConfig {
        // the list of guardians
        address[] guardians;
        // the info about guardians
        mapping(address => GuardianInfo) info;
        // the lock's release timestamp
        uint256 lock;
    }

    struct GuardianInfo {
        bool exists;
        uint128 index;
    }

    struct GuardianManagerConfig {
        // The time at which a guardian proposal or revokation will be confirmable by the owner
        mapping(bytes32 => uint256) pending;
    }

    struct RecoveryConfig {
        address recoveryAddress; // Address to which ownership should be transferred
        uint64 executeAfter; //
        uint32 guardianCount;
    }

    GuardianStorageConfig internal guardiansConfig;
    GuardianManagerConfig internal guardianManagerConfig;
    RecoveryConfig internal guardianRecoveryConfig;

    event EntryPointUpdated(address oldEntryPoint, address newEntryPoint);
    event Locked(bool isLocked);
    event GuardianProposed(address indexed guardian, uint256 executeAfter);
    event GuardianAdded(address indexed guardian);
    event RecoveryExecuted(address indexed _recovery, uint64 executeAfter);

    error AccountLocked();
    error AccountNotLocked();
    error CannotUnlock();
    error InsecurePeriod();
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
        require(isGuardian(msg.sender), "Must be guardian");
        _;
    }

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
        _isGuardian = false; // ToDo
    }

    /**
     * @notice Lets the owner add a guardian to its Openfort account.
     * The first guardian is added immediately. All following proposals must be confirmed
     * by calling the confirmGuardianProposal() method.
     * @param _guardian The guardian to propose.
     */
    function proposeGuardian(address _guardian) external onlyOwner {
        if (isLocked()) revert AccountLocked();
        if (owner() == _guardian) revert();
        if (isGuardian(_guardian)) revert();

        // Guardians must either be an EOA or a contract with an owner()
        // method that returns an address with a 25000 gas stipend.
        // Note that this test is not meant to be strict and can be bypassed by custom malicious contracts.
        (bool success,) = _guardian.call{gas: 25000}(abi.encodeWithSignature("owner()"));
        require(success, "SM: must be EOA/Argent wallet");

        bytes32 id = keccak256(abi.encodePacked(_guardian, "proposal"));
        require(
            guardianManagerConfig.pending[id] == 0
                || block.timestamp > guardianManagerConfig.pending[id] + securityWindow,
            "SM: duplicate pending proposal"
        );
        guardianManagerConfig.pending[id] = block.timestamp + securityPeriod;
        emit GuardianProposed(_guardian, block.timestamp + securityPeriod);
    }

    /**
     * @notice Confirms the pending proposal of a guardian to an account.
     * The method must be called during the confirmation window and can be called by anyone to enable orchestration.
     * @param _guardian The guardian.
     */
    function confirmGuardianProposal(address _guardian) external {
        if (isLocked()) revert AccountLocked();
        bytes32 id = keccak256(abi.encodePacked(_guardian, "proposal"));
        require(guardianManagerConfig.pending[id] > 0, "Unknown pending proposal");
        require(guardianManagerConfig.pending[id] < block.timestamp, "Pending proposal not over");
        require(block.timestamp < guardianManagerConfig.pending[id] + securityWindow, "Pending proposal expired");
        _addGuardian(_guardian);
        emit GuardianAdded(_guardian);
        delete guardianManagerConfig.pending[id];
    }

    /**
     * @notice Add a guardian to the account.
     * @param _guardian The guardian to add.
     */
    function _addGuardian(address _guardian) internal {
        if (_guardian == address(0)) revert ZeroAddressNotAllowed();
        guardiansConfig.guardians.push(_guardian);
        guardiansConfig.info[_guardian].exists = true;
        guardiansConfig.info[_guardian].index = SafeCastUpgradeable.toUint128(guardiansConfig.guardians.length);
    }

    /**
     * @notice Revoke a guardian from an Openfort account.
     * @param _guardian The guardian to revoke.
     */
    function revokeGuardian(address _guardian) external {
        address lastGuardian = guardiansConfig.guardians[guardiansConfig.guardians.length - 1];
        if (_guardian != lastGuardian) {
            uint128 targetIndex = guardiansConfig.info[_guardian].index;
            guardiansConfig.guardians[targetIndex] = lastGuardian;
            guardiansConfig.info[lastGuardian].index = targetIndex;
        }
        guardiansConfig.guardians.pop();
        delete guardiansConfig.info[_guardian];
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
     * @param _recovery The address to which ownership should be transferred.
     */
    function executeRecovery(address _recovery) external {
        _requireRecovery(false);
        require(!isGuardian(_recovery), "Recovery address cannot be a guardian");
        uint64 executeAfter = uint64(block.timestamp + recoveryPeriod);
        guardianRecoveryConfig = RecoveryConfig(_recovery, executeAfter, uint32(guardianRecoveryConfig.guardianCount));
        _setLock(block.timestamp + lockPeriod);
        emit RecoveryExecuted(_recovery, executeAfter);
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
