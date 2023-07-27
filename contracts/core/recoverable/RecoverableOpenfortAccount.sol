// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Base account contract to inherit from and EntryPoint interface
import {BaseOpenfortAccount, IEntryPoint} from "../BaseOpenfortAccount.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

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

    // Period during which the owner can cancel a guardian addition/revokation in seconds (7 days)
    uint256 internal recoveryPeriod;
    // Lock period
    uint256 internal lockPeriod;
    // The security period to add/remove guardians
    // Minimum period between the lock and an unlock. Must be greater or equal to the security period.
    uint256 internal securityPeriod;
    // The security window
    uint256 internal securityWindow;

    struct Lock {
        // Lock's release timestamp
        uint64 release;
        // Signature of the method that set the last lock
        bytes4 lockerMethod;
    }

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

    struct RecoveryConfig {
        address recoveryAddress; // Address to which ownership should be transferred
        uint64 executeAfter;
        uint32 guardianCount;
    }

    struct GuardianManagerConfig {
        // The time at which a guardian addition or revokation will be confirmable by the owner
        mapping(bytes32 => uint256) pending;
    }

    Lock internal locker;
    GuardianStorageConfig internal guardiansConfig;
    RecoveryConfig internal guardianRecoveryConfig;
    GuardianManagerConfig internal guardianManagerConfig;

    event EntryPointUpdated(address oldEntryPoint, address newEntryPoint);
    event GuardianAdded(address indexed guardian);
    event Locked(uint64 releaseAfter);
    event Unlocked();

    error InsecurePeriod();

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
     * @notice Throws if the wallet is locked.
     */
    modifier whenUnlocked() {
        require(!_isLocked(), "Wallet locked");
        _;
    }

    /**
     * @notice Lets a guardian lock a wallet.
     */
    function lock() external onlyGuardian whenUnlocked {
        _setLock(block.timestamp + lockPeriod, RecoverableOpenfortAccount.lock.selector);
        emit Locked(uint64(block.timestamp + lockPeriod));
    }

    /**
     * @notice Lets a guardian unlock a locked wallet.
     */
    function unlock() external onlyGuardian whenUnlocked {
        require(locker.lockerMethod == RecoverableOpenfortAccount.lock.selector, "SM: cannot unlock");
        _setLock(0, bytes4(0));
        emit Unlocked();
    }

    function _setLock(uint256 _releaseAfter, bytes4 _locker) internal {
        locker = Lock(SafeCast.toUint64(_releaseAfter), _locker);
    }

    /**
     * @notice Returns the release time of a wallet lock or 0 if the wallet is unlocked.
     * @return _releaseAfter The epoch time at which the lock will release (in seconds).
     */
    function getLock() external view returns (uint64 _releaseAfter) {
        return _isLocked() ? locker.release : 0;
    }

    /**
     * @notice Helper method to check if a wallet is locked.
     */
    function _isLocked() internal view returns (bool) {
        return locker.release > uint64(block.timestamp);
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
     * @notice Confirms the pending addition of a guardian to an account.
     * The method must be called during the confirmation window and can be called by anyone to enable orchestration.
     * @param _guardian The guardian.
     */
    function confirmGuardianAddition(address _guardian) external whenUnlocked {
        bytes32 id = keccak256(abi.encodePacked(_guardian, "addition"));
        require(guardianManagerConfig.pending[id] > 0, "Unknown pending addition");
        require(guardianManagerConfig.pending[id] < block.timestamp, "Pending addition not over");
        require(block.timestamp < guardianManagerConfig.pending[id] + securityWindow, "Pending addition expired");
        _addGuardian(_guardian);
        emit GuardianAdded(_guardian);
        delete guardianManagerConfig.pending[id];
    }

    /**
     * @notice Add a guardian to the account.
     * @param _guardian The guardian to add.
     */
    function _addGuardian(address _guardian) internal {
        guardiansConfig.guardians.push(_guardian);
        guardiansConfig.info[_guardian].exists = true;
        guardiansConfig.info[_guardian].index = uint128(guardiansConfig.guardians.length - 1);
    }

    /**
     * Recovery functionalities *
     */

    /**
     * @notice Lets the owner initiate a transfer of the account ownership. It is a 2 step process
     * @param _newOwner The address to which ownership should be transferred.
     */
    function transferOwnership(address _newOwner) public override whenUnlocked {
        require(!isGuardian(_newOwner), "new owner cannot be a guardian");
        super.transferOwnership(_newOwner);
    }
}
