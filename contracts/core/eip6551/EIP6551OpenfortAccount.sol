// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ECDSAUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {IERC1271Upgradeable} from "@openzeppelin/contracts-upgradeable/interfaces/IERC1271Upgradeable.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {SafeCastUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/math/SafeCastUpgradeable.sol";

import {IERC6551Account} from "erc6551/src/interfaces/IERC6551Account.sol";
import {IERC6551Executable} from "erc6551/src/interfaces/IERC6551Executable.sol";
import {ERC6551AccountLib} from "erc6551/src/lib/ERC6551AccountLib.sol";
import {BaseAccount, UserOperation, IEntryPoint} from "account-abstraction/core/BaseAccount.sol";
import {TokenCallbackHandler} from "account-abstraction/samples/callback/TokenCallbackHandler.sol";
import "account-abstraction/core/Helpers.sol" as Helpers;

/**
 * @title EIP6551OpenfortAccount (Non-upgradeable)
 * @notice Smart contract wallet with session keys following the ERC-4337 and EIP-6551 standards.
 * It inherits from:
 *  - BaseAccount to comply with ERC-4337
 *  - Initializable because accounts are meant to be created using Factories
 *  - IERC6551Account to have permissions using ERC-721 tokens
 *  - EIP712Upgradeable to use typed structured signatures EIP-712 (supporting ERC-5267 too)
 *  - IERC1271Upgradeable for Signature Validation (ERC-1271)
 *  - TokenCallbackHandler to support ERC-777, ERC-721 and ERC-1155
 */
contract EIP6551OpenfortAccount is
    BaseAccount,
    Initializable,
    IERC6551Account,
    IERC6551Executable,
    EIP712Upgradeable,
    IERC1271Upgradeable,
    TokenCallbackHandler
{
    using ECDSAUpgradeable for bytes32;

    address internal entrypointContract;

    // bytes4(keccak256("isValidSignature(bytes32,bytes)")
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;
    // bytes4(keccak256("execute(address,uint256,bytes,uint8)")
    bytes4 internal constant EXECUTE_ERC6551_SELECTOR = 0x51945447;
    // bytes4(keccak256("execute(address,uint256,bytes)")
    bytes4 internal constant EXECUTE_SELECTOR = 0xb61d27f6;
    // bytes4(keccak256("executeBatch(address[],uint256[],bytes[])")
    bytes4 internal constant EXECUTEBATCH_SELECTOR = 0x47e1da2a;

    uint256 public state;

    /**
     * Struct like ValidationData (from the EIP-4337) - alpha solution - to keep track of session keys' data
     * @param validAfter this sessionKey is valid only after this timestamp.
     * @param validUntil this sessionKey is valid only after this timestamp.
     * @param limit limit of uses remaining
     * @param masterSessionKey if set to true, the session key does not have any limitation other than the validity time
     * @param whitelising if set to true, the session key has to follow whitelisting rules
     * @param whitelist - this session key can only interact with the addresses in the whitelist.
     */
    struct SessionKeyStruct {
        uint48 validAfter;
        uint48 validUntil;
        uint48 limit;
        bool masterSessionKey;
        bool whitelising;
        mapping(address => bool) whitelist;
    }

    mapping(address => SessionKeyStruct) public sessionKeys;

    event AccountCreated(address indexed creator);
    event SessionKeyRegistered(address indexed key);
    event SessionKeyRevoked(address indexed key);
    event EntryPointUpdated(address oldEntryPoint, address newEntryPoint);

    error ZeroAddressNotAllowed();
    error NotOwnerOrEntrypoint();
    error NotOwnerOrEntrypointOrSelf();
    error InvalidParameterLength();

    // solhint-disable-next-line no-empty-blocks
    receive() external payable virtual {}

    constructor() {
        emit AccountCreated(msg.sender);
        _disableInitializers();
    }

    /*
     * @notice Initialize the smart contract wallet.
     */
    function initialize(address _entrypoint) public initializer {
        if (_entrypoint == address(0)) {
            revert ZeroAddressNotAllowed();
        }
        emit EntryPointUpdated(entrypointContract, _entrypoint);
        entrypointContract = _entrypoint;
        __EIP712_init("Openfort", "0.4");
        state = 1;
    }

    /**
     * Require the function call went through owner
     */
    function _requireFromOwner() internal view {
        if (msg.sender != owner()) {
            revert NotOwnerOrEntrypoint();
        }
    }

    /**
     * Require the function call went through EntryPoint or owner
     */
    function _requireFromEntryPointOrOwner() internal view {
        if (msg.sender != address(entryPoint()) && msg.sender != owner()) {
            revert NotOwnerOrEntrypoint();
        }
    }

    /**
     * Require the function call went through EntryPoint, owner or self
     */
    function _requireFromEntryPointOrOwnerorSelf() internal view {
        if (msg.sender != address(entryPoint()) && msg.sender != owner() && msg.sender != address(this)) {
            revert NotOwnerOrEntrypointOrSelf();
        }
    }

    function owner() public view virtual returns (address) {
        (uint256 chainId, address contractAddress, uint256 tokenId) = token();
        if (chainId != block.chainid) return address(0);
        return IERC721(contractAddress).ownerOf(tokenId);
    }

    /**
     * @dev {See IERC6551Account-token}
     */
    function token() public view virtual override returns (uint256, address, uint256) {
        return ERC6551AccountLib.token();
    }

    /**
     * Check current account deposit in the entryPoint
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /*
     * @notice Return whether a sessionKey is valid.
     */
    function isValidSessionKey(address _sessionKey, bytes calldata callData) public returns (bool) {
        SessionKeyStruct storage sessionKey = sessionKeys[_sessionKey];
        // If not owner and the session key is revoked, return false
        if (sessionKey.validUntil == 0) return false;

        // If the signer is a session key that is still valid
        // Let's first get the selector of the function that the caller is using
        bytes4 funcSelector =
            callData[0] | (bytes4(callData[1]) >> 8) | (bytes4(callData[2]) >> 16) | (bytes4(callData[3]) >> 24);

        if (funcSelector == EXECUTE_SELECTOR || funcSelector == EXECUTE_ERC6551_SELECTOR) {
            // Limit of transactions per sessionKey reached
            if (sessionKey.limit == 0) return false;
            // Deduct one use of the limit for the given session key
            unchecked {
                sessionKey.limit = sessionKey.limit - 1;
            }

            // Check if it is a masterSessionKey
            if (sessionKey.masterSessionKey) {
                return true;
            }

            // If it is not a masterSessionKey, let's check for whitelisting and reentrancy
            address toContract;
            (toContract,,) = abi.decode(callData[4:], (address, uint256, bytes));
            if (toContract == address(this)) {
                return false;
            } // Only masterSessionKey can reenter

            // If there is no whitelist or there is, but the target is whitelisted, return true
            if (!sessionKey.whitelising || sessionKey.whitelist[toContract]) {
                return true;
            }

            return false; // All other cases, deny
        } else if (funcSelector == EXECUTEBATCH_SELECTOR) {
            (address[] memory toContracts,,) = abi.decode(callData[4:], (address[], uint256[], bytes[]));
            // Check if limit of transactions per sessionKey reached
            if (sessionKey.limit < toContracts.length || toContracts.length > 9) return false;
            unchecked {
                sessionKey.limit = sessionKey.limit - SafeCastUpgradeable.toUint48(toContracts.length);
            }

            // Check if it is a masterSessionKey (no whitelist applies)
            if (sessionKey.masterSessionKey) return true;

            for (uint256 i = 0; i < toContracts.length;) {
                if (toContracts[i] == address(this)) {
                    return false;
                } // Only masterSessionKey can reenter
                if (sessionKey.whitelising && !sessionKey.whitelist[toContracts[i]]) {
                    return false;
                } // One contract's not in the sessionKey's whitelist (if any)
                unchecked {
                    ++i; // gas optimization
                }
            }
            return true;
        }

        // If a session key is used for other functions other than execute() or executeBatch(), deny
        return false;
    }

    /*
     * @notice See EIP-1271
     * Any signature by the owner is valid. Session keys need to sign using EIP712.
     */
    function isValidSignature(bytes32 _hash, bytes memory _signature) public view override returns (bytes4) {
        address signer = _hash.recover(_signature);

        if (owner() == signer) return MAGICVALUE;

        bytes32 hash = _hash.toEthSignedMessageHash();
        signer = hash.recover(_signature);
        if (owner() == signer) return MAGICVALUE;

        bytes32 digest = _hashTypedDataV4(_hash);
        signer = digest.recover(_signature);
        if (owner() == signer) return MAGICVALUE;

        SessionKeyStruct storage sessionKey = sessionKeys[signer];
        // If the signer is a session key that is still valid
        if (
            sessionKey.validUntil == 0 || sessionKey.validAfter > block.timestamp
                || sessionKey.validUntil < block.timestamp || sessionKey.limit < 1
        ) {
            return 0xffffffff;
        } // Not owner or session key revoked
        else {
            return MAGICVALUE;
        }
    }

    /**
     * @dev {See IERC6551Executable-execute}
     */
    function execute(address _target, uint256 _value, bytes calldata _data, uint8 _operation)
        external
        payable
        override
        returns (bytes memory _result)
    {
        require(_isValidSigner(msg.sender), "Caller is not owner");
        require(_operation == 0, "Only call operations are supported");
        ++state;
        bool success;
        // solhint-disable-next-line avoid-low-level-calls
        (success, _result) = _target.call{value: _value}(_data);
        require(success, string(_result));
        return _result;
    }

    /**
     * Execute a transaction (called directly from owner, or by entryPoint)
     */
    function execute(address dest, uint256 value, bytes calldata func) external {
        _requireFromEntryPointOrOwner();
        ++state;
        _call(dest, value, func);
    }

    /**
     * Execute a sequence of transactions. Maximum 9.
     */
    function executeBatch(address[] calldata _target, uint256[] calldata _value, bytes[] calldata _calldata) external {
        _requireFromEntryPointOrOwner();
        if (_target.length > 9 || _target.length != _calldata.length || _target.length != _value.length) {
            revert InvalidParameterLength();
        }
        for (uint256 i = 0; i < _target.length;) {
            ++state;
            _call(_target[i], _value[i], _calldata[i]);
            unchecked {
                ++i; // gas optimization
            }
        }
    }

    /**
     * Deposit more funds for this account in the entryPoint
     */
    function addDeposit() public payable {
        entryPoint().depositTo{value: msg.value}(address(this));
    }

    /**
     * Withdraw value from the account's deposit
     * @param withdrawAddress target to send to
     * @param amount to withdraw
     * @notice ONLY the owner can call this function (it's not using _requireFromEntryPointOrOwner())
     */
    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public {
        _requireFromOwner();
        ++state;
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    /**
     * @dev Call a target contract and reverts if it fails.
     */
    function _call(address _target, uint256 value, bytes calldata _calldata) internal {
        (bool success, bytes memory result) = _target.call{value: value}(_calldata);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
        ++state;
    }

    /**
     * @inheritdoc BaseAccount
     */
    function _validateSignature(UserOperation calldata userOp, bytes32 userOpHash)
        internal
        override
        returns (uint256 validationData)
    {
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        address signer = hash.recover(userOp.signature);

        // If the userOp was signed by the owner, allow straightaway
        if (owner() == signer) {
            return 0;
        }

        // Check if the session key is valid according to the data in the userOp
        if (isValidSessionKey(signer, userOp.callData)) {
            return Helpers._packValidationData(false, sessionKeys[signer].validUntil, sessionKeys[signer].validAfter);
        }

        return SIG_VALIDATION_FAILED;
    }

    function isValidSigner(address signer, bytes calldata) external view virtual returns (bytes4) {
        if (_isValidSigner(signer)) return IERC6551Account.isValidSigner.selector;
        return bytes4(0);
    }

    function _isValidSigner(address signer) internal view virtual returns (bool) {
        return signer == owner();
    }

    /**
     * Register a session key to the account
     * @param _key session key to register
     * @param _validAfter - this session key is valid only after this timestamp.
     * @param _validUntil - this session key is valid only up to this timestamp.
     * @param _limit - limit of uses remaining.
     * @param _whitelist - this session key can only interact with the addresses in the _whitelist.
     */
    function registerSessionKey(
        address _key,
        uint48 _validAfter,
        uint48 _validUntil,
        uint48 _limit,
        address[] calldata _whitelist
    ) public {
        _requireFromEntryPointOrOwnerorSelf();

        // Not sure why changing this for a custom error increases gas dramatically
        require(_whitelist.length < 11, "Whitelist too big");
        uint256 i = 0;
        for (i; i < _whitelist.length;) {
            sessionKeys[_key].whitelist[_whitelist[i]] = true;
            unchecked {
                ++i; // gas optimization
            }
        }
        if (i != 0) sessionKeys[_key].whitelising = true;
        else if (_limit == 2 ** 48 - 1) sessionKeys[_key].masterSessionKey = true;

        sessionKeys[_key].validAfter = _validAfter;
        sessionKeys[_key].validUntil = _validUntil;
        sessionKeys[_key].limit = _limit;
        sessionKeys[_key].masterSessionKey = false;
        ++state;
        emit SessionKeyRegistered(_key);
    }

    /**
     * Revoke a session key from the account
     * @param _key session key to revoke
     */
    function revokeSessionKey(address _key) external {
        _requireFromEntryPointOrOwnerorSelf();
        ++state;
        if (sessionKeys[_key].validUntil != 0) {
            sessionKeys[_key].validUntil = 0;
            sessionKeys[_key].masterSessionKey = false;
            emit SessionKeyRevoked(_key);
        }
    }

    function version() external pure virtual returns (uint256) {
        return 1;
    }

    /**
     * Return the current EntryPoint
     */
    function entryPoint() public view override returns (IEntryPoint) {
        return IEntryPoint(entrypointContract);
    }

    /**
     * Update the EntryPoint address
     */
    function updateEntryPoint(address _newEntrypoint) external {
        if (_newEntrypoint == address(0)) {
            revert ZeroAddressNotAllowed();
        }
        _requireFromOwner();
        ++state;
        emit EntryPointUpdated(entrypointContract, _newEntrypoint);
        entrypointContract = _newEntrypoint;
    }
}
