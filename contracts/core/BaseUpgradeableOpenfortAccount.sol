// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {ECDSAUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import {IERC1271Upgradeable} from "@openzeppelin/contracts-upgradeable/interfaces/IERC1271Upgradeable.sol";

import {BaseAccount, UserOperation, IEntryPoint} from "account-abstraction/core/BaseAccount.sol";
import {TokenCallbackHandler} from "account-abstraction/samples/callback/TokenCallbackHandler.sol";

/**
  * @title BaseUpgradeableOpenfortAccount (Non-upgradeable)
  * @author Eloi<eloi@openfort.xyz>
  * @notice Minimal smart contract wallet with session keys following the ERC-4337 standard.
  * It inherits from:
  *  - Initializable because StaticOpenfortAccounts are meant to be created using StaticOpenfortAccountFactory
  *  - IERC1271 for Signature Validation
  *  - BaseAccount to comply with ERC-4337 
  *  - Ownable2Step to have permissions
  *  - TokenCallbackHandler to support ERC777, ERC721 and ERC1155
  */
abstract contract BaseUpgradeableOpenfortAccount is BaseAccount, Initializable, IERC1271Upgradeable, Ownable2StepUpgradeable, TokenCallbackHandler {
    using ECDSAUpgradeable for bytes32;

    // bytes4(keccak256("isValidSignature(bytes32,bytes)")
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;

    IEntryPoint private immutable entrypointContract;
    address public immutable factory;

    /** Struct like ValidationData (from the EIP-4337) - alpha solution - to keep track of session keys' data
     * @param validAfter this sessionKey is valid only after this timestamp.
     * @param validUntil this sessionKey is valid only after this timestamp.
     * @param masterSessionKey if set to true, the session key does not have any limitation other than the validity time
     * @param canSign if set to true, the session key can sign as the account (future)
     * @param whitelist - this session key can only interact with the addresses in the whitelist.
     */
    struct SessionKeyStruct {
        uint48 validAfter;
        uint48 validUntil;
        bool masterSessionKey;
        mapping(address => bool) whitelist;
    }
    mapping(address => SessionKeyStruct) public sessionKeys;

    event SessionKeyRegistered(address indexed key);
    event SessionKeyRevoked(address indexed key);
    
    // solhint-disable-next-line no-empty-blocks
    receive() external payable virtual {}

    constructor(IEntryPoint _entrypoint, address _factory) {
        _disableInitializers();
        entrypointContract = _entrypoint;
        factory = _factory;
    }

    /// @notice Initializes the smart contract wallet.
    function initialize(address _defaultAdmin, bytes calldata) public virtual initializer {
        _transferOwnership(_defaultAdmin);
    }

    /**
     * Require the function call went through EntryPoint or owner
     */
    function _requireFromEntryPointOrOwner() internal view {
        require(msg.sender == address(entryPoint()) || msg.sender == owner(), "Account: not Owner or EntryPoint");
    }

    /**
     * @inheritdoc BaseAccount
     */
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return entrypointContract;
    }

    /**
     * Check current account deposit in the entryPoint
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /*
     * @notice Return whether a signer is authorized.
     */
    function isValidSigner(address _signer) public view virtual returns (bool valid) {
        if(owner() == _signer)
            return true;
        
        // If the signer is a session key that is still valid
        if (sessionKeys[_signer].validUntil != 0 ) {
            // Calculate the time range
            bool outOfTimeRange = block.timestamp > sessionKeys[_signer].validUntil || block.timestamp < sessionKeys[_signer].validAfter;
            require(!outOfTimeRange, "Session key expired");
            if(sessionKeys[_signer].masterSessionKey)
                return true;
        }
        return false;
    }

    /// @notice See EIP-1271
    function isValidSignature(bytes32 _hash, bytes memory _signature)
        public
        view
        virtual
        override
        returns (bytes4 magicValue)
    {
        address signer = _hash.recover(_signature);
        if (isValidSigner(signer)) {
            magicValue = MAGICVALUE;
        }
    }

    /**
     * Execute a transaction (called directly from owner, or by entryPoint)
     */
    function execute(address dest, uint256 value, bytes calldata func) external {
        _requireFromEntryPointOrOwner();
        _call(dest, value, func);
    }

    /**
     * Execute a sequence of transactions
     */
    function executeBatch(
        address[] calldata _target,
        uint256[] calldata _value,
        bytes[] calldata _calldata
    ) external virtual {
        _requireFromEntryPointOrOwner();
        require(_target.length == _calldata.length && _target.length == _value.length, "Account: wrong array lengths.");
        for (uint256 i = 0; i < _target.length; i++) {
            _call(_target[i], _value[i], _calldata[i]);
        }
    }

    /**
     * Deposit more funds for this account in the entryPoint
     */
    function addDeposit() public payable {
        entryPoint().depositTo{value : msg.value}(address(this));
    }

    /**
     * Withdraw value from the account's deposit
     * @param withdrawAddress target to send to
     * @param amount to withdraw
     * @notice ONLY the owner can call this function (it's not using _requireFromEntryPointOrOwner())
     */
    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public onlyOwner {
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    /**
     * @dev Call a target contract and reverts if it fails.
     */
    function _call(
        address _target,
        uint256 value,
        bytes memory _calldata
    ) internal {
        (bool success, bytes memory result) = _target.call{ value: value }(_calldata);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /**
     * @inheritdoc BaseAccount
     */
    function _validateSignature(UserOperation calldata userOp, bytes32 userOpHash)
        internal
        virtual
        override
        returns (uint256 validationData)
    {
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        address signer = hash.recover(userOp.signature);

        if (!isValidSigner(signer))
            return SIG_VALIDATION_FAILED;
        return 0;
    }

    /**
     * Register a master session key to the account
     * @param _key session key to register
     * @param _validAfter - this session key is valid only after this timestamp.
     * @param _validUntil - this session key is valid only up to this timestamp.
     * @notice using this function will automatically set the sessionkey as a
     * master session key because no further restricion was set.
     */
    function registerSessionKey(address _key, uint48 _validAfter, uint48 _validUntil) external {
        _requireFromEntryPointOrOwner();
        sessionKeys[_key].validAfter = _validAfter;
        sessionKeys[_key].validUntil = _validUntil;
        sessionKeys[_key].masterSessionKey = true;
        emit SessionKeyRegistered(_key);
    }

    /**
     * Register a session key to the account
     * @param _key session key to register
     * @param _validAfter - this session key is valid only after this timestamp.
     * @param _validUntil - this session key is valid only up to this timestamp.
     * @param _whitelist - this session key can only interact with the addresses in the _whitelist.
     */
    function registerSessionKey(address _key, uint48 _validAfter, uint48 _validUntil, address[] calldata _whitelist) external {
        _requireFromEntryPointOrOwner();
        sessionKeys[_key].validAfter = _validAfter;
        sessionKeys[_key].validUntil = _validUntil;
        sessionKeys[_key].masterSessionKey = false;

        uint whitelistLen = _whitelist.length;
        for (uint256 i = 0; i < whitelistLen; i++) {
            sessionKeys[_key].whitelist[_whitelist[i]] = true;
        }

        emit SessionKeyRegistered(_key);
    }

    /**
     * Revoke a session key from the account
     * @param _key session key to revoke
     */
    function revokeSessionKey(address _key) external {
        _requireFromEntryPointOrOwner();
        if(sessionKeys[_key].validUntil != 0) {
            sessionKeys[_key].validUntil = 0;
            emit SessionKeyRevoked(_key);
        }
    }
}
