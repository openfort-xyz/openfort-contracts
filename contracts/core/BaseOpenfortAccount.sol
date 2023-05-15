// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

import {BaseAccount, UserOperation, IEntryPoint} from "account-abstraction/core/BaseAccount.sol";
import {TokenCallbackHandler} from "account-abstraction/samples/callback/TokenCallbackHandler.sol";

/**
  * @title StaticOpenfortAccount (Non-upgradeable)
  * @author Eloi<eloi@openfort.xyz>
  * @notice Minimal smart contract wallet with session keys following the ERC-4337 standard.
  * It inherits from:
  *  - BaseAccount to comply with ERC-4337 
  *  - Initializable because StaticOpenfortAccounts are meant to be created using StaticOpenfortAccountFactory
  *  - Ownable2Step to have permissions
  *  - IERC1271 for Signature Validation
  *  - TokenCallbackHandler to support ERC777, ERC721 and ERC1155
  */
abstract contract BaseOpenfortAccount is BaseAccount, Initializable, Ownable2Step, IERC1271, TokenCallbackHandler {
    using ECDSA for bytes32;

    // bytes4(keccak256("isValidSignature(bytes32,bytes)")
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;
    // bytes4(keccak256("execute(address,uint256,bytes)")
    bytes4 internal constant EXECUTE_SELECTOR = 0xb61d27f6;
    // bytes4(keccak256("executeBatch(address[],uint256[],bytes[])")
    bytes4 internal constant EXECUTEBATCH_SELECTOR = 0x47e1da2a;
    uint48 internal constant DEFAULT_LIMIT = 100;

    IEntryPoint private immutable entrypointContract;
    address public immutable factory;

    /** Struct like ValidationData (from the EIP-4337) - alpha solution - to keep track of session keys' data
     * @param validAfter this sessionKey is valid only after this timestamp.
     * @param validUntil this sessionKey is valid only after this timestamp.
     * @param limit limit of uses remaining
     * @param masterSessionKey if set to true, the session key does not have any limitation other than the validity time
     * @param canSign if set to true, the session key can sign as the account (future)
     * @param whitelist - this session key can only interact with the addresses in the whitelist.
     */
    struct SessionKeyStruct {
        uint48 validAfter;
        uint48 validUntil;
        uint48 limit;
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
     * @notice Return whether a sessionKey is valid.
     */
    function isValidSessionKey(address _sessionKey, bytes calldata callData) public virtual returns (bool valid) {
        // If the signer is a session key that is still valid
        if(sessionKeys[_sessionKey].validUntil == 0)
            return false; // "Not owner or session key revoked"
        
        // Calculate the time range
        bool outOfTimeRange = block.timestamp > sessionKeys[_sessionKey].validUntil || block.timestamp < sessionKeys[_sessionKey].validAfter;
        if(outOfTimeRange)
            return false; // "Session key expired"
        
        // Let's first get the selector of the function that the caller is using
        bytes4 funcSelector =
            callData[0] |
            (bytes4(callData[1]) >> 8) |
            (bytes4(callData[2]) >> 16) |
            (bytes4(callData[3]) >> 24);

        if(funcSelector == EXECUTE_SELECTOR) {
            if(sessionKeys[_sessionKey].limit == 0)
                return false; // "Limit of transactions per sessionKey reached");
            unchecked {
                sessionKeys[_sessionKey].limit = sessionKeys[_sessionKey].limit - 1;
            }
            
            // Check if it is a masterSessionKey
            if(sessionKeys[_sessionKey].masterSessionKey)
                return true;
            
            // If it is not a masterSessionKey, let's check for whitelisting
            address toContract;
            (toContract, , ) = abi.decode(callData[4:], (address,uint256,bytes));
            if(toContract == address(this))
                return false; // "Only masterSessionKey can reenter"
            if(!sessionKeys[_sessionKey].whitelist[toContract])
                return false; // "Contract's not in the sessionKey's whitelist"
            return true;
        }
        else if(funcSelector == EXECUTEBATCH_SELECTOR) {
            address[] memory toContract;
            (toContract, , ) = abi.decode(callData[4:], (address[],uint256[],bytes[]));
            uint256 lengthBatch = toContract.length;
            if(sessionKeys[_sessionKey].limit < uint48(lengthBatch))
                return false; // "Limit of transactions per sessionKey reached"
            unchecked {
                sessionKeys[_sessionKey].limit = sessionKeys[_sessionKey].limit - uint48(lengthBatch);
            }

            // Check if it is a masterSessionKey
            if(sessionKeys[_sessionKey].masterSessionKey)
                return true;

            for(uint256 i = 0; i < lengthBatch; i++) {
                if(toContract[i] == address(this))
                    return false; // "Only masterSessionKey can reenter"
                if(!sessionKeys[_sessionKey].whitelist[toContract[i]])
                    return false; // "One contract's not in the sessionKey's whitelist");
            }
            return true;
        }

        // If a session key is used for other functions other than execute() or executeBatch(), deny
        return false;
    }

    /*
     * @notice See EIP-1271
     * @ToDo only the owner can sign
     */
    function isValidSignature(bytes32 _hash, bytes memory _signature)
        public
        view
        virtual
        override
        returns (bytes4 magicValue)
    {
        address signer = _hash.recover(_signature);
        if(owner() == signer)
            magicValue = MAGICVALUE;
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
        for(uint256 i = 0; i < _target.length; i++) {
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

        // If the userOp was signed by the owner, allow straightaway
        if(owner() == signer)
            return 0;

        // Check if the session key is valid according to the data in the userOp
        if (isValidSessionKey(signer, userOp.callData))
            return 0;

        return SIG_VALIDATION_FAILED;
    }

    /**
     * Register a master session key to the account
     * @param _key session key to register
     * @param _validAfter - this session key is valid only after this timestamp.
     * @param _validUntil - this session key is valid only up to this timestamp.
     * @notice using this function will automatically set the sessionkey as a
     * master session key because no further restricion was set.
     * @notice default limit set to 100.
     */
    function registerSessionKey(address _key, uint48 _validAfter, uint48 _validUntil) public onlyOwner {
        registerSessionKey(_key, _validAfter, _validUntil, DEFAULT_LIMIT);
    }

    /**
     * Register a master session key to the account
     * @param _key session key to register
     * @param _validAfter - this session key is valid only after this timestamp.
     * @param _validUntil - this session key is valid only up to this timestamp.
     * @param _limit - this session key is valid only up to this timestamp.
     * @notice using this function will automatically set the sessionkey as a
     * master session key because no further restricion was set.
     */
    function registerSessionKey(address _key, uint48 _validAfter, uint48 _validUntil, uint48 _limit) public onlyOwner {
        sessionKeys[_key].validAfter = _validAfter;
        sessionKeys[_key].validUntil = _validUntil;
        sessionKeys[_key].limit = _limit;
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
    function registerSessionKey(address _key, uint48 _validAfter, uint48 _validUntil, address[] calldata _whitelist) public onlyOwner {
        registerSessionKey(_key, _validAfter, _validUntil, DEFAULT_LIMIT, _whitelist);
    }

    /**
     * Register a session key to the account
     * @param _key session key to register
     * @param _validAfter - this session key is valid only after this timestamp.
     * @param _validUntil - this session key is valid only up to this timestamp.
     * @param _limit - this session key is valid only up to this timestamp.
     * @param _whitelist - this session key can only interact with the addresses in the _whitelist.
     */
    function registerSessionKey(address _key, uint48 _validAfter, uint48 _validUntil, uint48 _limit, address[] calldata _whitelist) public onlyOwner {
        sessionKeys[_key].validAfter = _validAfter;
        sessionKeys[_key].validUntil = _validUntil;
        sessionKeys[_key].limit = _limit;
        sessionKeys[_key].masterSessionKey = false;

        uint whitelistLen = _whitelist.length;
        require(whitelistLen <= 10, "Whitelist too big");
        for (uint256 i = 0; i < whitelistLen; i++) {
            sessionKeys[_key].whitelist[_whitelist[i]] = true;
        }

        emit SessionKeyRegistered(_key);
    }

    /**
     * Revoke a session key from the account
     * @param _key session key to revoke
     */
    function revokeSessionKey(address _key) external onlyOwner {
        if(sessionKeys[_key].validUntil != 0) {
            sessionKeys[_key].validUntil = 0;
            emit SessionKeyRevoked(_key);
        }
    }
}
