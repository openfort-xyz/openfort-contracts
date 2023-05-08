// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

// solhint-disable no-inline-assembly

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {BaseAccount, UserOperation} from "account-abstraction/core/BaseAccount.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {TokenCallbackHandler} from "account-abstraction/samples/callback/TokenCallbackHandler.sol";

/**
  * @title OpenfortSessionKeyAccount (Non-upgradeable)
  * @author Eloi<eloi@openfort.xyz>
  * @notice Minimal smart contract wallet with session keys following the ERC-4337 standard.
  * It inherits from:
  *  - Ownable2Step to have permissions
  *  - BaseAccount to comply with ERC-4337 
  *  - TokenCallbackHandler to support ERC777, ERC721 and ERC1155
  *  - ECDSA for signature verifications
  */
contract OpenfortSessionKeyAccount is Ownable2Step, BaseAccount, TokenCallbackHandler {
    using ECDSA for bytes32;

    /** Struct like ValidationData (from the EIP-4337) - alpha solution - to keep track of session keys' data
     * @param validAfter this sessionKey is valid only after this timestamp.
     * @param validUntil this sessionKey is valid only after this timestamp.
     */
    struct SessionKeyStruct {
        uint48 validAfter;
        uint48 validUntil;
    }

    IEntryPoint private immutable _entryPoint;
    mapping(address => SessionKeyStruct) public sessionKeys;

    event SessionKeyRegistered(address indexed key);
    event SessionKeyRevoked(address indexed key);

    constructor(IEntryPoint _anEntryPoint) {
        _entryPoint = _anEntryPoint;
    }

    /**
     * @inheritdoc BaseAccount
     */
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return _entryPoint;
    }

    /**
     * @inheritdoc BaseAccount
     */
    function _validateSignature(UserOperation calldata userOp, bytes32 userOpHash)
    internal override virtual returns (uint256 validationData) {
        // Using toEthSignedMessageHash to turn the signature to an Ethereum signed message
        bytes32 hash = userOpHash.toEthSignedMessageHash();

        // Recover the signer address from the signature
        address sessionKey = hash.recover(userOp.signature);
        
        // If the signer is a session key that is still valid
        if (sessionKeys[sessionKey].validUntil != 0 ) {
            // Calculate the time range
            bool outOfTimeRange = block.timestamp > sessionKeys[sessionKey].validUntil || block.timestamp < sessionKeys[sessionKey].validAfter;
            require(!outOfTimeRange, "Session key expired");
            return 0;
        }
        return SIG_VALIDATION_FAILED;
    }

    /**
     * Require the function call went through EntryPoint or owner
     */
    function _requireFromEntryPointOrOwner() internal view {
        require(msg.sender == address(entryPoint()) || msg.sender == owner(), "Account: not Owner or EntryPoint");
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
    function executeBatch(address[] calldata dest, bytes[] calldata func) external {
        _requireFromEntryPointOrOwner();
        require(dest.length == func.length, "wrong array lengths");
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], 0, func[i]);
        }
    }

    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value : value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }
    
    /**
     * Check current account deposit in the entryPoint
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
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
     * Register a session key to the account
     * @param _key session key to revoke
     * @param _validAfter - this session key is valid only after this timestamp.
     * @param _validUntil - this session key is valid only up to this timestamp.
     */
    function registerSessionKey(address _key, uint48 _validAfter, uint48 _validUntil) external {
        _requireFromEntryPointOrOwner();
        sessionKeys[_key].validAfter = _validAfter;
        sessionKeys[_key].validUntil = _validUntil;
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

    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}
}
