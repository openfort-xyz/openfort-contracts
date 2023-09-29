// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {UserOperation, UserOperationLib, IEntryPoint} from "account-abstraction/core/BaseAccount.sol";
import "account-abstraction/core/Helpers.sol" as Helpers;
import {BaseOpenfortPaymaster} from "./BaseOpenfortPaymaster.sol";
import {OpenfortErrorsAndEvents} from "../interfaces/OpenfortErrorsAndEvents.sol";

/**
 * @title OpenfortPaymaster (Non-upgradeable)
 * @author Eloi<eloi@openfort.xyz>
 * @notice A paymaster that uses external service to decide whether to pay for the UserOp.
 * The Paymaster trusts an external signer (owner) to sign each user operation.
 * The calling user must pass the UserOp to that external signer first, which performs
 * whatever off-chain verification before signing the UserOp.
 * It has the following features:
 *  - Sponsor the whole UserOp (PayForUser mode)
 *  - Let the sender pay fees in ERC20 (both using an exchange rate per gas or per userOp)
 *  - All ERC20s used to sponsor gas go to the address `tokenRecipient`
 */
contract OpenfortPaymaster is BaseOpenfortPaymaster {
    using ECDSA for bytes32;
    using UserOperationLib for UserOperation;
    using SafeERC20 for IERC20;

    uint256 private constant SIGNATURE_OFFSET = 180; // 20+48+48+32+32 = 180

    address public tokenRecipient;

    enum Mode {
        PayForUser,
        DynamicRate,
        FixedRate
    }

    struct PolicyStrategy {
        Mode paymasterMode;
        address erc20Token;
        uint256 exchangeRate;
    }

    /// @notice When a transaction has been paid using an ERC20 token
    event GasPaidInERC20(address erc20Token, uint256 actualGasCost, uint256 actualTokensSent);

    /// @notice When the owner deposits gas to the EntryPoint
    event GasDeposited(address indexed from, address indexed depositor, uint256 indexed value);

    /// @notice When the owner withdraws gas from the EntryPoint
    event GasWithdrawn(address indexed depositor, address indexed to, uint256 indexed value);

    /// @notice When tokenRecipient changes
    event TokenRecipientUpdated(address oldTokenRecipient, address newTokenRecipient);

    event PostOpReverted(bytes context, uint256 actualGasCost);

    constructor(IEntryPoint _entryPoint, address _owner) BaseOpenfortPaymaster(_entryPoint, _owner) {
        tokenRecipient = _owner;
    }

    /**
     * Return the hash we're going to sign off-chain (and validate on-chain)
     * this method is called by the off-chain service, to sign the request.
     * it is called on-chain from the validatePaymasterUserOp, to validate the signature.
     * note that this signature covers all fields of the UserOperation, except the "paymasterAndData",
     * which will carry the signature itself.
     */
    function getHash(
        UserOperation calldata userOp,
        uint48 validUntil,
        uint48 validAfter,
        PolicyStrategy memory strategy
    ) public view returns (bytes32) {
        // Dividing the hashing in 2 parts due to the stack too deep error
        bytes memory firstHalf = abi.encode(
            userOp.getSender(),
            userOp.nonce,
            keccak256(userOp.initCode),
            keccak256(userOp.callData),
            userOp.callGasLimit,
            userOp.verificationGasLimit,
            userOp.preVerificationGas,
            userOp.maxFeePerGas,
            userOp.maxPriorityFeePerGas
        );
        bytes memory secondHalf = abi.encode(block.chainid, address(this), validUntil, validAfter, strategy);
        return keccak256(abi.encodePacked(firstHalf, secondHalf));
    }

    /**
     * Verify that the paymaster owner has signed this request.
     * The "paymasterAndData" is expected to be the paymaster and a signature over the entire request params
     * paymasterAndData[:ADDRESS_OFFSET]: address(this)
     * paymasterAndData[ADDRESS_OFFSET:SIGNATURE_OFFSET]: abi.encode(validUntil, validAfter, strategy) // 20+48+48+32+32+32
     * paymasterAndData[SIGNATURE_OFFSET:]: signature
     */
    function _validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32, /*userOpHash*/
        uint256 /*requiredPreFund*/
    ) internal view override returns (bytes memory context, uint256 validationData) {
        (uint48 validUntil, uint48 validAfter, PolicyStrategy memory strategy, bytes calldata signature) =
            parsePaymasterAndData(userOp.paymasterAndData);

        bytes32 hash = ECDSA.toEthSignedMessageHash(getHash(userOp, validUntil, validAfter, strategy));

        // Don't revert on signature failure: return SIG_VALIDATION_FAILED with empty context
        if (owner() != ECDSA.recover(hash, signature)) {
            return ("", Helpers._packValidationData(true, validUntil, validAfter));
        }

        context = abi.encode(userOp.sender, strategy, userOp.maxFeePerGas, userOp.maxPriorityFeePerGas);

        // If the parsePaymasterAndData was signed by the owner of the paymaster
        // return the context and validity (validUntil, validAfter).
        return (context, Helpers._packValidationData(false, validUntil, validAfter));
    }

    /*
     * For ERC20 modes (DynamicRate and FixedRate), transfer the right amount of tokens from the sender to the designated recipient
     */
    function _postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost) internal override {
        if (mode == PostOpMode.postOpReverted) {
			emit PostOpReverted(context, actualGasCost);
			// Do nothing here to not revert the whole bundle and harm reputation - From ethInfinitism
			return;
		}
        (address sender, PolicyStrategy memory strategy, uint256 maxFeePerGas, uint256 maxPriorityFeePerGas) =
            abi.decode(context, (address, PolicyStrategy, uint256, uint256));

        // Getting OP gas price
        uint256 opGasPrice;
        unchecked {
            if (maxFeePerGas == maxPriorityFeePerGas) {
                // Legacy mode (for networks that do not support basefee opcode)
                opGasPrice = maxFeePerGas;
            } else {
                opGasPrice = Math.min(maxFeePerGas, maxPriorityFeePerGas + block.basefee);
            }
        }

        uint256 actualOpCost = actualGasCost + (postOpGas * opGasPrice);

        if (strategy.paymasterMode == Mode.DynamicRate) {
            uint256 actualTokenCost = actualOpCost * strategy.exchangeRate;
            emit GasPaidInERC20(address(strategy.erc20Token), actualOpCost, actualTokenCost);
            IERC20(strategy.erc20Token).safeTransferFrom(sender, tokenRecipient, actualTokenCost);
        } else if (strategy.paymasterMode == Mode.FixedRate) {
            emit GasPaidInERC20(address(strategy.erc20Token), actualOpCost, strategy.exchangeRate);
            IERC20(strategy.erc20Token).safeTransferFrom(sender, tokenRecipient, strategy.exchangeRate);
        }
    }

    /**
     * Parse paymasterAndData
     * The "paymasterAndData" is expected to be the paymaster and a signature over the entire request params
     * paymasterAndData[:ADDRESS_OFFSET]: address(this)
     * paymasterAndData[ADDRESS_OFFSET:SIGNATURE_OFFSET]: (validUntil, validAfter, strategy)
     * paymasterAndData[SIGNATURE_OFFSET:]: signature
     */
    function parsePaymasterAndData(bytes calldata paymasterAndData)
        public
        pure
        returns (uint48 validUntil, uint48 validAfter, PolicyStrategy memory strategy, bytes calldata signature)
    {
        (validUntil, validAfter, strategy) =
            abi.decode(paymasterAndData[ADDRESS_OFFSET:SIGNATURE_OFFSET], (uint48, uint48, PolicyStrategy));
        signature = paymasterAndData[SIGNATURE_OFFSET:];
    }

    /**
     * @dev Override the default implementation.
     */
    function deposit() public payable override {
        entryPoint.depositTo{value: msg.value}(address(this));
        emit GasDeposited(msg.sender, msg.sender, msg.value);
    }

    /**
     * @inheritdoc BaseOpenfortPaymaster
     */
    function withdrawTo(address payable _withdrawAddress, uint256 _amount) public override onlyOwner {
        entryPoint.withdrawTo(_withdrawAddress, _amount);
        emit GasWithdrawn(msg.sender, _withdrawAddress, _amount);
    }

    /**
     * Allows the owner of the paymaster to update the token recipient address
     */
    function updateTokenRecipient(address _newTokenRecipient) external onlyOwner {
        if (_newTokenRecipient == address(0)) revert OpenfortErrorsAndEvents.ZeroValueNotAllowed();
        emit TokenRecipientUpdated(tokenRecipient, _newTokenRecipient);
        tokenRecipient = _newTokenRecipient;
    }
}
