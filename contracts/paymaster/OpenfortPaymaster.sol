// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {UserOperation, UserOperationLib, IEntryPoint} from "account-abstraction/core/BaseAccount.sol";
import {BasePaymaster} from "account-abstraction/core/BasePaymaster.sol";
import "account-abstraction/core/Helpers.sol" as Helpers;

/**
 * A paymaster inspired in the VerifyingPaymaster samples from eth-infinitism and Stackups' modification.
 */
contract OpenfortPaymaster is BasePaymaster {
    using ECDSA for bytes32;
    using UserOperationLib for UserOperation;
    using SafeERC20 for IERC20;

    uint256 private constant VALID_PND_OFFSET = 20; // length of an address
    uint256 private constant SIGNATURE_OFFSET = 180; // 20+48+48+64 = 180
    uint256 private constant POST_OP_GAS = 35000;

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

    error InvalidTokenRecipient();

    event GasPaidInERC20(address ERC20, uint256 actualGasCost, uint256 actualTokensSent);
    event TokenRecipientUpdated(address oldTokenRecipient, address newTokenRecipient);

    constructor(IEntryPoint _entryPoint, address _owner) BasePaymaster(_entryPoint) {
        _transferOwnership(_owner);
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
        bytes memory secondHalf = abi.encode(
            block.chainid,
            address(this),
            validUntil,
            validAfter,
            strategy.paymasterMode,
            strategy.erc20Token,
            strategy.exchangeRate
        );
        return keccak256(abi.encodePacked(firstHalf, secondHalf));
    }

    /**
     * Verify paymaster owner signed this request.
     * The "paymasterAndData" is expected to be the paymaster and a signature over the entire request params
     * paymasterAndData[:20]: address(this)
     * paymasterAndData[20:148]: abi.encode(validUntil, validAfter, strategy) // 20+48+48+64
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

        context = abi.encode(
            userOp.sender,
            strategy.paymasterMode,
            strategy.erc20Token,
            strategy.exchangeRate,
            userOp.maxFeePerGas,
            userOp.maxPriorityFeePerGas
        );

        // If the parsePaymasterAndData was signed by the owner of the paymaster
        // return the context and validity (validUntil, validAfter).
        return (context, Helpers._packValidationData(false, validUntil, validAfter));
    }

    /*
     * For ERC20 modes, transfer the right amount of tokens from the sender to the designated recipient
     */
    function _postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost) internal override {
        (
            address sender,
            Mode paymasterMode,
            IERC20 token,
            uint256 exchangeRate,
            uint256 maxFeePerGas,
            uint256 maxPriorityFeePerGas
        ) = abi.decode(context, (address, Mode, IERC20, uint256, uint256, uint256));

        if (paymasterMode == Mode.DynamicRate) {
            uint256 opGasPrice;
            unchecked {
                if (maxFeePerGas == maxPriorityFeePerGas) {
                    opGasPrice = maxFeePerGas;
                } else {
                    opGasPrice = Math.min(maxFeePerGas, maxPriorityFeePerGas + block.basefee);
                }
            }

            uint256 actualTokenCost = ((actualGasCost + (POST_OP_GAS * opGasPrice)) * exchangeRate) / 1e18;
            if (mode != PostOpMode.postOpReverted) {
                emit GasPaidInERC20(address(token), actualGasCost, actualTokenCost);
                token.safeTransferFrom(sender, tokenRecipient, actualTokenCost);
            }
        } else if (paymasterMode == Mode.FixedRate) {
            emit GasPaidInERC20(address(token), actualGasCost, exchangeRate);
            token.safeTransferFrom(sender, tokenRecipient, exchangeRate);
        }
    }

    /**
     * Parse paymasterAndData
     * The "paymasterAndData" is expected to be the paymaster and a signature over the entire request params
     * paymasterAndData[:20]: address(this)
     * paymasterAndData[20:SIGNATURE_OFFSET]: (validUntil, validAfter, strategy) // 20+48+48+64
     * paymasterAndData[SIGNATURE_OFFSET:]: signature
     */
    function parsePaymasterAndData(bytes calldata paymasterAndData)
        public
        pure
        returns (uint48 validUntil, uint48 validAfter, PolicyStrategy memory strategy, bytes calldata signature)
    {
        (validUntil, validAfter, strategy) =
            abi.decode(paymasterAndData[VALID_PND_OFFSET:SIGNATURE_OFFSET], (uint48, uint48, PolicyStrategy));
        signature = paymasterAndData[SIGNATURE_OFFSET:];
    }

    /**
     * Allows the owner of the paymaster to update the token recipient address
     */
    function updateTokenRecipient(address _newTokenRecipient) external onlyOwner {
        if (_newTokenRecipient == address(0)) revert InvalidTokenRecipient();
        emit TokenRecipientUpdated(tokenRecipient, _newTokenRecipient);
        tokenRecipient = _newTokenRecipient;
    }
}
