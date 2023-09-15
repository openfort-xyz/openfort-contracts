// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {BaseAccount, UserOperation, UserOperationLib, IEntryPoint} from "account-abstraction/core/BaseAccount.sol";
import {BasePaymaster} from "account-abstraction/core/BasePaymaster.sol";
import "account-abstraction/core/Helpers.sol" as Helpers;

/**
 * A paymaster based on the eth-infinitism sample VerifyingPaymaster contract and Stackups.
 * It has the same functionality as the sample, but with added support for withdrawing ERC20 tokens.
 * All withdrawn tokens will be transferred to a designated address.
 * Note that the off-chain signer should have a strategy in place to handle a failed token withdrawal.
 *
 * See account-abstraction/contracts/samples/VerifyingPaymaster.sol for detailed comments.
 */
contract OpenfortPaymaster is BasePaymaster {
    using ECDSA for bytes32;
    using UserOperationLib for UserOperation;
    using SafeERC20 for IERC20;

    uint256 private constant VALID_PND_OFFSET = 20; // length of an address
    uint256 private constant SIGNATURE_OFFSET = 148; // 48+48+20+32 = 148
    uint256 private constant POST_OP_GAS = 35000;

    event GasPaidInERC20(address ERC20, uint256 actualGasCost, uint256 actualTokensSent);

    constructor(IEntryPoint _entryPoint, address _owner) BasePaymaster(_entryPoint) {
        _transferOwnership(_owner);
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
        address erc20Token,
        uint256 exchangeRate
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
        bytes memory secondHalf =
            abi.encode(block.chainid, address(this), validUntil, validAfter, erc20Token, exchangeRate);
        return keccak256(abi.encodePacked(firstHalf, secondHalf));
    }

    /**
     * Verify our external signer signed this request.
     * The "paymasterAndData" is expected to be the paymaster and a signature over the entire request params
     * paymasterAndData[:20]: address(this)
     * paymasterAndData[20:148]: abi.encode(validUntil, validAfter, erc20Token, exchangeRate) // 48+48+20+32
     * paymasterAndData[SIGNATURE_OFFSET:]: signature
     */
    function _validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32, /*userOpHash*/
        uint256 /*requiredPreFund*/
    ) internal view override returns (bytes memory context, uint256 validationData) {
        (uint48 validUntil, uint48 validAfter, address erc20Token, uint256 exchangeRate, bytes calldata signature) =
            parsePaymasterAndData(userOp.paymasterAndData);
        // solhint-disable-next-line reason-string
        require(
            signature.length == 64 || signature.length == 65,
            "VerifyingPaymaster: invalid signature length in paymasterAndData"
        );
        bytes32 hash = ECDSA.toEthSignedMessageHash(getHash(userOp, validUntil, validAfter, erc20Token, exchangeRate));

        context = "";
        if (erc20Token != address(0)) {
            context =
                abi.encode(userOp.sender, erc20Token, exchangeRate, userOp.maxFeePerGas, userOp.maxPriorityFeePerGas);
        }

        // don't revert on signature failure: return SIG_VALIDATION_FAILED
        if (owner() != ECDSA.recover(hash, signature)) {
            return (context, Helpers._packValidationData(true, validUntil, validAfter));
        }

        // If the parsePaymasterAndData was signed by the owner of the Paymaster
        // return the context (empty if native token) and validity (validUntil, validAfter).
        return (context, Helpers._packValidationData(false, validUntil, validAfter));
    }

    /*
     * If everything worked fine, transfer the right amount of tokens from the sender (SCW) to the designated recipient
     */
    function _postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost) internal override {
        (address sender, IERC20 token, uint256 exchangeRate, uint256 maxFeePerGas, uint256 maxPriorityFeePerGas) =
            abi.decode(context, (address, IERC20, uint256, uint256, uint256));

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
            token.safeTransferFrom(sender, owner(), actualTokenCost);
        }
    }

    /**
     * Parse paymasterAndData.
     * The "paymasterAndData" is expected to be the paymaster and a signature over the entire request params
     * paymasterAndData[:20]: address(this)
     * paymasterAndData[20:SIGNATURE_OFFSET]: (validUntil, validAfter, erc20Token, exchangeRate) // 48+48+20+32
     * paymasterAndData[SIGNATURE_OFFSET:]: signature
     */
    function parsePaymasterAndData(bytes calldata paymasterAndData)
        public
        pure
        returns (
            uint48 validUntil,
            uint48 validAfter,
            address erc20Token,
            uint256 exchangeRate,
            bytes calldata signature
        )
    {
        (validUntil, validAfter, erc20Token, exchangeRate) =
            abi.decode(paymasterAndData[VALID_PND_OFFSET:SIGNATURE_OFFSET], (uint48, uint48, address, uint256));
        signature = paymasterAndData[SIGNATURE_OFFSET:];
    }
}
