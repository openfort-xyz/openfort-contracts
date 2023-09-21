// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {UserOperation, UserOperationLib, IEntryPoint} from "account-abstraction/core/BaseAccount.sol";
import {BaseOpenfortPaymaster} from "./BaseOpenfortPaymaster.sol";
import "account-abstraction/core/Helpers.sol" as Helpers;
import {OpenfortErrorsAndEvents} from "../interfaces/OpenfortErrorsAndEvents.sol";

/**
 * @title OpenfortPaymaster (Non-upgradeable)
 * @author Eloi<eloi@openfort.xyz>
 * @notice A paymaster that uses external service to decide whether to pay for the UserOp.
 * The paymaster trusts an external signer to sign the transaction.
 * The calling user must pass the UserOp to that external signer first, which performs
 * whatever off-chain verification before signing the UserOp.
 * It has the following features:
 * - Sponsor the whole UserOp
 * - Let the sender pay fees in ERC20 (both using an exchange rate per gas or per userOp)
 * - Let multiple actors deposit native tokens to sponsor transactions
 */
contract OpenfortPaymaster is BaseOpenfortPaymaster {
    using ECDSA for bytes32;
    using UserOperationLib for UserOperation;
    using SafeERC20 for IERC20;

    uint256 private constant VALID_PND_OFFSET = 20; // length of an address
    uint256 private constant SIGNATURE_OFFSET = 180; // 20+48+48+64 = 180
    uint256 private constant POST_OP_GAS = 35000;

    mapping(address => uint256) public depositorBalances;

    enum Mode {
        PayForUser,
        DynamicRate,
        FixedRate
    }

    struct PolicyStrategy {
        Mode paymasterMode;
        address depositor;
        address erc20Token;
        uint256 exchangeRate;
    }

    /// @notice For a Paymaster, emit when a transaction has been paid using an ERC20 token
    event GasPaidInERC20(address erc20Token, uint256 actualGasCost, uint256 actualTokensSent);

    constructor(IEntryPoint _entryPoint, address _owner) BaseOpenfortPaymaster(_entryPoint, _owner) {}

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
     * Verify that the paymaster owner has signed this request.
     * The "paymasterAndData" is expected to be the paymaster and a signature over the entire request params
     * paymasterAndData[:20]: address(this)
     * paymasterAndData[20:148]: abi.encode(validUntil, validAfter, strategy) // 20+48+48+64
     * paymasterAndData[SIGNATURE_OFFSET:]: signature
     */
    function _validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32, /*userOpHash*/
        uint256 requiredPreFund
    ) internal view override returns (bytes memory context, uint256 validationData) {
        (uint48 validUntil, uint48 validAfter, PolicyStrategy memory strategy, bytes calldata signature) =
            parsePaymasterAndData(userOp.paymasterAndData);

        bytes32 hash = ECDSA.toEthSignedMessageHash(getHash(userOp, validUntil, validAfter, strategy));

        // Don't revert on signature failure: return SIG_VALIDATION_FAILED with empty context
        if (owner() != ECDSA.recover(hash, signature)) {
            return ("", Helpers._packValidationData(true, validUntil, validAfter));
        }

        if (requiredPreFund > paymasterIdBalances[paymasterData.paymasterId]) revert InsufficientBalance(requiredPreFund, paymasterIdBalances[paymasterData.paymasterId]);

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
     * For ERC20 modes (DynamicRate and FixedRate), transfer the right amount of tokens from the sender to the designated recipient
     */
    function _postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost) internal override {
        (
            address sender,
            Mode paymasterMode,
            IERC20 erc20Token,
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
                emit GasPaidInERC20(address(erc20Token), actualGasCost, actualTokenCost);
                erc20Token.safeTransferFrom(sender, tokenRecipient, actualTokenCost);
            }
        } else if (paymasterMode == Mode.FixedRate) {
            emit GasPaidInERC20(address(erc20Token), actualGasCost, exchangeRate);
            erc20Token.safeTransferFrom(sender, tokenRecipient, exchangeRate);
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
     * @dev Override the default implementation.
     */
    function deposit() public payable virtual override {
        revert("Use depositFor() instead");
    }

    /**
     * @dev Add a deposit for this paymaster and given depositor (Dapp Depositor address), used for paying for transaction fees
     * @param _depositorAddress depositor address for which deposit is being made
     */
    function depositFor(address _depositorAddress) external payable {
        if (_depositorAddress == address(0)) revert OpenfortErrorsAndEvents.ZeroAddressNotAllowed();
        if (msg.value == 0) revert OpenfortErrorsAndEvents.MustSendNativeToken();
    }

    /**
     * @dev Withdraws the specified amount of gas tokens from the paymaster's balance and transfers them to the specified address.
     * @param withdrawAddress The address to which the gas tokens should be transferred.
     * @param amount The amount of gas tokens to withdraw.
     */
    function withdrawTo(address payable withdrawAddress, uint256 amount) public override {
        if (withdrawAddress == address(0)) revert OpenfortErrorsAndEvents.ZeroAddressNotAllowed();
    }
}
