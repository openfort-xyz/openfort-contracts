// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.19;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {UserOperation, UserOperationLib, IEntryPoint} from "account-abstraction/core/BaseAccount.sol";
import "account-abstraction/core/Helpers.sol" as Helpers;
import {BaseOpenfortPaymaster} from "./BaseOpenfortPaymaster.sol";
import {OpenfortErrorsAndEvents} from "../interfaces/OpenfortErrorsAndEvents.sol";

/**
 * @title OpenfortPaymasterV2 (Non-upgradeable)
 * @notice A paymaster that uses external service to decide whether to pay for the UserOp.
 * The Paymaster trusts an external signer (owner) to sign each user operation.
 * The calling user must pass the UserOp to that external signer first, which performs
 * whatever off-chain verification before signing the UserOp.
 * It has the following features:
 *  - Sponsor the whole UserOp (PayForUser mode)
 *  - Let the sender pay fees in ERC20 (both using an exchange rate per gas or per userOp)
 *  - Let multiple actors deposit native tokens to sponsor transactions
 */
contract OpenfortPaymasterV2 is BaseOpenfortPaymaster {
    using ECDSA for bytes32;
    using UserOperationLib for UserOperation;
    using SafeERC20 for IERC20;

    uint256 private constant SIGNATURE_OFFSET = 212; // 20+48+48+32+32+32 = 212

    mapping(address => uint256) private depositorBalances;
    uint256 private totalDepositorBalances;

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

    /// @notice When a transaction has been paid using an ERC20 token
    event GasPaidInERC20(address erc20Token, uint256 actualGasCost, uint256 actualTokensSent);

    /// @notice When the owner or a depositor deposits gas to the EntryPoint
    event GasDeposited(address indexed from, address indexed depositor, uint256 indexed value);

    /// @notice When the owner or a depositor withdraws gas from the EntryPoint
    event GasWithdrawn(address indexed depositor, address indexed to, uint256 indexed value);

    /// @notice When a depositor uses gas from the EntryPoint deposit and it is deducted from depositorBalances
    event GasBalanceDeducted(address depositor, uint256 actualOpCost);

    event PostOpReverted(bytes context, uint256 actualGasCost);

    constructor(IEntryPoint _entryPoint, address _owner) BaseOpenfortPaymaster(_entryPoint, _owner) {
        totalDepositorBalances = 0;
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
     * Return current paymaster's deposit on the EntryPoint for a given depositor address.
     * Owner deposit is all deposited funds that are not part of other depositors.
     */
    function getDepositFor(address _depositor) public view returns (uint256) {
        if (_depositor == owner()) return (entryPoint.balanceOf(address(this)) - totalDepositorBalances);
        return depositorBalances[_depositor];
    }

    /**
     * Verify that the paymaster owner has signed this request.
     * The "paymasterAndData" is expected to be the paymaster and a signature over the entire request params
     * paymasterAndData[:ADDRESS_OFFSET]: address(this)
     * paymasterAndData[ADDRESS_OFFSET:SIGNATURE_OFFSET]: abi.encode(validUntil, validAfter, strategy)
     * paymasterAndData[SIGNATURE_OFFSET:]: signature
     */
    function _validatePaymasterUserOp(UserOperation calldata userOp, bytes32, /*userOpHash*/ uint256 requiredPreFund)
        internal
        view
        override
        returns (bytes memory context, uint256 validationData)
    {
        (uint48 validUntil, uint48 validAfter, PolicyStrategy memory strategy, bytes calldata signature) =
            parsePaymasterAndData(userOp.paymasterAndData);

        bytes32 hash = ECDSA.toEthSignedMessageHash(getHash(userOp, validUntil, validAfter, strategy));

        // Don't revert on signature failure: return SIG_VALIDATION_FAILED with empty context
        if (owner() != ECDSA.recover(hash, signature)) {
            return ("", Helpers._packValidationData(true, validUntil, validAfter));
        }

        if (strategy.depositor != owner() && requiredPreFund > depositorBalances[strategy.depositor]) {
            revert OpenfortErrorsAndEvents.InsufficientBalance(requiredPreFund, depositorBalances[strategy.depositor]);
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
            if (mode != PostOpMode.postOpReverted) {
                emit GasPaidInERC20(address(strategy.erc20Token), actualOpCost, actualTokenCost);
                IERC20(strategy.erc20Token).safeTransferFrom(sender, strategy.depositor, actualTokenCost);
            }
        } else if (strategy.paymasterMode == Mode.FixedRate) {
            emit GasPaidInERC20(address(strategy.erc20Token), actualOpCost, strategy.exchangeRate);
            IERC20(strategy.erc20Token).safeTransferFrom(sender, strategy.depositor, strategy.exchangeRate);
        }

        // In any of the modes, subtract the cost to the right depositor
        if (strategy.depositor != owner()) {
            totalDepositorBalances -= actualOpCost;
            depositorBalances[strategy.depositor] -= actualOpCost;
            emit GasBalanceDeducted(strategy.depositor, actualOpCost);
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
        if (msg.sender != owner()) revert("Not Owner: use depositFor() instead");
        entryPoint.depositTo{value: msg.value}(address(this));
        emit GasDeposited(msg.sender, msg.sender, msg.value);
    }

    /**
     * @inheritdoc BaseOpenfortPaymaster
     */
    function withdrawTo(address payable _withdrawAddress, uint256 _amount) public override onlyOwner {
        if (_amount > getDepositFor(msg.sender)) {
            revert OpenfortErrorsAndEvents.InsufficientBalance(_amount, getDepositFor(msg.sender));
        }
        entryPoint.withdrawTo(_withdrawAddress, _amount);
        emit GasWithdrawn(msg.sender, _withdrawAddress, _amount);
    }

    /**
     * @dev Add a deposit for this paymaster and given depositor, used for paying for transaction fees
     * @param _depositorAddress depositor address for which deposit is being made
     */
    function depositFor(address _depositorAddress) public payable {
        if (_depositorAddress == address(0)) revert OpenfortErrorsAndEvents.ZeroValueNotAllowed();
        if (msg.value == 0) revert OpenfortErrorsAndEvents.MustSendNativeToken();
        if (_depositorAddress == owner()) revert OpenfortErrorsAndEvents.OwnerNotAllowed();
        depositorBalances[_depositorAddress] += msg.value;
        totalDepositorBalances += msg.value;
        entryPoint.depositTo{value: msg.value}(address(this));
        emit GasDeposited(msg.sender, _depositorAddress, msg.value);
    }

    /**
     * @dev Withdraws the specified amount of gas tokens from the paymaster's balance and transfers them to the specified address.
     * @param _withdrawAddress The address to which the gas tokens should be transferred to.
     * @param _amount The amount of gas tokens to withdraw.
     */
    function withdrawDepositorTo(address payable _withdrawAddress, uint256 _amount) external {
        if (_withdrawAddress == address(0)) revert OpenfortErrorsAndEvents.ZeroValueNotAllowed();
        if (msg.sender == owner()) revert OpenfortErrorsAndEvents.OwnerNotAllowed();
        uint256 currentBalance = depositorBalances[msg.sender];
        if (_amount > currentBalance) {
            revert OpenfortErrorsAndEvents.InsufficientBalance(_amount, currentBalance);
        }
        depositorBalances[msg.sender] -= _amount;
        totalDepositorBalances -= _amount;
        entryPoint.withdrawTo(_withdrawAddress, _amount);
        emit GasWithdrawn(msg.sender, _withdrawAddress, _amount);
    }

    /**
     * @dev Withdraws the specified amount of gas tokens from a depositor paymaster's balance and transfers them to the specified address.
     * @param _depositorAddress The address to which the gas tokens should be withdrawn from.
     * @param _withdrawAddress The address to which the gas tokens should be transferred to.
     * @param _amount The amount of gas tokens to withdraw.
     * @notice Function to allow the owner of the Paymaster to withdraw the deposit of a depositor and send it
     * To be used when the depositor looses access to the address and requests Openfort to recover it from the deposits.
     */
    function withdrawFromDepositor(address _depositorAddress, address payable _withdrawAddress, uint256 _amount)
        external
        onlyOwner
    {
        if (_depositorAddress == address(0)) revert OpenfortErrorsAndEvents.ZeroValueNotAllowed();
        uint256 currentBalance = depositorBalances[_depositorAddress];
        if (_amount > currentBalance) {
            revert OpenfortErrorsAndEvents.InsufficientBalance(_amount, currentBalance);
        }
        depositorBalances[_depositorAddress] -= _amount;
        totalDepositorBalances -= _amount;
        entryPoint.withdrawTo(_withdrawAddress, _amount);
        emit GasWithdrawn(_depositorAddress, _withdrawAddress, _amount);
    }

    /**
     * @dev The new owner accepts the ownership transfer.
     * @notice If the new owner had some native tokens deposited to the Paymaster,
     * they will now be part of the owner's deposit.
     */
    function acceptOwnership() public override {
        totalDepositorBalances -= depositorBalances[pendingOwner()];
        depositorBalances[pendingOwner()] = 0;
        super.acceptOwnership();
    }
}
