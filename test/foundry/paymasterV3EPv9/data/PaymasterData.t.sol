// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Constants} from "./Constants.sol";
import {Test} from "lib/forge-std/src/Test.sol";
import {PaymasterConstants} from "./PaymasterConstants.sol";

contract PaymasterData is Test, Constants, PaymasterConstants {
    struct ERC20PaymasterData {
        /// @dev The treasury address where the tokens will be sent to.
        address treasury;
        /// @dev Timestamp until which the sponsorship is valid.
        uint48 validUntil;
        /// @dev Timestamp after which the sponsorship is valid.
        uint48 validAfter;
        /// @dev The gas overhead of calling transferFrom during the postOp.
        uint128 postOpGas;
        /// @dev ERC-20 token that the sender will pay with.
        address token;
        /// @dev The exchange rate of the ERC-20 token during sponsorship.
        uint256 exchangeRate;
        /// @dev The paymaster signature.
        bytes signature;
        /// @dev The paymasterValidationGasLimit to be used in the postOp.
        uint128 paymasterValidationGasLimit;
        /// @dev The preFund of the userOperation.
        uint256 preFundInToken;
        /// @dev A constant fee that is added to the userOp's gas cost.
        uint128 constantFee;
        /// @dev The recipient of the tokens.
        address recipient;
    }

    struct ERC20PostOpContext {
        /// @dev The userOperation sender.
        address sender;
        /// @dev The token used to pay for gas sponsorship.
        address token;
        /// @dev The treasury address where the tokens will be sent to.
        address treasury;
        /// @dev The exchange rate between the token and the chain's native currency.
        uint256 exchangeRate;
        /// @dev The gas overhead when performing the transferFrom call.
        uint128 postOpGas;
        /// @dev The userOperation hash.
        bytes32 userOpHash;
        /// @dev The userOperation's maxFeePerGas (v0.6 only)
        uint256 maxFeePerGas;
        /// @dev The userOperation's maxPriorityFeePerGas (v0.6 only)
        uint256 maxPriorityFeePerGas;
        /// @dev The pre fund of the userOperation.
        uint256 preFund;
        /// @dev The pre fund of the userOperation that was charged.
        uint256 preFundCharged;
        /// @dev The total allowed execution gas limit, i.e the sum of the callGasLimit and postOpGasLimit.
        uint256 executionGasLimit;
        /// @dev Estimate of the gas used before the userOp is executed.
        uint256 preOpGasApproximation;
        /// @dev A constant fee that is added to the userOp's gas cost.
        uint128 constantFee;
        /// @dev The recipient of the tokens.
        address recipient;
    }

    error OPFPaymasterV3__PaymasterAndDataLengthInvalid();

    /// @notice The paymaster data mode is invalid. The mode should be 0 or 1.
    error OPFPaymasterV3__PaymasterModeInvalid();

    /// @notice The paymaster data length is invalid for the selected mode.
    error OPFPaymasterV3__PaymasterConfigLengthInvalid();

    /// @notice The paymaster signature length is invalid.
    error OPFPaymasterV3__PaymasterSignatureLengthInvalid();

    /// @notice The token is invalid.
    error OPFPaymasterV3__TokenAddressInvalid();

    /// @notice The token exchange rate is invalid.
    error OPFPaymasterV3__ExchangeRateInvalid();

    /// @notice The recipient is invalid.
    error OPFPaymasterV3__RecipientInvalid();

    /// @notice The preFund is too high.
    error OPFPaymasterV3__PreFundTooHigh();

    uint256 ownerPK;
    address owner;
    uint256 managerPK;
    address manager;
    uint256[] signersPK;
    address[] signers;

    address treasury;

    uint48 validUntil;
    uint48 validAfter;

    function _setPaymasterData() internal {
        treasury = makeAddr("treasury");
        (owner, ownerPK) = makeAddrAndKey("owner");
        (manager, managerPK) = makeAddrAndKey("manager");

        for (uint256 i = 0; i < signersLength;) {
            (address signer, uint256 signerPK) = makeAddrAndKey(string.concat("signer", vm.toString(i)));
            signers.push(signer);
            signersPK.push(signerPK);
            unchecked {
                i++;
            }
        }
    }
}
