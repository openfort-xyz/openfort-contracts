// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {UserOperationLib} from "@account-abstraction-v8/core/UserOperationLib.sol";
import {MessageHashUtils} from "@oz-v5.4.0/utils/cryptography/MessageHashUtils.sol";
import {BasePaymasterTest as Base} from "test/foundry/paymasterV3/BasePaymasterTest.t.sol";
import {PackedUserOperation} from "@account-abstraction-v8/interfaces/PackedUserOperation.sol";

using UserOperationLib for PackedUserOperation;

abstract contract PaymasterHelpers is Base {
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

    uint48 validUntil;
    uint48 validAfter;
    uint128 constant postGas = 50000;
    uint128 constant paymasterValidationGasLimit = 100000;
    uint256 constant preVerificationGas = 800_000;
    uint256 exchangeRate = 1_000_000;
    uint256 requiredPreFund = 1000000;
    // Basic ERC20 mode - no optional fields
    uint8 combinedByteBasic = 0x00;

    // With constant fee
    uint8 combinedByteFee = 0x01;

    // Only recipient included
    uint8 combinedByteRecipient = 0x02;

    // Only preFund included
    uint8 combinedBytePreFund = 0x04;

    // All three optional fields included (0x01 | 0x02 | 0x04)
    uint8 combinedByteAll = 0x07;

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

    function _parsePaymasterAndDataCallData(PackedUserOperation calldata _userOp)
        external
        view
        returns (uint8 mode, bytes calldata paymasterConfig)
    {
        (mode, paymasterConfig) = _parsePaymasterAndData(_userOp.paymasterAndData, PAYMASTER_DATA_OFFSET);
    }

    function _parseErc20ConfigCallData(bytes calldata paymasterConfig)
        external
        pure
        returns (ERC20PaymasterData memory cfg)
    {
        cfg = _parseErc20Config(paymasterConfig);
    }

    function _createPostOpContextCallData(
        PackedUserOperation calldata _userOp,
        bytes32 _userOpHash,
        ERC20PaymasterData memory _cfg,
        uint256 _requiredPreFund
    ) external pure returns (bytes memory context) {
        context = _createPostOpContext(_userOp, _userOpHash, _cfg, _requiredPreFund);
    }

    function _signPaymasterData(uint8 _mode, PackedUserOperation calldata _userOp, uint256 _signerIndx)
        external
        view
        returns (bytes memory paymasterSignature)
    {
        bytes32 rawHash = PM.getHash(_mode, _userOp);
        bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(rawHash);
        uint256 PK = signersPK[_signerIndx];
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, ethSignedHash);

        paymasterSignature = abi.encodePacked(r, s, v);
    }

    function _createPaymasterDataMode(PackedUserOperation memory userOp, uint8 _mode, uint8 _combinedByte)
        internal
        returns (bytes memory paymasterData)
    {
        uint128 verificationGasLimit = uint128(uint256(bytes32(userOp.accountGasLimits)) >> 128);
        _validWindow();
        if (_mode == VERIFYING_MODE) {
            paymasterData = abi.encodePacked(
                address(PM),
                verificationGasLimit,
                postGas,
                (_mode << 1) | MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH,
                validUntil,
                validAfter
            );
        } else if (_mode == ERC20_MODE) {
            paymasterData = abi.encodePacked(
                address(PM),
                verificationGasLimit,
                postGas,
                (_mode << 1) | MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH,
                _combinedByte,
                validUntil,
                validAfter,
                address(mockERC20),
                postGas,
                exchangeRate,
                paymasterValidationGasLimit,
                treasury
            );
            if ((_combinedByte & 0x04) != 0) {
                // preFundPresent
                uint128 reasonablePreFund = uint128((requiredPreFund * exchangeRate) / 1e18 / 2);
                paymasterData = abi.encodePacked(paymasterData, reasonablePreFund);
            }

            if ((_combinedByte & 0x01) != 0) {
                // constantFeePresent
                paymasterData = abi.encodePacked(paymasterData, uint128(10000)); // constantFee (16 bytes)
            }

            if ((_combinedByte & 0x02) != 0) {
                // recipientPresent
                paymasterData = abi.encodePacked(paymasterData, address(sender)); // recipient (20 bytes)
            }
        }
    }

    function _validWindow() internal {
        validUntil = uint48(block.timestamp + 1 days);
        validAfter = 0;
    }

    function _signUserOp(bytes32 hash) internal view returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(senderPK, hash);

        signature = abi.encodePacked(r, s, v);
    }

    function _createPostOpContext(
        PackedUserOperation calldata _userOp,
        bytes32 _userOpHash,
        ERC20PaymasterData memory _cfg,
        uint256 _requiredPreFund
    ) internal pure returns (bytes memory) {
        // the limit we have for executing the userOp.
        uint256 executionGasLimit = _userOp.unpackCallGasLimit() + _userOp.unpackPostOpGasLimit();

        // the limit we are allowed for everything before the userOp is executed.
        uint256 preOpGasApproximation = _userOp.preVerificationGas + _userOp.unpackVerificationGasLimit() // VerificationGasLimit
            // is an overestimation.
            + _cfg.paymasterValidationGasLimit; // paymasterValidationGasLimit has to be an under estimation to compensate
            // for
            // the overestimation.

        return abi.encode(
            ERC20PostOpContext({
                sender: _userOp.sender,
                token: _cfg.token,
                treasury: _cfg.treasury,
                exchangeRate: _cfg.exchangeRate,
                postOpGas: _cfg.postOpGas,
                userOpHash: _userOpHash,
                maxFeePerGas: uint256(0), // for v0.7 userOperations, the gasPrice is passed in the postOp.
                maxPriorityFeePerGas: uint256(0), // for v0.7 userOperations, the gasPrice is passed in the postOp.
                executionGasLimit: executionGasLimit,
                preFund: _requiredPreFund,
                preFundCharged: _cfg.preFundInToken,
                preOpGasApproximation: preOpGasApproximation,
                constantFee: _cfg.constantFee,
                recipient: _cfg.recipient
            })
        );
    }

    function _parseErc20Config(bytes calldata _paymasterConfig)
        internal
        pure
        returns (ERC20PaymasterData memory config)
    {
        if (_paymasterConfig.length < ERC20_PAYMASTER_DATA_LENGTH) {
            revert OPFPaymasterV3__PaymasterConfigLengthInvalid();
        }

        uint128 configPointer = 0;

        uint8 combinedByte = uint8(_paymasterConfig[configPointer]);
        // constantFeePresent is in the *lowest* bit
        bool constantFeePresent = (combinedByte & 0x01) != 0;
        // recipientPresent is in the second lowest bit
        bool recipientPresent = (combinedByte & 0x02) != 0;
        // preFundPresent is in the third lowest bit
        bool preFundPresent = (combinedByte & 0x04) != 0;
        configPointer += 1;
        config.validUntil = uint48(bytes6(_paymasterConfig[configPointer:configPointer + 6])); // 6 bytes
        configPointer += 6;
        config.validAfter = uint48(bytes6(_paymasterConfig[configPointer:configPointer + 6])); // 6 bytes
        configPointer += 6;
        config.token = address(bytes20(_paymasterConfig[configPointer:configPointer + 20])); // 20 bytes
        configPointer += 20;
        config.postOpGas = uint128(bytes16(_paymasterConfig[configPointer:configPointer + 16])); // 16 bytes
        configPointer += 16;
        config.exchangeRate = uint256(bytes32(_paymasterConfig[configPointer:configPointer + 32])); // 32 bytes
        configPointer += 32;
        config.paymasterValidationGasLimit = uint128(bytes16(_paymasterConfig[configPointer:configPointer + 16])); // 16
            // bytes
        configPointer += 16;
        config.treasury = address(bytes20(_paymasterConfig[configPointer:configPointer + 20])); // 20 bytes
        configPointer += 20;

        config.preFundInToken = uint256(0);
        if (preFundPresent) {
            if (_paymasterConfig.length < configPointer + 16) {
                revert OPFPaymasterV3__PaymasterConfigLengthInvalid();
            }

            config.preFundInToken = uint128(bytes16(_paymasterConfig[configPointer:configPointer + 16])); // 16 bytes
            configPointer += 16;
        }
        config.constantFee = uint128(0);
        if (constantFeePresent) {
            if (_paymasterConfig.length < configPointer + 16) {
                revert OPFPaymasterV3__PaymasterConfigLengthInvalid();
            }

            config.constantFee = uint128(bytes16(_paymasterConfig[configPointer:configPointer + 16])); // 16 bytes
            configPointer += 16;
        }

        config.recipient = address(0);
        if (recipientPresent) {
            if (_paymasterConfig.length < configPointer + 20) {
                revert OPFPaymasterV3__PaymasterConfigLengthInvalid();
            }

            config.recipient = address(bytes20(_paymasterConfig[configPointer:configPointer + 20])); // 20 bytes
            configPointer += 20;
        }
        config.signature = _paymasterConfig[configPointer:];

        if (config.token == address(0)) {
            revert OPFPaymasterV3__TokenAddressInvalid();
        }

        if (config.exchangeRate == 0) {
            revert OPFPaymasterV3__ExchangeRateInvalid();
        }

        if (recipientPresent && config.recipient == address(0)) {
            revert OPFPaymasterV3__RecipientInvalid();
        }

        if (config.signature.length != 64 && config.signature.length != 65) {
            revert OPFPaymasterV3__PaymasterSignatureLengthInvalid();
        }

        return config;
    }

    function _parsePaymasterAndData(bytes calldata _paymasterAndData, uint256 _paymasterDataOffset)
        internal
        pure
        returns (uint8, bytes calldata)
    {
        if (_paymasterAndData.length < _paymasterDataOffset + 1) {
            revert OPFPaymasterV3__PaymasterAndDataLengthInvalid();
        }

        uint8 combinedByte = uint8(_paymasterAndData[_paymasterDataOffset]);
        // rest of the bits represent the mode
        uint8 mode = uint8((combinedByte >> 1));

        bytes calldata paymasterConfig = _paymasterAndData[_paymasterDataOffset + 1:];

        return (mode, paymasterConfig);
    }

    function _calculateExpectedTokenTransfer(bytes memory context, uint256 actualGasCost, uint256 actualUserOpFeePerGas)
        internal
        pure
        returns (uint256)
    {
        ERC20PostOpContext memory ctx = abi.decode(context, (ERC20PostOpContext));

        uint256 expectedPenaltyGasCost = _expectedPenaltyGasCost(
            actualGasCost, actualUserOpFeePerGas, ctx.postOpGas, ctx.preOpGasApproximation, ctx.executionGasLimit
        );

        uint256 totalActualGasCost = actualGasCost + expectedPenaltyGasCost;

        uint256 costInToken =
            getCostInToken(totalActualGasCost, ctx.postOpGas, actualUserOpFeePerGas, ctx.exchangeRate) + ctx.constantFee;

        uint256 absoluteCostInToken =
            costInToken > ctx.preFundCharged ? costInToken - ctx.preFundCharged : ctx.preFundCharged - costInToken;

        return absoluteCostInToken;
    }

    function _expectedPenaltyGasCost(
        uint256 _actualGasCost,
        uint256 _actualUserOpFeePerGas,
        uint128 postOpGas,
        uint256 preOpGasApproximation,
        uint256 executionGasLimit
    ) internal pure returns (uint256) {
        uint256 PENALTY_PERCENT = 10;
        uint256 executionGasUsed = 0;
        uint256 actualGas = _actualGasCost / _actualUserOpFeePerGas + postOpGas;

        if (actualGas > preOpGasApproximation) {
            executionGasUsed = actualGas - preOpGasApproximation;
        }

        uint256 expectedPenaltyGas = 0;
        if (executionGasLimit > executionGasUsed) {
            expectedPenaltyGas = ((executionGasLimit - executionGasUsed) * PENALTY_PERCENT) / 100;
        }

        return expectedPenaltyGas * _actualUserOpFeePerGas;
    }

    function getCostInToken(
        uint256 _actualGasCost,
        uint256 _postOpGas,
        uint256 _actualUserOpFeePerGas,
        uint256 _exchangeRate
    ) internal pure returns (uint256) {
        return ((_actualGasCost + (_postOpGas * _actualUserOpFeePerGas)) * _exchangeRate) / 1e18;
    }
}
