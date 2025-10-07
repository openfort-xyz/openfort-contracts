// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {IERC20} from "@oz-v5.4.0/token/ERC20/IERC20.sol";
import {IPaymasterV8} from "contracts/paymaster/PaymasterV3/interfaces/IPaymasterV8.sol";
import {_parseValidationData, ValidationData} from "@account-abstraction-v8/core/Helpers.sol";
import {PackedUserOperation} from "@account-abstraction-v8/interfaces/PackedUserOperation.sol";
import {PaymasterHelpers} from "test/foundry/paymasterV3/paymaster-helpers/PaymasterHelpers.sol";

uint256 constant mintTokens = 30e18;

contract PaymasterPostOp is PaymasterHelpers {
    modifier mint() {
        _mint(sender, mintTokens);
        _;
    }

    function test_balanceOf() public mint {
        uint256 balance = IERC20(address(mockERC20)).balanceOf(sender);
        assertEq(mintTokens, balance);
    }

    function test_postOpERC20_MODE_combinedByteBasic() public mint {
        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp.nonce = ENTRY_POINT_V8.getNonce(userOp.sender, 0);
        userOp.accountGasLimits = _packAccountGasLimits(600_000, 400_000);
        userOp.preVerificationGas = preVerificationGas;
        userOp.gasFees = _packGasFees(80 gwei, 15 gwei);

        userOp.paymasterAndData = _createPaymasterDataMode(userOp, ERC20_MODE, combinedByteBasic);
        bytes memory paymasterSignature = this._signPaymasterData(ERC20_MODE, userOp, 1);
        userOp.paymasterAndData = abi.encodePacked(userOp.paymasterAndData, paymasterSignature);

        bytes32 userOpHash = ENTRY_POINT_V8.getUserOpHash(userOp);
        userOp.signature = _signUserOp(userOpHash);

        vm.prank(address(ENTRY_POINT_V8));
        (bytes memory context, uint256 validationData) = PM.validatePaymasterUserOp(userOp, userOpHash, 0);

        (, bytes memory paymasterConfig) = this._parsePaymasterAndDataCallData(userOp);

        ERC20PaymasterData memory cfg = this._parseErc20ConfigCallData(paymasterConfig);
        bytes memory compureContext = this._createPostOpContextCallData(userOp, userOpHash, cfg, 0);

        ValidationData memory data = _parseValidationData(validationData);

        assertEq(context, compureContext);
        assertEq(data.validUntil, validUntil);
        assertEq(data.validAfter, validAfter);

        uint256 actualUserOpFeePerGas = uint128(uint256(bytes32(userOp.gasFees)) >> 128);
        uint256 actualGasCost = 350000 * actualUserOpFeePerGas;
        uint256 expectedTokenTransfer = _calculateExpectedTokenTransfer(context, actualGasCost, actualUserOpFeePerGas);

        uint256 treasuryBalanceBefore = IERC20(address(mockERC20)).balanceOf(treasury);
        uint256 senderBalanceBefore = IERC20(address(mockERC20)).balanceOf(sender);

        this._postOp(IPaymasterV8.PostOpMode.opSucceeded, context, actualGasCost, actualUserOpFeePerGas);

        uint256 treasuryBalanceAfter = IERC20(address(mockERC20)).balanceOf(treasury);
        uint256 senderBalanceAfter = IERC20(address(mockERC20)).balanceOf(sender);

        assertEq(treasuryBalanceAfter - treasuryBalanceBefore, expectedTokenTransfer);
        assertEq(senderBalanceBefore - senderBalanceAfter, expectedTokenTransfer);
    }

    function test_postOpERC20_MODE_combinedByteFee() public mint {
        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp.nonce = ENTRY_POINT_V8.getNonce(userOp.sender, 0);
        userOp.accountGasLimits = _packAccountGasLimits(600_000, 400_000);
        userOp.preVerificationGas = preVerificationGas;
        userOp.gasFees = _packGasFees(80 gwei, 15 gwei);

        userOp.paymasterAndData = _createPaymasterDataMode(userOp, ERC20_MODE, combinedByteFee);
        bytes memory paymasterSignature = this._signPaymasterData(ERC20_MODE, userOp, 1);
        userOp.paymasterAndData = abi.encodePacked(userOp.paymasterAndData, paymasterSignature);

        bytes32 userOpHash = ENTRY_POINT_V8.getUserOpHash(userOp);
        userOp.signature = _signUserOp(userOpHash);

        vm.prank(address(ENTRY_POINT_V8));
        (bytes memory context, uint256 validationData) = PM.validatePaymasterUserOp(userOp, userOpHash, 0);

        (, bytes memory paymasterConfig) = this._parsePaymasterAndDataCallData(userOp);

        ERC20PaymasterData memory cfg = this._parseErc20ConfigCallData(paymasterConfig);
        bytes memory compureContext = this._createPostOpContextCallData(userOp, userOpHash, cfg, 0);

        ValidationData memory data = _parseValidationData(validationData);

        assertEq(context, compureContext);
        assertEq(data.validUntil, validUntil);
        assertEq(data.validAfter, validAfter);

        uint256 actualUserOpFeePerGas = uint128(uint256(bytes32(userOp.gasFees)) >> 128);
        uint256 actualGasCost = 350000 * actualUserOpFeePerGas;
        uint256 expectedTokenTransfer = _calculateExpectedTokenTransfer(context, actualGasCost, actualUserOpFeePerGas);

        uint256 treasuryBalanceBefore = IERC20(address(mockERC20)).balanceOf(treasury);
        uint256 senderBalanceBefore = IERC20(address(mockERC20)).balanceOf(sender);

        this._postOp(IPaymasterV8.PostOpMode.opSucceeded, context, actualGasCost, actualUserOpFeePerGas);

        uint256 treasuryBalanceAfter = IERC20(address(mockERC20)).balanceOf(treasury);
        uint256 senderBalanceAfter = IERC20(address(mockERC20)).balanceOf(sender);

        assertEq(treasuryBalanceAfter - treasuryBalanceBefore, expectedTokenTransfer);
        assertEq(senderBalanceBefore - senderBalanceAfter, expectedTokenTransfer);
    }

    function test_postOpERC20_MODE_combinedByteRecipient() public mint {
        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp.nonce = ENTRY_POINT_V8.getNonce(userOp.sender, 0);
        userOp.accountGasLimits = _packAccountGasLimits(600_000, 400_000);
        userOp.preVerificationGas = preVerificationGas;
        userOp.gasFees = _packGasFees(80 gwei, 15 gwei);

        userOp.paymasterAndData = _createPaymasterDataMode(userOp, ERC20_MODE, combinedByteRecipient);
        bytes memory paymasterSignature = this._signPaymasterData(ERC20_MODE, userOp, 1);
        userOp.paymasterAndData = abi.encodePacked(userOp.paymasterAndData, paymasterSignature);

        bytes32 userOpHash = ENTRY_POINT_V8.getUserOpHash(userOp);
        userOp.signature = _signUserOp(userOpHash);

        vm.prank(address(ENTRY_POINT_V8));
        (bytes memory context, uint256 validationData) = PM.validatePaymasterUserOp(userOp, userOpHash, 0);

        (, bytes memory paymasterConfig) = this._parsePaymasterAndDataCallData(userOp);
        ERC20PaymasterData memory cfg = this._parseErc20ConfigCallData(paymasterConfig);
        bytes memory compureContext = this._createPostOpContextCallData(userOp, userOpHash, cfg, 0);

        ValidationData memory data = _parseValidationData(validationData);

        assertEq(context, compureContext);
        assertEq(data.validUntil, validUntil);
        assertEq(data.validAfter, validAfter);

        uint256 actualUserOpFeePerGas = uint128(uint256(bytes32(userOp.gasFees)) >> 128);
        uint256 actualGasCost = 350000 * actualUserOpFeePerGas;
        uint256 expectedTokenTransfer = _calculateExpectedTokenTransfer(context, actualGasCost, actualUserOpFeePerGas);

        uint256 treasuryBalanceBefore = IERC20(address(mockERC20)).balanceOf(treasury);
        uint256 senderBalanceBefore = IERC20(address(mockERC20)).balanceOf(sender);

        this._postOp(IPaymasterV8.PostOpMode.opSucceeded, context, actualGasCost, actualUserOpFeePerGas);

        uint256 treasuryBalanceAfter = IERC20(address(mockERC20)).balanceOf(treasury);
        uint256 senderBalanceAfter = IERC20(address(mockERC20)).balanceOf(sender);

        assertEq(treasuryBalanceAfter - treasuryBalanceBefore, expectedTokenTransfer);
        assertEq(senderBalanceBefore - senderBalanceAfter, expectedTokenTransfer);
    }

    function test_postOpERC20_MODE_combinedBytePreFund() public mint {
        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp.nonce = ENTRY_POINT_V8.getNonce(userOp.sender, 0);
        userOp.accountGasLimits = _packAccountGasLimits(600_000, 400_000);
        userOp.preVerificationGas = preVerificationGas;
        userOp.gasFees = _packGasFees(80 gwei, 15 gwei);

        userOp.paymasterAndData = _createPaymasterDataMode(userOp, ERC20_MODE, combinedBytePreFund);
        bytes memory paymasterSignature = this._signPaymasterData(ERC20_MODE, userOp, 1);
        userOp.paymasterAndData = abi.encodePacked(userOp.paymasterAndData, paymasterSignature);

        bytes32 userOpHash = ENTRY_POINT_V8.getUserOpHash(userOp);
        userOp.signature = _signUserOp(userOpHash);

        vm.prank(address(ENTRY_POINT_V8));
        (bytes memory context, uint256 validationData) = PM.validatePaymasterUserOp(userOp, userOpHash, requiredPreFund);

        (, bytes memory paymasterConfig) = this._parsePaymasterAndDataCallData(userOp);

        ERC20PaymasterData memory cfg = this._parseErc20ConfigCallData(paymasterConfig);
        bytes memory compureContext = this._createPostOpContextCallData(userOp, userOpHash, cfg, requiredPreFund);

        ValidationData memory data = _parseValidationData(validationData);

        assertEq(context, compureContext);
        assertEq(data.validUntil, validUntil);
        assertEq(data.validAfter, validAfter);

        uint256 actualUserOpFeePerGas = uint128(uint256(bytes32(userOp.gasFees)) >> 128);
        uint256 actualGasCost = 350000 * actualUserOpFeePerGas;
        uint256 expectedTokenTransfer = _calculateExpectedTokenTransfer(context, actualGasCost, actualUserOpFeePerGas);

        uint256 treasuryBalanceBefore = IERC20(address(mockERC20)).balanceOf(treasury);
        uint256 senderBalanceBefore = IERC20(address(mockERC20)).balanceOf(sender);

        this._postOp(IPaymasterV8.PostOpMode.opSucceeded, context, actualGasCost, actualUserOpFeePerGas);

        uint256 treasuryBalanceAfter = IERC20(address(mockERC20)).balanceOf(treasury);
        uint256 senderBalanceAfter = IERC20(address(mockERC20)).balanceOf(sender);

        assertEq(treasuryBalanceAfter - treasuryBalanceBefore, expectedTokenTransfer);
        assertEq(senderBalanceBefore - senderBalanceAfter, expectedTokenTransfer);
    }

    function test_postOpERC20_MODE_combinedByteAll() public mint {
        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp.nonce = ENTRY_POINT_V8.getNonce(userOp.sender, 0);
        userOp.accountGasLimits = _packAccountGasLimits(600_000, 400_000);
        userOp.preVerificationGas = preVerificationGas;
        userOp.gasFees = _packGasFees(80 gwei, 15 gwei);

        userOp.paymasterAndData = _createPaymasterDataMode(userOp, ERC20_MODE, combinedByteAll);
        bytes memory paymasterSignature = this._signPaymasterData(ERC20_MODE, userOp, 1);
        userOp.paymasterAndData = abi.encodePacked(userOp.paymasterAndData, paymasterSignature);

        bytes32 userOpHash = ENTRY_POINT_V8.getUserOpHash(userOp);
        userOp.signature = _signUserOp(userOpHash);

        vm.prank(address(ENTRY_POINT_V8));
        (bytes memory context, uint256 validationData) = PM.validatePaymasterUserOp(userOp, userOpHash, 0);

        (, bytes memory paymasterConfig) = this._parsePaymasterAndDataCallData(userOp);
        ERC20PaymasterData memory cfg = this._parseErc20ConfigCallData(paymasterConfig);
        bytes memory compureContext = this._createPostOpContextCallData(userOp, userOpHash, cfg, 0);

        ValidationData memory data = _parseValidationData(validationData);

        assertEq(context, compureContext);
        assertEq(data.validUntil, validUntil);
        assertEq(data.validAfter, validAfter);

        uint256 actualUserOpFeePerGas = uint128(uint256(bytes32(userOp.gasFees)) >> 128);
        uint256 actualGasCost = 350000 * actualUserOpFeePerGas;
        uint256 expectedTokenTransfer = _calculateExpectedTokenTransfer(context, actualGasCost, actualUserOpFeePerGas);

        uint256 treasuryBalanceBefore = IERC20(address(mockERC20)).balanceOf(treasury);
        uint256 senderBalanceBefore = IERC20(address(mockERC20)).balanceOf(sender);

        this._postOp(IPaymasterV8.PostOpMode.opSucceeded, context, actualGasCost, actualUserOpFeePerGas);

        uint256 treasuryBalanceAfter = IERC20(address(mockERC20)).balanceOf(treasury);
        uint256 senderBalanceAfter = IERC20(address(mockERC20)).balanceOf(sender);

        assertEq(treasuryBalanceAfter - treasuryBalanceBefore, expectedTokenTransfer);
        assertEq(senderBalanceBefore - senderBalanceAfter, expectedTokenTransfer);
    }

    function _postOp(
        IPaymasterV8.PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost,
        uint256 actualUserOpFeePerGas
    ) external {
        vm.prank(sender);
        IERC20(address(mockERC20)).approve(address(PM), type(uint256).max);

        vm.prank(address(ENTRY_POINT_V8));
        PM.postOp(mode, context, actualGasCost, actualUserOpFeePerGas);
    }
}
