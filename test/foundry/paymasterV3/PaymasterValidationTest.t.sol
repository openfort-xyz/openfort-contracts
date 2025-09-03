// SPDX-license-Identifier: MIT

pragma solidity ^0.8.29;

import {IERC20} from "@oz-v5.4.0/token/ERC20/IERC20.sol";
import {PackedUserOperation} from "@account-abstraction-v8/interfaces/PackedUserOperation.sol";
import {_parseValidationData, ValidationData} from "@account-abstraction-v8/core/Helpers.sol";
import {PaymasterHelpers} from "test/foundry/paymasterV3/paymaster-helpers/PaymasterHelpers.sol";

import {console2 as console} from "lib/forge-std/src/test.sol";

uint256 constant mintTokens = 30e18;

contract PaymasterValidationTest is PaymasterHelpers {
    modifier mint() {
        _mint(sender, mintTokens);
        _;
    }

    function test_balanceOf() public mint {
        uint256 balance = IERC20(address(mockERC20)).balanceOf(sender);
        assertEq(mintTokens, balance);
    }

    function test_validatePaymasterUserOpModeVERIFYING_MODE() public mint {
        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp.nonce = ENTRY_POINT_V8.getNonce(userOp.sender, 0);
        userOp.accountGasLimits = _packAccountGasLimits(600_000, 400_000);
        userOp.preVerificationGas = preVerificationGas;
        userOp.gasFees = _packGasFees(80 gwei, 15 gwei);

        userOp.paymasterAndData = _createPaymasterDataMode(userOp, VERIFYING_MODE, 0);
        bytes memory paymasterSignature = this._signPaymasterData(VERIFYING_MODE, userOp, 1);
        userOp.paymasterAndData = abi.encodePacked(userOp.paymasterAndData, paymasterSignature);

        bytes32 userOpHash = ENTRY_POINT_V8.getUserOpHash(userOp);
        userOp.signature = _signUserOp(userOpHash);

        vm.prank(address(ENTRY_POINT_V8));
        (bytes memory context, uint256 validationData) = PM.validatePaymasterUserOp(userOp, userOpHash, 0);

        ValidationData memory data = _parseValidationData(validationData);

        assertEq(context, hex"");
        assertEq(data.validUntil, validUntil);
        assertEq(data.validAfter, validAfter);
    }

    function test_validatePaymasterUserOpModeERC20_MODE_combinedByteBasic() public {
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
    }

    function test_validatePaymasterUserOpModeERC20_MODE_combinedByteFee() public {
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
    }

    function test_validatePaymasterUserOpModeERC20_MODE_combinedByteRecipient() public {
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
    }

    function test_validatePaymasterUserOpModeERC20_MODE_combinedBytePreFund() public {
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
    }

    function test_validatePaymasterUserOpModeERC20_MODE_combinedByteAll() public {
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
        (bytes memory context, uint256 validationData) = PM.validatePaymasterUserOp(userOp, userOpHash, requiredPreFund);

        (, bytes memory paymasterConfig) = this._parsePaymasterAndDataCallData(userOp);

        ERC20PaymasterData memory cfg = this._parseErc20ConfigCallData(paymasterConfig);
        bytes memory compureContext = this._createPostOpContextCallData(userOp, userOpHash, cfg, requiredPreFund);

        ValidationData memory data = _parseValidationData(validationData);

        assertEq(context, compureContext);
        assertEq(data.validUntil, validUntil);
        assertEq(data.validAfter, validAfter);
    }
}
