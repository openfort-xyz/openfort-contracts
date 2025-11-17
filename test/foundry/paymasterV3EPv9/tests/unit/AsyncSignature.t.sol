// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import {Deploy} from "test/foundry/paymasterV3EPv9/Deploy.t.sol";
import {console2 as console} from "lib/forge-std/src/console2.sol";
import {PackedUserOperation} from "lib/account-abstraction-v09/contracts/interfaces/PackedUserOperation.sol";
import {UserOperationLib as UserOperationLibV9} from "lib/account-abstraction-v09/contracts/core/UserOperationLib.sol";

contract AsyncSignature is Deploy {
    function test_AsyncSiganture_VERIFYING_MODE() external {
        bytes memory callData = abi.encodeWithSignature("execute(address,uint256,bytes)", address(0xbAbE), 0, hex"");

        PackedUserOperation memory userOp = _getFreshUserOp(owner7702);

        userOp = _populateUserOp(
            userOp, callData, _packAccountGasLimits(400_000, 600_000), 800_000, _packGasFees(15 gwei, 80 gwei), hex""
        );

        uint128 verificationGasLimit = uint128(uint256(bytes32(userOp.accountGasLimits)) >> 128);
        _validWindow();

        userOp.paymasterAndData = abi.encodePacked(
            address(PM),
            verificationGasLimit,
            postGas,
            (VERIFYING_MODE << 1) | MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH,
            validUntil,
            validAfter,
            UserOperationLibV9.PAYMASTER_SIG_MAGIC
        );

        bytes32 userOpHash = _getUserOpHash(userOp);
        
        userOp.signature = _signUserOp(userOpHash, owner7702PK);

        userOp.paymasterAndData = abi.encodePacked(
            address(PM),
            verificationGasLimit,
            postGas,
            (VERIFYING_MODE << 1) | MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH,
            validUntil,
            validAfter,
            uint16(0),
            UserOperationLibV9.PAYMASTER_SIG_MAGIC
        );
        bytes memory paymasterSignature = this._signPaymasterData(VERIFYING_MODE, userOp, 0);

        userOp.paymasterAndData = abi.encodePacked(
            address(PM),
            verificationGasLimit,
            postGas,
            (VERIFYING_MODE << 1) | MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH,
            validUntil,
            validAfter,
            paymasterSignature,
            uint16(paymasterSignature.length),
            UserOperationLibV9.PAYMASTER_SIG_MAGIC
        );

        console.log("\n=== PackedUserOperation ===");
        console.log("sender:              ", userOp.sender);
        console.log("nonce:               ", userOp.nonce);
        console.log("initCode:            ", vm.toString(userOp.initCode));
        console.log("callData:            ", vm.toString(userOp.callData));
        console.log("accountGasLimits:    ", vm.toString(userOp.accountGasLimits));
        console.log("preVerificationGas:  ", userOp.preVerificationGas);
        console.log("gasFees:             ", vm.toString(userOp.gasFees));
        console.log("paymasterAndData:    ", vm.toString(userOp.paymasterAndData));
        console.log("signature:           ", vm.toString(userOp.signature));
        console.log("===========================\n");

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        _etch();

        vm.prank(sender, sender);
        ENTRY_POINT_V9.handleOps(ops, payable(owner));
    }

    function test_AsyncSiganture_ERC20_MODE_combinedByteBasic() external {
        _mintAndApprove(owner7702, 30 ether);

        bytes memory callData = abi.encodeWithSignature("execute(address,uint256,bytes)", address(0xbAbE), 0, hex"");

        PackedUserOperation memory userOp = _getFreshUserOp(owner7702);

        userOp = _populateUserOp(
            userOp, callData, _packAccountGasLimits(400_000, 600_000), 800_000, _packGasFees(15 gwei, 80 gwei), hex""
        );

        uint128 verificationGasLimit = uint128(uint256(bytes32(userOp.accountGasLimits)) >> 128);
        _validWindow();

        bytes memory dummySignature = new bytes(65);
        userOp.paymasterAndData = abi.encodePacked(
            address(PM),
            verificationGasLimit,
            postGas,
            (ERC20_MODE << 1) | MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH,
            uint8(combinedByteBasic),
            validUntil,
            validAfter,
            address(mockERC20),
            postGas,
            exchangeRate,
            paymasterValidationGasLimit,
            treasury,
            dummySignature,
            uint16(65),
            UserOperationLibV9.PAYMASTER_SIG_MAGIC
        );

        bytes32 userOpHash = _getUserOpHash(userOp);

        userOp.signature = _signUserOp(userOpHash, owner7702PK);
        bytes memory paymasterSignature = this._signPaymasterData(ERC20_MODE, userOp, 1);

        userOp.paymasterAndData = abi.encodePacked(
            address(PM),
            verificationGasLimit,
            postGas,
            (ERC20_MODE << 1) | MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH,
            uint8(combinedByteBasic),
            validUntil,
            validAfter,
            address(mockERC20),
            postGas,
            exchangeRate,
            paymasterValidationGasLimit,
            treasury,
            paymasterSignature,
            uint16(paymasterSignature.length),
            UserOperationLibV9.PAYMASTER_SIG_MAGIC
        );

        console.log("\n=== PackedUserOperation (ERC20 Mode) ===");
        console.log("sender:              ", userOp.sender);
        console.log("nonce:               ", userOp.nonce);
        console.log("initCode:            ", vm.toString(userOp.initCode));
        console.log("callData:            ", vm.toString(userOp.callData));
        console.log("accountGasLimits:    ", vm.toString(userOp.accountGasLimits));
        console.log("preVerificationGas:  ", userOp.preVerificationGas);
        console.log("gasFees:             ", vm.toString(userOp.gasFees));
        console.log("paymasterAndData:    ", vm.toString(userOp.paymasterAndData));
        console.log("signature:           ", vm.toString(userOp.signature));
        console.log("===========================\n");

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        _etch();

        vm.prank(sender, sender);
        ENTRY_POINT_V9.handleOps(ops, payable(owner));
    }

    function test_SyncSiganture_VERIFYING_MODE() external {
        bytes memory callData = abi.encodeWithSignature("execute(address,uint256,bytes)", address(0xbAbE), 0, hex"");

        PackedUserOperation memory userOp = _getFreshUserOp(owner7702);

        userOp = _populateUserOp(
            userOp, callData, _packAccountGasLimits(400_000, 600_000), 800_000, _packGasFees(15 gwei, 80 gwei), hex""
        );

        userOp.paymasterAndData = _createPaymasterDataMode(userOp, VERIFYING_MODE, 0);

        bytes memory paymasterSignature = this._signPaymasterData(VERIFYING_MODE, userOp, 0);

        userOp.paymasterAndData = abi.encodePacked(userOp.paymasterAndData, paymasterSignature);

        bytes32 userOpHash = _getUserOpHash(userOp);

        userOp.signature = _signUserOp(userOpHash, owner7702PK);

        console.log("\n=== PackedUserOperation ===");
        console.log("sender:              ", userOp.sender);
        console.log("nonce:               ", userOp.nonce);
        console.log("initCode:            ", vm.toString(userOp.initCode));
        console.log("callData:            ", vm.toString(userOp.callData));
        console.log("accountGasLimits:    ", vm.toString(userOp.accountGasLimits));
        console.log("preVerificationGas:  ", userOp.preVerificationGas);
        console.log("gasFees:             ", vm.toString(userOp.gasFees));
        console.log("paymasterAndData:    ", vm.toString(userOp.paymasterAndData));
        console.log("signature:           ", vm.toString(userOp.signature));
        console.log("===========================\n");

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        _etch();

        vm.prank(sender, sender);
        ENTRY_POINT_V9.handleOps(ops, payable(owner));
    }

    function test_SyncSiganture_ERC20_MODE_combinedByteBasic() external {
        _mintAndApprove(owner7702, 30 ether);

        bytes memory callData = abi.encodeWithSignature("execute(address,uint256,bytes)", address(0xbAbE), 0, hex"");

        PackedUserOperation memory userOp = _getFreshUserOp(owner7702);

        userOp = _populateUserOp(
            userOp, callData, _packAccountGasLimits(400_000, 600_000), 800_000, _packGasFees(15 gwei, 80 gwei), hex""
        );

        userOp.paymasterAndData = _createPaymasterDataMode(userOp, ERC20_MODE, combinedByteBasic);

        bytes memory paymasterSignature = this._signPaymasterData(ERC20_MODE, userOp, 1);

        userOp.paymasterAndData = abi.encodePacked(userOp.paymasterAndData, paymasterSignature);

        bytes32 userOpHash = _getUserOpHash(userOp);
        userOp.signature = _signUserOp(userOpHash, owner7702PK);

        console.log("\n=== PackedUserOperation (ERC20 Mode) ===");
        console.log("sender:              ", userOp.sender);
        console.log("nonce:               ", userOp.nonce);
        console.log("initCode:            ", vm.toString(userOp.initCode));
        console.log("callData:            ", vm.toString(userOp.callData));
        console.log("accountGasLimits:    ", vm.toString(userOp.accountGasLimits));
        console.log("preVerificationGas:  ", userOp.preVerificationGas);
        console.log("gasFees:             ", vm.toString(userOp.gasFees));
        console.log("paymasterAndData:    ", vm.toString(userOp.paymasterAndData));
        console.log("signature:           ", vm.toString(userOp.signature));
        console.log("===========================\n");

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        _etch();

        vm.prank(sender, sender);
        ENTRY_POINT_V9.handleOps(ops, payable(owner));
    }
}
