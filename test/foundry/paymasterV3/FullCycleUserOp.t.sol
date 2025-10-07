// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {IERC20} from "@oz-v5.4.0/token/ERC20/IERC20.sol";
import {MockERC20} from "test/foundry/paymasterV3/mocks/MockERC20.sol";
import {PackedUserOperation} from "@account-abstraction-v8/interfaces/PackedUserOperation.sol";
import {PaymasterHelpers} from "test/foundry/paymasterV3/paymaster-helpers/PaymasterHelpers.sol";

uint256 constant mintTokens = 30e18;
uint256 constant sendTokens = 5e18;

contract FullCycleUserOp is PaymasterHelpers {
    modifier mint() {
        _mint(sender, mintTokens);
        _;
    }

    modifier approvePM() {
        vm.prank(sender);
        mockERC20.approve(address(PM), type(uint256).max);
        _;
    }

    modifier depositAndStakeEP() {
        vm.startPrank(owner);
        PM.deposit{value: 1 ether}();
        PM.addStake{value: 1 ether}(860);
        vm.stopPrank();
        _;
    }

    function test_FullCycleUserOpModeVERIFYING_MODE() public depositAndStakeEP {
        uint256 balanceSener = sender.balance;
        assertEq(balanceSener, 0);

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp.nonce = ENTRY_POINT_V8.getNonce(userOp.sender, 0);
        userOp.initCode = hex"7702";

        address target = address(mockERC20);
        uint256 value = 0;
        bytes memory data = abi.encodeWithSelector(MockERC20.mint.selector, sender, mintTokens);

        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(address,uint256,bytes)")), target, value, data);
        userOp.callData = callData;

        userOp.accountGasLimits = _packAccountGasLimits(600_000, 400_000);
        userOp.preVerificationGas = preVerificationGas;
        userOp.gasFees = _packGasFees(80 gwei, 15 gwei);

        userOp.paymasterAndData = _createPaymasterDataMode(userOp, VERIFYING_MODE, 0);
        bytes memory paymasterSignature = this._signPaymasterData(VERIFYING_MODE, userOp, 1);
        userOp.paymasterAndData = abi.encodePacked(userOp.paymasterAndData, paymasterSignature);

        bytes32 userOpHash = ENTRY_POINT_V8.getUserOpHash(userOp);
        userOp.signature = _signUserOp(userOpHash);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        _etch();

        uint256 senderBalanceBefore = IERC20(address(mockERC20)).balanceOf(sender);

        vm.prank(owner);
        ENTRY_POINT_V8.handleOps(ops, payable(owner));

        uint256 senderBalanceAfter = IERC20(address(mockERC20)).balanceOf(sender);

        assertEq(senderBalanceBefore + mintTokens, senderBalanceAfter);
    }

    function test_FullCycleUserOpERC20_MODE_combinedByteBasic() public depositAndStakeEP mint approvePM {
        uint256 balanceSener = sender.balance;
        assertEq(balanceSener, 0);
        address random = makeAddr("random");

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp.nonce = ENTRY_POINT_V8.getNonce(userOp.sender, 0);
        userOp.initCode = hex"7702";

        address target = address(mockERC20);
        uint256 value = 0;
        bytes memory data = abi.encodeWithSelector(IERC20.transfer.selector, random, sendTokens);

        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(address,uint256,bytes)")), target, value, data);
        userOp.callData = callData;

        userOp.accountGasLimits = _packAccountGasLimits(600_000, 400_000);
        userOp.preVerificationGas = preVerificationGas;
        userOp.gasFees = _packGasFees(80 gwei, 15 gwei);

        userOp.paymasterAndData = _createPaymasterDataMode(userOp, ERC20_MODE, combinedByteBasic);
        bytes memory paymasterSignature = this._signPaymasterData(ERC20_MODE, userOp, 1);
        userOp.paymasterAndData = abi.encodePacked(userOp.paymasterAndData, paymasterSignature);

        bytes32 userOpHash = ENTRY_POINT_V8.getUserOpHash(userOp);
        userOp.signature = _signUserOp(userOpHash);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        _etch();

        uint256 randomBalanceBefore = IERC20(address(mockERC20)).balanceOf(random);
        uint256 treasuryBalanceBefore = IERC20(address(mockERC20)).balanceOf(treasury);
        uint256 senderBalanceBefore = IERC20(address(mockERC20)).balanceOf(sender);

        vm.prank(owner);
        ENTRY_POINT_V8.handleOps(ops, payable(owner));

        uint256 randomBalanceAfter = IERC20(address(mockERC20)).balanceOf(random);
        uint256 treasuryBalanceAfter = IERC20(address(mockERC20)).balanceOf(treasury);
        uint256 senderBalanceAfter = IERC20(address(mockERC20)).balanceOf(sender);

        assertEq(randomBalanceBefore + sendTokens, randomBalanceAfter);
        assertEq(senderBalanceBefore - (15156 + sendTokens), senderBalanceAfter);
        assertNotEq(treasuryBalanceBefore, treasuryBalanceAfter);
    }

    function test_FullCycleUserOpERC20_MODE_combinedByteFee() public depositAndStakeEP mint approvePM {
        uint256 balanceSener = sender.balance;
        assertEq(balanceSener, 0);
        address random = makeAddr("random");

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp.nonce = ENTRY_POINT_V8.getNonce(userOp.sender, 0);
        userOp.initCode = hex"7702";

        address target = address(mockERC20);
        uint256 value = 0;
        bytes memory data = abi.encodeWithSelector(IERC20.transfer.selector, random, sendTokens);

        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(address,uint256,bytes)")), target, value, data);
        userOp.callData = callData;

        userOp.accountGasLimits = _packAccountGasLimits(600_000, 400_000);
        userOp.preVerificationGas = preVerificationGas;
        userOp.gasFees = _packGasFees(80 gwei, 15 gwei);

        userOp.paymasterAndData = _createPaymasterDataMode(userOp, ERC20_MODE, combinedByteFee);
        bytes memory paymasterSignature = this._signPaymasterData(ERC20_MODE, userOp, 1);
        userOp.paymasterAndData = abi.encodePacked(userOp.paymasterAndData, paymasterSignature);

        bytes32 userOpHash = ENTRY_POINT_V8.getUserOpHash(userOp);
        userOp.signature = _signUserOp(userOpHash);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        _etch();

        uint256 randomBalanceBefore = IERC20(address(mockERC20)).balanceOf(random);
        uint256 treasuryBalanceBefore = IERC20(address(mockERC20)).balanceOf(treasury);
        uint256 senderBalanceBefore = IERC20(address(mockERC20)).balanceOf(sender);

        vm.prank(owner);
        ENTRY_POINT_V8.handleOps(ops, payable(owner));

        uint256 randomBalanceAfter = IERC20(address(mockERC20)).balanceOf(random);
        uint256 treasuryBalanceAfter = IERC20(address(mockERC20)).balanceOf(treasury);
        uint256 senderBalanceAfter = IERC20(address(mockERC20)).balanceOf(sender);

        assertEq(randomBalanceBefore + sendTokens, randomBalanceAfter);
        assertEq(senderBalanceBefore - (25167 + sendTokens), senderBalanceAfter);
        assertNotEq(treasuryBalanceBefore, treasuryBalanceAfter);
    }

    function test_FullCycleUserOpERC20_MODE_combinedByteRecipient() public depositAndStakeEP mint approvePM {
        uint256 balanceSener = sender.balance;
        assertEq(balanceSener, 0);
        address random = makeAddr("random");

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp.nonce = ENTRY_POINT_V8.getNonce(userOp.sender, 0);
        userOp.initCode = hex"7702";

        address target = address(mockERC20);
        uint256 value = 0;
        bytes memory data = abi.encodeWithSelector(IERC20.transfer.selector, random, sendTokens);

        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(address,uint256,bytes)")), target, value, data);
        userOp.callData = callData;

        userOp.accountGasLimits = _packAccountGasLimits(600_000, 400_000);
        userOp.preVerificationGas = preVerificationGas;
        userOp.gasFees = _packGasFees(80 gwei, 15 gwei);

        userOp.paymasterAndData = _createPaymasterDataMode(userOp, ERC20_MODE, combinedByteRecipient);
        bytes memory paymasterSignature = this._signPaymasterData(ERC20_MODE, userOp, 1);
        userOp.paymasterAndData = abi.encodePacked(userOp.paymasterAndData, paymasterSignature);

        bytes32 userOpHash = ENTRY_POINT_V8.getUserOpHash(userOp);
        userOp.signature = _signUserOp(userOpHash);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        _etch();

        uint256 randomBalanceBefore = IERC20(address(mockERC20)).balanceOf(random);
        uint256 treasuryBalanceBefore = IERC20(address(mockERC20)).balanceOf(treasury);
        uint256 senderBalanceBefore = IERC20(address(mockERC20)).balanceOf(sender);

        vm.prank(owner);
        ENTRY_POINT_V8.handleOps(ops, payable(owner));

        uint256 randomBalanceAfter = IERC20(address(mockERC20)).balanceOf(random);
        uint256 treasuryBalanceAfter = IERC20(address(mockERC20)).balanceOf(treasury);
        uint256 senderBalanceAfter = IERC20(address(mockERC20)).balanceOf(sender);

        assertEq(randomBalanceBefore + sendTokens, randomBalanceAfter);
        assertEq(senderBalanceBefore - (15167 + sendTokens), senderBalanceAfter);
        assertNotEq(treasuryBalanceBefore, treasuryBalanceAfter);
    }

    function test_FullCycleUserOpERC20_MODE_combinedBytePreFund() public depositAndStakeEP mint approvePM {
        uint256 balanceSener = sender.balance;
        assertEq(balanceSener, 0);
        address random = makeAddr("random");

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp.nonce = ENTRY_POINT_V8.getNonce(userOp.sender, 0);
        userOp.initCode = hex"7702";

        address target = address(mockERC20);
        uint256 value = 0;
        bytes memory data = abi.encodeWithSelector(IERC20.transfer.selector, random, sendTokens);

        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(address,uint256,bytes)")), target, value, data);
        userOp.callData = callData;

        userOp.accountGasLimits = _packAccountGasLimits(600_000, 400_000);
        userOp.preVerificationGas = preVerificationGas;
        userOp.gasFees = _packGasFees(80 gwei, 15 gwei);

        userOp.paymasterAndData = _createPaymasterDataMode(userOp, ERC20_MODE, combinedBytePreFund);
        bytes memory paymasterSignature = this._signPaymasterData(ERC20_MODE, userOp, 1);
        userOp.paymasterAndData = abi.encodePacked(userOp.paymasterAndData, paymasterSignature);

        bytes32 userOpHash = ENTRY_POINT_V8.getUserOpHash(userOp);
        userOp.signature = _signUserOp(userOpHash);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        _etch();

        uint256 randomBalanceBefore = IERC20(address(mockERC20)).balanceOf(random);
        uint256 treasuryBalanceBefore = IERC20(address(mockERC20)).balanceOf(treasury);
        uint256 senderBalanceBefore = IERC20(address(mockERC20)).balanceOf(sender);

        vm.prank(owner);
        ENTRY_POINT_V8.handleOps(ops, payable(owner));

        uint256 randomBalanceAfter = IERC20(address(mockERC20)).balanceOf(random);
        uint256 treasuryBalanceAfter = IERC20(address(mockERC20)).balanceOf(treasury);
        uint256 senderBalanceAfter = IERC20(address(mockERC20)).balanceOf(sender);

        assertEq(randomBalanceBefore + sendTokens, randomBalanceAfter);
        assertEq(senderBalanceBefore - (15167 + sendTokens), senderBalanceAfter);
        assertNotEq(treasuryBalanceBefore, treasuryBalanceAfter);
    }

    function test_FullCycleUserOpERC20_MODE_combinedByteAll() public depositAndStakeEP mint approvePM {
        uint256 balanceSener = sender.balance;
        assertEq(balanceSener, 0);
        address random = makeAddr("random");

        PackedUserOperation memory userOp = _getFreshUserOp();
        userOp.nonce = ENTRY_POINT_V8.getNonce(userOp.sender, 0);
        userOp.initCode = hex"7702";

        address target = address(mockERC20);
        uint256 value = 0;
        bytes memory data = abi.encodeWithSelector(IERC20.transfer.selector, random, sendTokens);

        bytes memory callData =
            abi.encodeWithSelector(bytes4(keccak256("execute(address,uint256,bytes)")), target, value, data);
        userOp.callData = callData;

        userOp.accountGasLimits = _packAccountGasLimits(600_000, 400_000);
        userOp.preVerificationGas = preVerificationGas;
        userOp.gasFees = _packGasFees(80 gwei, 15 gwei);

        userOp.paymasterAndData = _createPaymasterDataMode(userOp, ERC20_MODE, combinedByteAll);
        bytes memory paymasterSignature = this._signPaymasterData(ERC20_MODE, userOp, 1);
        userOp.paymasterAndData = abi.encodePacked(userOp.paymasterAndData, paymasterSignature);

        bytes32 userOpHash = ENTRY_POINT_V8.getUserOpHash(userOp);
        userOp.signature = _signUserOp(userOpHash);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        _etch();

        uint256 randomBalanceBefore = IERC20(address(mockERC20)).balanceOf(random);
        uint256 treasuryBalanceBefore = IERC20(address(mockERC20)).balanceOf(treasury);
        uint256 senderBalanceBefore = IERC20(address(mockERC20)).balanceOf(sender);

        vm.prank(owner);
        ENTRY_POINT_V8.handleOps(ops, payable(owner));

        uint256 randomBalanceAfter = IERC20(address(mockERC20)).balanceOf(random);
        uint256 treasuryBalanceAfter = IERC20(address(mockERC20)).balanceOf(treasury);
        uint256 senderBalanceAfter = IERC20(address(mockERC20)).balanceOf(sender);

        assertEq(randomBalanceBefore + sendTokens, randomBalanceAfter);
        assertEq(senderBalanceBefore - (25189 + sendTokens), senderBalanceAfter);
        assertNotEq(treasuryBalanceBefore, treasuryBalanceAfter);
    }
}
