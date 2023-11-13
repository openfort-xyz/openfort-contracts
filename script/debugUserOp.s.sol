// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import "forge-std/Script.sol";
import {UserOperation, EntryPoint} from "account-abstraction/core/EntryPoint.sol";

contract DebugUserOp is Script {
    function run() external {
        EntryPoint entryPoint = EntryPoint((payable(vm.envAddress("ENTRY_POINT_ADDRESS"))));
        UserOperation memory userOp = UserOperation({
            sender: 0x2804D247B28BF8DF9Dd3Fbc23aDa7d78C972Ec77,
            nonce: 0x0,
            initCode: hex"", // In hex without the 0x prefix
            callData: hex"", // In hex without the 0x prefix
            paymasterAndData: hex"", // In hex without the 0x prefix
            signature: hex"", // In hex without the 0x prefix
            callGasLimit: 0x989680,
            verificationGasLimit: 0x989680,
            preVerificationGas: 0x1,
            maxPriorityFeePerGas: 0x1,
            maxFeePerGas: 0x1
        });
        // UserOperation[] memory ops = new UserOperation[](1);
        // ops[0] = userOp;
        // entryPoint.handleOps(ops, payable(address(0)));

        entryPoint.simulateHandleOp(userOp, address(0), "");
        // simulateHandleOp() will always return the following error:
        //  error ExecutionResult(uint256 preOpGas, uint256 paid, uint48 validAfter, uint48 validUntil, bool targetSuccess, bytes targetResult);
    }
}
