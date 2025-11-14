// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import {UserOperation as UserOperation} from "lib/account-abstraction/contracts/interfaces/UserOperation.sol";
import {PackedUserOperation as PackedUserOperation} from "lib/account-abstraction-v09/contracts/interfaces/PackedUserOperation.sol";

abstract contract AAHelper {
    enum EP_Version {
        V6,
        V9
    }

    function _getFreshUserOp(address _owner) internal pure returns (UserOperation memory userOpV6, PackedUserOperation memory userOpV9) {
        userOpV6 = UserOperation({
            sender: _owner,
            nonce: 0,
            initCode: hex"",
            callData: hex"",
            callGasLimit: 0,
            verificationGasLimit: 0,
            preVerificationGas: 0,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: hex"",
            signature: hex""
        });
        userOpV9 = PackedUserOperation({
            sender: _owner,
            nonce: 0,
            initCode: hex"",
            callData: hex"",
            accountGasLimits: hex"",
            preVerificationGas: 0,
            gasFees: hex"",
            paymasterAndData: hex"",
            signature: hex""
        });
    }
}