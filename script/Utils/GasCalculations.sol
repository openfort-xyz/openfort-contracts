// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.17;

import {UserOperation, UserOperationLib} from "lib/account-abstraction/contracts/interfaces/UserOperation.sol";

using UserOperationLib for UserOperation;

struct DefaultGasOverheads {
    uint256 fixedCost;
}

function calcPreVerificationGas(UserOperation calldata userOp) pure {
    userOp.pack();
}
