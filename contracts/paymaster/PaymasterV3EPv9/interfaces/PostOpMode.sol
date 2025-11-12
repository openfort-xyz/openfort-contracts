// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

enum PostOpMode {
    // User op succeeded.
    opSucceeded,
    // User op reverted. Still has to pay for gas.
    opReverted,
    // Only used internally in the EntryPoint (cleanup after postOp reverts). Never calling paymaster with this value
    postOpReverted
}
