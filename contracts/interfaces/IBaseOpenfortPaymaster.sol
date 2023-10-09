// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.19;

import {IPaymaster, UserOperation} from "account-abstraction/interfaces/IPaymaster.sol";

interface IBaseOpenfortPaymaster is IPaymaster {
    /**
     * @inheritdoc IPaymaster
     */
    function validatePaymasterUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        external
        returns (bytes memory context, uint256 validationData);

    /**
     * @inheritdoc IPaymaster
     */
    function postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost) external;

    /**
     * Return current paymaster's deposit on the EntryPoint.
     */
    function getDeposit() external view returns (uint256);
}
