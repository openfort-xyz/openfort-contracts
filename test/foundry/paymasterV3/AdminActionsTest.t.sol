// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {BasePaymasterTest as Base} from "test/foundry/paymasterV3/BasePaymasterTest.t.sol";

contract AdminActionsTest is Base {
    uint256 stakeAmount = 0.1 ether;
    uint32 unstakeDelay = 8600;

    function test_addStak() public {
        _addStake();
    }

    function test_unlockStake() public {
        _addStake();

        vm.prank(owner);
        PM.unlockStake();
    }

    function _addStake() internal {
        vm.prank(owner);
        PM.addStake{value: stakeAmount}(unstakeDelay);
    }
}
