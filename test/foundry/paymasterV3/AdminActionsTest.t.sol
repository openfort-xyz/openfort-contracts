// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {BasePaymasterTest as Base} from "test/foundry/paymasterV3/BasePaymasterTest.t.sol";
import {IStakeManager} from "lib/account-abstractionV8/contracts/interfaces/IStakeManager.sol";

uint256 constant stakeAmount = 0.1 ether;
uint32 constant unstakeDelay = 8600;

contract AdminActionsTest is Base {
    function test_deposit() public {
        _deposit();
        IStakeManager.DepositInfo memory info = ENTRY_POINT_V8.getDepositInfo(address(PM));
        assertEq(0.1 ether, info.deposit);
    }

    function test_addStake() public {
        _addStake();
        IStakeManager.DepositInfo memory info = ENTRY_POINT_V8.getDepositInfo(address(PM));
        assertEq(uint112(stakeAmount), info.stake);
    }

    function test_unlockStake() public {
        _addStake();
        _unlockStake();
        IStakeManager.DepositInfo memory info = ENTRY_POINT_V8.getDepositInfo(address(PM));
        assertFalse(info.staked);
    }

    function test_withdrawTo() public {
        address random = makeAddr("random");
        _deposit();
        _addStake();
        _unlockStake();

        uint256 balanceBefore = random.balance;

        _warp(uint256(unstakeDelay) + 1);
        vm.prank(owner);
        PM.withdrawTo(payable(random), 0.01 ether);

        uint256 balanceAfter = random.balance;

        IStakeManager.DepositInfo memory info = ENTRY_POINT_V8.getDepositInfo(address(PM));
        assertFalse(info.staked);
        assertEq(balanceBefore + balanceAfter, balanceAfter);
    }

    function test_withdrawStake() public {
        _deposit();
        _addStake();
        _unlockStake();
        uint256 balanceBefore = owner.balance;

        _warp(uint256(unstakeDelay) + 100 days);
        vm.prank(owner);
        PM.withdrawStake(payable(owner));

        uint256 balanceAfter = owner.balance;

        IStakeManager.DepositInfo memory info = ENTRY_POINT_V8.getDepositInfo(address(PM));
        assertFalse(info.staked);
        assertEq(balanceBefore, balanceAfter);
    }

    function test_removeSigner() public {
        vm.prank(owner);
        PM.removeSigner(signers[0]);

        bool isValid = PM.signers(signers[0]);
        assertFalse(isValid);
    }

    function test_addSigner() public {
        address random = makeAddr("random");
        vm.prank(owner);
        PM.addSigner(random);

        bool isValid = PM.signers(random);
        assertTrue(isValid);
    }

    function _deposit() internal {
        vm.prank(owner);
        PM.deposit{value: 0.1 ether}();
    }

    function _addStake() internal {
        vm.prank(owner);
        PM.addStake{value: stakeAmount}(unstakeDelay);
    }

    function _unlockStake() internal {
        vm.prank(owner);
        PM.unlockStake();
    }
}

contract ManagerActionsTest is Base {
    function test_deposit() public {
        _deposit();
        IStakeManager.DepositInfo memory info = ENTRY_POINT_V8.getDepositInfo(address(PM));
        assertEq(0.1 ether, info.deposit);
    }

    function test_addStake() public {
        _addStake();
        IStakeManager.DepositInfo memory info = ENTRY_POINT_V8.getDepositInfo(address(PM));
        assertEq(uint112(stakeAmount), info.stake);
    }

    function test_unlockStake() public {
        _addStake();
        _unlockStake();
        IStakeManager.DepositInfo memory info = ENTRY_POINT_V8.getDepositInfo(address(PM));
        assertFalse(info.staked);
    }

    function test_withdrawTo() public {
        address random = makeAddr("random");
        _deposit();
        _addStake();
        _unlockStake();

        _warp(uint256(unstakeDelay) + 1);
        vm.expectRevert();
        vm.prank(manager);
        PM.withdrawTo(payable(random), 0.01 ether);
    }

    function test_withdrawStake() public {
        _deposit();
        _addStake();
        _unlockStake();

        _warp(uint256(unstakeDelay) + 100 days);
        vm.expectRevert();
        vm.prank(manager);
        PM.withdrawStake(payable(manager));
    }

    function test_removeSigner() public {
        vm.prank(manager);
        PM.removeSigner(signers[0]);

        bool isValid = PM.signers(signers[0]);
        assertFalse(isValid);
    }

    function test_addSigner() public {
        address random = makeAddr("random");
        vm.prank(manager);
        PM.addSigner(random);

        bool isValid = PM.signers(random);
        assertTrue(isValid);
    }

    function _deposit() internal {
        vm.prank(manager);
        PM.deposit{value: 0.1 ether}();
    }

    function _addStake() internal {
        vm.prank(manager);
        PM.addStake{value: stakeAmount}(unstakeDelay);
    }

    function _unlockStake() internal {
        vm.prank(manager);
        PM.unlockStake();
    }
}

contract RevertActionsTest is Base {
    error MultiSigner__SignerNotExist();
    error MultiSigner__SignerAlreadyExist();

    function test_revertSignerAlreadyExist() public {
        vm.expectRevert(MultiSigner__SignerAlreadyExist.selector);
        vm.prank(owner);
        PM.addSigner(signers[0]);
    }

    function test_revertSignerNotExist() public {
        address random = makeAddr("random");

        vm.expectRevert(MultiSigner__SignerNotExist.selector);
        vm.prank(owner);
        PM.removeSigner(random);
    }
}
