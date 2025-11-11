// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

import { MockERC20 } from "test/foundry/paymasterV3EPv9/mocks/MockERC20.sol";
import { EntryPoint } from "lib/account-abstraction-v09/contracts/core/EntryPoint.sol";
import { PaymasterHelper } from "test/foundry/paymasterV3EPv9/helpers/PaymasterHelper.t.sol";
import { Simple7702Account } from "test/foundry/paymasterV3EPv9/mocks/Simple7702Account.sol";
import { IEntryPoint } from "lib/account-abstraction-v09/contracts/interfaces/IEntryPoint.sol";
import { OPFPaymasterV3 as Paymaster } from "contracts/paymaster/PaymasterV3EPv9/OPFPaymasterV3.sol";

contract Deploy is PaymasterHelper {
    function setUp() public virtual {
        forkId = vm.createFork(SEPOLIA_RPC_URL);
        vm.selectFork(forkId);

        _setPaymasterData();
        _setData();

        EntryPoint deployedEntryPoint = new EntryPoint();
        vm.etch(entryPointV9, address(deployedEntryPoint).code);
        vm.label(entryPointV9, "EntryPointV9");
        ENTRY_POINT_V9 = IEntryPoint(payable(entryPointV9));

        mockERC20 = new MockERC20();
        account = new Simple7702Account();
        implementation = account;
        PM = new Paymaster(owner, manager, signers);

        _etch();
        _deal();
        _depositToEP();
    }

    function test_AfterConstructor() public {
        address getOwner = PM.OWNER();
        address getManager = PM.MANAGER();
        address[] memory getSigners = PM.getSigners();

        assertEq(getOwner, owner);
        assertEq(getManager, manager);

        for (uint256 i = 0; i < getSigners.length;) {
            assertEq(getSigners[i], signers[i]);
            unchecked {
                i++;
            }
        }
    }

    function _deal() internal {
        deal(owner, 10 ether);
        deal(owner7702, 10 ether);
    }

    function _mintAndApprove(address _owner, uint256 _value) internal {
        vm.startPrank(owner7702);
        mockERC20.mint(_owner, _value);
        mockERC20.approve(address(PM), type(uint256).max);
        vm.stopPrank();
    }
}
