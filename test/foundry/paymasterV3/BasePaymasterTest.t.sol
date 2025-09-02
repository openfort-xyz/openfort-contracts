// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {PaymasterDataTest as Data} from "test/foundry/paymasterV3/PaymasterDataTest.t.sol";
import {OPFPaymasterV3 as Paymaster} from "contracts/paymaster/PaymasterV3/OPFPaymasterV3.sol";

contract BasePaymasterTest is Data {
    Paymaster PM;

    function setUp() public virtual override {
        super.setUp();
        PM = new Paymaster(owner, manager, signers);
        _deal();
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
        deal(owner, 5e18);
        deal(manager, 3e18);

        for (uint256 i = 0; i < signers.length;) {
            deal(signers[i], 1e18);
            unchecked {
                i++;
            }
        }
    }
}
