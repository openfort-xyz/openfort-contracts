// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {Test, console2 as console} from "lib/forge-std/src/Test.sol";
import {PackedUserOperation} from "@account-abstraction-v8/interfaces/PackedUserOperation.sol";

contract GetSenderTest is Test {
    GetSender gS;

    function setUp() public {
        gS = new GetSender();
    }

    function test_getSener() public {
        PackedUserOperation memory userOp;

        address sender = makeAddr("sender");
        userOp.sender = sender;

        vm.prank(sender);

        address senderGet = gS._getSender(userOp);

        assertEq(sender, senderGet);
    }
}

contract GetSender {
    function _getSender(PackedUserOperation calldata userOp) external pure returns (address) {
        address data;
        //read sender from userOp, which is first userOp member (saves 800 gas...)
        assembly {
            data := calldataload(userOp)
        }
        return address(uint160(data));
    }
}
