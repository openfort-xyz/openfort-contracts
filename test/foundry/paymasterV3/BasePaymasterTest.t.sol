// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {console2 as console} from "lib/forge-std/src/test.sol";
import {PaymasterDataTest as Data} from "test/foundry/paymasterV3/PaymasterDataTest.t.sol";
import {OPFPaymasterV3 as Paymaster} from "contracts/paymaster/PaymasterV3/OPFPaymasterV3.sol";
import {PackedUserOperation} from "@account-abstraction-v8/interfaces/PackedUserOperation.sol";

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

    function _warp(uint256 _time) internal {
        vm.warp(block.timestamp + _time);
    }

    function _getHash(PackedUserOperation calldata _userOp, uint256 paymasterDataLength)
        internal
        view
        returns (bytes32)
    {
        bytes32 userOpHash = keccak256(
            abi.encode(
                _getSender(_userOp),
                _userOp.nonce,
                _userOp.accountGasLimits,
                _userOp.preVerificationGas,
                _userOp.gasFees,
                keccak256(_userOp.initCode),
                keccak256(_userOp.callData),
                keccak256(_userOp.paymasterAndData[:PAYMASTER_DATA_OFFSET + paymasterDataLength])
            )
        );

        return keccak256(abi.encode(userOpHash, block.chainid));
    }

    function _getSender(PackedUserOperation calldata userOp) internal pure returns (address) {
        address data;
        //read sender from userOp, which is first userOp member (saves 800 gas...)
        assembly {
            data := calldataload(userOp)
        }
        return address(uint160(data));
    }
}
