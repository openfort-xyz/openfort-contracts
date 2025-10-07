// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {console2 as console} from "lib/forge-std/src/test.sol";
import {MockERC20} from "test/foundry/paymasterV3/mocks/MockERC20.sol";
import {Simple7702Account} from "test/foundry/paymasterV3/mocks/Simple7702Account.sol";
import {PaymasterDataTest as Data} from "test/foundry/paymasterV3/PaymasterDataTest.t.sol";
import {OPFPaymasterV3 as Paymaster} from "contracts/paymaster/PaymasterV3/OPFPaymasterV3.sol";
import {PackedUserOperation} from "@account-abstraction-v8/interfaces/PackedUserOperation.sol";

contract BasePaymasterTest is Data {
    Paymaster PM;
    MockERC20 mockERC20;
    Simple7702Account account;
    Simple7702Account implementation;

    function setUp() public virtual override {
        super.setUp();
        PM = new Paymaster(owner, manager, signers);
        mockERC20 = new MockERC20();

        account = new Simple7702Account();
        implementation = account;
        _etch();

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

    function _mint(address _addr, uint256 _amount) internal {
        vm.prank(owner);
        mockERC20.mint(_addr, _amount);
    }

    function _packAccountGasLimits(uint256 callGasLimit, uint256 verificationGasLimit)
        internal
        pure
        returns (bytes32)
    {
        return bytes32((callGasLimit << 128) | verificationGasLimit);
    }

    function _packGasFees(uint256 maxFeePerGas, uint256 maxPriorityFeePerGas) internal pure returns (bytes32) {
        return bytes32((maxFeePerGas << 128) | maxPriorityFeePerGas);
    }

    function _etch() internal {
        vm.etch(sender, abi.encodePacked(bytes3(0xef0100), address(implementation)));
        account = Simple7702Account(payable(sender));
    }
}
