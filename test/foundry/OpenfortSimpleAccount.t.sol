// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import {Test} from "lib/forge-std/src/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "account-abstraction/core/EntryPoint.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";
import {OpenfortSimpleAccount} from "contracts/OpenfortSimpleAccount.sol";

contract OpenfortSimpleAccountTest is Test {
    using ECDSA for bytes32;

    EntryPoint public entryPoint;
    OpenfortSimpleAccount public openfortSimpleAccount;
    TestCounter public testCounter;

    address payable public bundler;
    address public user1;
    uint256 public user1PrivKey;

    /**
     * @notice Initialize the OpenfortSimpleAccountTest testing contract
     * Scenario:
     * - user1 is the deployer (and owner) of the OpenfortSimpleAccount
     * - openfortSimpleAccount is the smart contract wallet 
     * - testCounter is the counter used to test userOps
     */
    function setUp() public {
        entryPoint = new EntryPoint();
        (user1, user1PrivKey) = makeAddrAndKey("user1");
        bundler = payable(makeAddr("bundler"));
        testCounter = new TestCounter();
        vm.prank(user1);
        openfortSimpleAccount = new OpenfortSimpleAccount(entryPoint);
        entryPoint.depositTo{value: 1000000000000000000}(address(openfortSimpleAccount));
    }

    /**
     * Test that the owner (user1) can withdraw
     */
    function testwithdrawDepositTo() public {
        vm.prank(user1);
        openfortSimpleAccount.withdrawDepositTo(bundler, 50000);
    }

    /**
     * Auxiliary function to sign user ops
     */
    function signUserOp(UserOperation memory op, address addr, uint256 key)
        public
        view
        returns (bytes memory signature)
    {
        bytes32 hash = entryPoint.getUserOpHash(op);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, hash.toEthSignedMessageHash());
        require(addr == ECDSA.recover(hash.toEthSignedMessageHash(), v, r, s), "Invalid signature");
        signature = abi.encodePacked(r, s, v);
        require(addr == ECDSA.recover(hash.toEthSignedMessageHash(), signature), "Invalid signature");
    }

    function testOpenfortSimpleAccountCounter() public {
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = UserOperation({
            sender: payable(openfortSimpleAccount), //
            nonce: 0,
            initCode: hex"",
            callData: abi.encodeCall(
                OpenfortSimpleAccount.execute, (address(testCounter), 0, abi.encodeCall(TestCounter.count, ()))
                ),
            callGasLimit: 100000,
            verificationGasLimit: 200000,
            preVerificationGas: 200000,
            maxFeePerGas: 100000,
            maxPriorityFeePerGas: 100000,
            paymasterAndData: hex"",
            signature: hex""
        });
        ops[0].signature = signUserOp(ops[0], user1, user1PrivKey);
        address openfortSimpleAccountAddress = address(openfortSimpleAccount);
        uint256 count = testCounter.counters(openfortSimpleAccountAddress);
        require(count == 0, "The count for openfortSimpleAccount is not 0!");
        entryPoint.handleOps(ops, bundler);
        count = testCounter.counters(openfortSimpleAccountAddress);
        require(count == 1, "The count for openfortSimpleAccount has not been updated!");
    }
}
