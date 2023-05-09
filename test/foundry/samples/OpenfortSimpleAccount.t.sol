// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import {Test, console} from "lib/forge-std/src/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint, UserOperation} from "account-abstraction/core/EntryPoint.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";
import {OpenfortSimpleAccount} from "contracts/samples/OpenfortSimpleAccount.sol";

contract OpenfortSimpleAccountTest is Test {
    using ECDSA for bytes32;

    EntryPoint public entryPoint;
    OpenfortSimpleAccount public openfortSimpleAccount;
    TestCounter public testCounter;

    address payable public bundler;
    address public user1;
    uint256 public user1PrivKey;

    /**
     * @notice Initialize the OpenfortSimpleAccountTest testing contract.
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
        // Simulate the next TX (creation of an OpenfortSimpleAccount) using user1
        vm.prank(user1);
        openfortSimpleAccount = new OpenfortSimpleAccount(entryPoint);
        entryPoint.depositTo{value: 1000000000000000000}(address(openfortSimpleAccount));
    }

    /**
     * Test that the owner (user1) can withdraw.
     * Useful to verify that the deployer/owner can still directly call it.
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
        // Check that the address can be retrieved from the signature values (v,r,s)
        require(addr == ECDSA.recover(hash.toEthSignedMessageHash(), v, r, s), "Invalid signature");
        signature = abi.encodePacked(r, s, v);
        // Check that the address can be retrieved from the signature as it will be received by the user (one string value)
        require(addr == ECDSA.recover(hash.toEthSignedMessageHash(), signature), "Invalid signature");
    }

    /**
     * Send a userOp to the deployed openfortSimpleAccount signed by its
     * deplyer/owner, user1.
     */
    function testOpenfortSimpleAccountCounter() public {
        address openfortSimpleAccountAddress = address(openfortSimpleAccount);
        uint nonce = entryPoint.getNonce(openfortSimpleAccountAddress, 0);
        require(nonce == 0, "Nonce should be 0");
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = UserOperation({
            sender: openfortSimpleAccountAddress, // Contract address that will receive the UserOp
            nonce: nonce,
            initCode: hex"",
            callData: abi.encodeCall(   // Function that the OpenfortSimpleAccount will execute
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
        console.log("The signature is %s", string(ops[0].signature));
        uint256 count = testCounter.counters(openfortSimpleAccountAddress);
        require(count == 0, "Counter is not 0");
        nonce = entryPoint.getNonce(openfortSimpleAccountAddress, 0);
        require(nonce == 0, "Nonce should still be 0");
        entryPoint.handleOps(ops, bundler);
        count = testCounter.counters(openfortSimpleAccountAddress);
        require(count == 1, "Counter has not been updated!");
        nonce = entryPoint.getNonce(openfortSimpleAccountAddress, 0);
        require(nonce == 1, "Nonce should have increased");
    }

    /**
     * Send a userOp containing three calls to the deployed openfortSimpleAccount
     * signed by its deplyer/owner, user1. It uses executeBatch() instead of execute()
     */
    function testOpenfortSimpleAccountCounterBatch() public {
        address openfortSimpleAccountAddress = address(openfortSimpleAccount);
        uint nonce = entryPoint.getNonce(openfortSimpleAccountAddress, 0);
        require(nonce == 0, "Nonce should be 0");

        address[] memory contracts = new address[](5);
        contracts[0] = address(testCounter);
        contracts[1] = address(testCounter);
        contracts[2] = address(testCounter);
        contracts[3] = address(testCounter);
        contracts[4] = address(testCounter);
        
        bytes[] memory functions = new bytes[](5);
        functions[0] = abi.encodeCall(TestCounter.count, ());
        functions[1] = abi.encodeCall(TestCounter.count, ());
        functions[2] = abi.encodeCall(TestCounter.count, ());
        functions[3] = abi.encodeCall(TestCounter.count, ());
        functions[4] = abi.encodeCall(TestCounter.count, ());
        
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = UserOperation({
            sender: openfortSimpleAccountAddress, // Contract address that will receive the UserOp
            nonce: nonce,
            initCode: hex"",
            callData: abi.encodeCall(   // Function that the OpenfortSimpleAccount will execute
                OpenfortSimpleAccount.executeBatch, (contracts, functions)
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

        uint256 count = testCounter.counters(openfortSimpleAccountAddress);
        require(count == 0, "Counter is not 0");
        nonce = entryPoint.getNonce(openfortSimpleAccountAddress, 0);
        require(nonce == 0, "Nonce should still be 0");

        entryPoint.handleOps(ops, bundler);
        
        count = testCounter.counters(openfortSimpleAccountAddress);
        require(count == 5, "Counter has not been updated!");
        nonce = entryPoint.getNonce(openfortSimpleAccountAddress, 0);
        require(nonce == 1, "Nonce should have increased");
    }
}
