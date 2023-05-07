// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import {Test, console} from "lib/forge-std/src/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint, UserOperation} from "account-abstraction/core/EntryPoint.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";
import {OpenfortSessionKeyAccount} from "contracts/samples/OpenfortSessionKeyAccount.sol";

contract OpenfortSessionKeyAccountTest is Test {
    using ECDSA for bytes32;

    EntryPoint public entryPoint;
    OpenfortSessionKeyAccount public openfortSessionKeyAccount;
    TestCounter public testCounter;

    address public openfort;
    uint256 public openfortPrivKey;
    address payable public bundler;
    address public sessionKey;
    uint256 public sessionKeyPrivKey;
    
    /**
     * @notice Initialize the OpenfortSessionKeyAccountTest testing contract.
     * Scenario:
     * - openfort is the deployer (and owner) of the OpenfortSessionKeyAccount
     * - OpenfortSessionKeyAccount is the smart contract wallet 
     * - testCounter is the counter used to test userOps
     */
    function setUp() public {
        entryPoint = new EntryPoint();
        (openfort, openfortPrivKey) = makeAddrAndKey("openfort");
        bundler = payable(makeAddr("bundler"));
        testCounter = new TestCounter();
        
        // Simulate the next TX (creation of an OpenfortSessionKeyAccount) using openfort
        vm.prank(openfort);
        openfortSessionKeyAccount = new OpenfortSessionKeyAccount(entryPoint);

        entryPoint.depositTo{value: 1000000000000000000}(address(openfortSessionKeyAccount));
    }

    /**
     * Test that the owner (openfort) can withdraw.
     * Useful to verify that the deployer/owner can still directly call it.
     */
    function testwithdrawDepositTo() public {
        vm.prank(openfort);
        openfortSessionKeyAccount.withdrawDepositTo(bundler, 50000);
    }

    /**
     * Test that the default account cannot register a new session key
     */
    function testFailregisterSessionKey() public {
        // Generate a new key pair as session key
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        // Try to register the new session key
        openfortSessionKeyAccount.registerSessionKey(sessionKey, 0, 2**48 - 1);
    }

    /**
     * Test that Openfort can register a new session key
     */
    function testregisterSessionKey() public {
        // Generate a new key pair as session key
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        // Openfort register the new session key
        vm.prank(openfort);
        openfortSessionKeyAccount.registerSessionKey(sessionKey, 0, 2**48 - 1);
    }
}
