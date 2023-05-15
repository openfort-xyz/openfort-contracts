// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {Script} from "forge-std/Script.sol";
import {StaticOpenfortAccountFactory, IEntryPoint} from "../contracts/core/static/StaticOpenfortAccountFactory.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";

contract StaticOpenfortAccountFactoryDeploy is Script {
    uint256 deployPrivKey;
    address deployAddress;

    function setUp() public {
        deployPrivKey = vm.deriveKey(vm.envString("MNEMONIC"), 0);
        deployAddress = vm.addr(deployPrivKey);
    }

    function run() public {
        vm.startBroadcast(deployPrivKey);

        StaticOpenfortAccountFactory staticOpenfortAccountFactory = new StaticOpenfortAccountFactory(IEntryPoint(address(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789)));
        staticOpenfortAccountFactory.accountImplementation();
  
        // The first call should create a new account, while the second will just return the corresponding account address
        staticOpenfortAccountFactory.createAccount(deployAddress, bytes(""));
        staticOpenfortAccountFactory.createAccount(deployAddress, bytes(""));

        // Deploy a TestCount
        TestCounter testCounter = new TestCounter();
        testCounter.count();

        vm.stopBroadcast();
    }
}
