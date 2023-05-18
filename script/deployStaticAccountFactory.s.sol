// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {Script} from "forge-std/Script.sol";
import {StaticOpenfortFactory} from "../contracts/core/static/StaticOpenfortFactory.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";

contract StaticOpenfortFactoryDeploy is Script {
    uint256 deployPrivKey;
    address deployAddress;

    function setUp() public {
        deployPrivKey = vm.deriveKey(vm.envString("MNEMONIC"), 0);
        deployAddress = vm.addr(deployPrivKey);
    }

    function run() public {
        vm.startBroadcast(deployPrivKey);

        StaticOpenfortFactory staticOpenfortFactory = new StaticOpenfortFactory((payable(vm.envAddress("ENTRY_POINT_ADDRESS"))));
        staticOpenfortFactory.accountImplementation();
  
        // The first call should create a new account, while the second will just return the corresponding account address
        staticOpenfortFactory.createAccount(deployAddress, bytes(""));
        staticOpenfortFactory.createAccount(deployAddress, bytes(""));

        // Deploy a TestCount
        TestCounter testCounter = new TestCounter();
        testCounter.count();

        vm.stopBroadcast();
    }
}
