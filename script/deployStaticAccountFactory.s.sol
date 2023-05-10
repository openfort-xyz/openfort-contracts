// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {Script} from "forge-std/Script.sol";
import {StaticAccountFactory, IEntryPoint} from "../contracts/core/static/StaticAccountFactory.sol";

contract StaticAccountFactoryDeploy is Script {
    uint256 deployPrivKey;
    address deployAddress;
    function setUp() public {
        deployPrivKey = vm.deriveKey(vm.envString("MNEMONIC"), 0);
        deployAddress = vm.addr(deployPrivKey);
    }

    function run() public {
        vm.startBroadcast(deployPrivKey);

        StaticAccountFactory staticAccountFactory = new StaticAccountFactory(IEntryPoint(address(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789)));
        staticAccountFactory.accountImplementation();
  
        staticAccountFactory.createAccount(deployAddress, bytes(""));

        vm.stopBroadcast();
    }
}
