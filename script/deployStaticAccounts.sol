// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {Script, console} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {StaticOpenfortFactory} from "../contracts/core/static/StaticOpenfortFactory.sol";

contract StaticOpenfortDeploy is Script {
    uint256 internal deployPrivKey = vm.deriveKey(vm.envString("MNEMONIC"), 0);
    address internal deployAddress = makeAddr(vm.envString("MNEMONIC"));
    IEntryPoint internal entryPoint = IEntryPoint((payable(vm.envAddress("ENTRY_POINT_ADDRESS"))));

    function setUp() public {}

    function run() public {
        vm.startBroadcast(deployPrivKey);

        StaticOpenfortFactory staticOpenfortFactory = new StaticOpenfortFactory(address(entryPoint));
        staticOpenfortFactory.accountImplementation();

        // The first call should create a new account, while the second will just return the corresponding account address
        address account2 = staticOpenfortFactory.createAccount(deployAddress, bytes(""));
        console.log(
            "Factory at address %s has created an account at address %s", address(staticOpenfortFactory), account2
        );
        // staticOpenfortFactory.createAccount(deployAddress, bytes(""));

        vm.stopBroadcast();
    }
}
