// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {StaticOpenfortFactory} from "../contracts/core/static/StaticOpenfortFactory.sol";
// import {USDC} from "../contracts/mock/USDC.sol";
import {Rewards} from "../contracts/mock/Rewards.sol";

contract DeployMock is Script {
    uint256 internal deployPrivKey = vm.deriveKey(vm.envString("MNEMONIC"), 0);
    address internal deployAddress = vm.addr(deployPrivKey);
    IEntryPoint internal entryPoint = IEntryPoint((payable(vm.envAddress("ENTRY_POINT_ADDRESS"))));

    function run() public {
        vm.startBroadcast(deployPrivKey);

        // USDC u = new USDC();
        Rewards r = new Rewards();

        vm.stopBroadcast();
    }
}
