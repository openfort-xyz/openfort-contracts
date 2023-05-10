// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {Script} from "forge-std/Script.sol";
import {OpenfortSimpleAccount, IEntryPoint} from "../contracts/samples/OpenfortSimpleAccount.sol";

contract OpenfortSimpleAccountDeploy is Script {
    uint256 privKey;
    function setUp() public {
        privKey = vm.deriveKey(vm.envString("MNEMONIC"), 0);
    }

    function run() public {
        vm.startBroadcast(privKey);

        OpenfortSimpleAccount openfortSimpleAccount = new OpenfortSimpleAccount(IEntryPoint(address(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789)));
        openfortSimpleAccount.entryPoint();

        vm.stopBroadcast();
    }
}
