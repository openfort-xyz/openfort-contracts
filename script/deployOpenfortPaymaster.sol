// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {OpenfortPaymaster} from "../contracts/paymaster/OpenfortPaymaster.sol";

contract OpenfortPaymasterDeploy is Script {
    uint256 internal deployPrivKey = vm.deriveKey(vm.envString("MNEMONIC_TESTNET"), 0);
    // uint256 internal deployPrivKey = vm.envUint("PK");
    address internal deployAddress = vm.addr(deployPrivKey);
    IEntryPoint internal entryPoint = IEntryPoint((payable(vm.envAddress("ENTRY_POINT_ADDRESS"))));
    uint256 internal constant UNSTAKEDELAYSEC = 8600;

    function run() public {
        bytes32 versionSalt = vm.envBytes32("VERSION_SALT");
        vm.startBroadcast(deployPrivKey);

        OpenfortPaymaster openfortPaymaster = new OpenfortPaymaster{salt: versionSalt}(entryPoint, deployAddress);

        entryPoint.depositTo{value: 0.5 ether}(address(openfortPaymaster));
        entryPoint.addStake{value: 0.25 ether}(UNSTAKEDELAYSEC);

        vm.stopBroadcast();
    }
}
