// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {Script} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {OpenfortPaymasterV2} from "../contracts/paymaster/OpenfortPaymasterV2.sol";

contract OpenfortPaymasterV2Deploy is Script {
    // uint256 internal deployPrivKey = vm.deriveKey(vm.envString("MNEMONIC_PAYMASTER_OWNER_TESTNET"), 0);
    uint256 internal deployPrivKey = vm.envUint("PK_PAYMASTER_OWNER_MAINNET");
    address internal deployAddress = vm.addr(deployPrivKey);
    IEntryPoint internal entryPoint = IEntryPoint((payable(vm.envAddress("ENTRY_POINT_ADDRESS"))));
    uint32 internal constant UNSTAKEDELAYSEC = 8600;

    function run() public {
        bytes32 versionSalt = vm.envBytes32("VERSION_SALT");
        vm.startBroadcast(deployPrivKey);

        OpenfortPaymasterV2 openfortPaymaster = new OpenfortPaymasterV2{salt: versionSalt}(entryPoint, deployAddress);

        entryPoint.depositTo{value: 0.2 ether}(address(openfortPaymaster));
        openfortPaymaster.addStake{value: 0.1 ether}(UNSTAKEDELAYSEC);

        vm.stopBroadcast();
    }
}
