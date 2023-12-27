// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Script} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {OpenfortPaymasterV2} from "../contracts/paymaster/OpenfortPaymasterV2.sol";
import {CheckOrDeployEntryPoint} from "script/aux/checkOrDeployEntryPoint.sol";

contract OpenfortPaymasterV2Deploy is Script, CheckOrDeployEntryPoint {
    uint256 internal deployPrivKey = vm.envUint("PK_PAYMASTER_OWNER_TESTNET");
    address internal deployAddress = vm.addr(deployPrivKey);
    IEntryPoint internal entryPoint;
    uint32 internal constant UNSTAKEDELAYSEC = 8600;

    function run() public returns (OpenfortPaymasterV2 openfortPaymaster) {
        bytes32 versionSalt = vm.envBytes32("VERSION_SALT");
        entryPoint = checkOrDeployEntryPoint();

        vm.startBroadcast(deployPrivKey);

        openfortPaymaster = new OpenfortPaymasterV2{salt: versionSalt}(entryPoint, deployAddress);
        entryPoint.depositTo{value: 1.5 ether}(address(openfortPaymaster));
        openfortPaymaster.addStake{value: 0.015 ether}(UNSTAKEDELAYSEC);

        vm.stopBroadcast();
    }
}
