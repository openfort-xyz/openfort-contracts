// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {Script} from "forge-std/Script.sol";
import {UpgradeableOpenfortFactory} from "../contracts/core/upgradeable/UpgradeableOpenfortFactory.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";

contract UpgradeableOpenfortDeploy is Script {
    uint256 deployPrivKey;
    address deployAddress;

    function setUp() public {
        deployPrivKey = vm.deriveKey(vm.envString("MNEMONIC"), 0);
        deployAddress = vm.addr(deployPrivKey);
    }

    function run() public {
        vm.startBroadcast(deployPrivKey);

        UpgradeableOpenfortFactory upgradeableOpenfortFactory = new UpgradeableOpenfortFactory((payable(vm.envAddress("ENTRY_POINT_ADDRESS"))));
        upgradeableOpenfortFactory.accountImplementation();
  
        // The first call should create a new account, while the second will just return the corresponding account address
        upgradeableOpenfortFactory.createAccount(deployAddress, bytes(""));
        upgradeableOpenfortFactory.createAccount(deployAddress, bytes(""));

        vm.stopBroadcast();
    }
}
