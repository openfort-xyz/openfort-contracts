// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {Script, console} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {UpgradeableOpenfortFactory} from "../contracts/core/upgradeable/UpgradeableOpenfortFactory.sol";

contract UpgradeableOpenfortDeploy is Script {
    uint256 internal deployPrivKey = vm.deriveKey(vm.envString("MNEMONIC"), 0);
    address internal deployAddress = vm.addr(deployPrivKey);
    IEntryPoint internal entryPoint = IEntryPoint((payable(vm.envAddress("ENTRY_POINT_ADDRESS"))));

    function run() public {
        vm.startBroadcast(deployPrivKey);

        UpgradeableOpenfortFactory upgradeableOpenfortFactory = new UpgradeableOpenfortFactory(address(entryPoint));
        //address account1 = upgradeableOpenfortFactory.accountImplementation();

        // The first call should create a new account, while the second will just return the corresponding account address
        address account2 = upgradeableOpenfortFactory.createAccount(deployAddress, bytes(""));
        console.log(
            "Factory at address %s has created an account at address %s", address(upgradeableOpenfortFactory), account2
        );
        //address account3 = upgradeableOpenfortFactory.createAccount(deployAddress, bytes(""));

        //assert(account1 != account2);
        //assert(account2 == account3);

        //UpgradeableOpenfortAccount newAccount = new UpgradeableOpenfortAccount();

        //UpgradeableOpenfortAccount(payable(account2)).upgradeTo(address(newAccount));

        vm.stopBroadcast();
    }
}
