// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {UpgradeableOpenfortAccount} from "../contracts/core/upgradeable/UpgradeableOpenfortAccount.sol";
import {UpgradeableOpenfortFactory} from "../contracts/core/upgradeable/UpgradeableOpenfortFactory.sol";

contract UpgradeableOpenfortDeploy is Script {
    uint256 internal deployPrivKey = vm.deriveKey(vm.envString("MNEMONIC"), 0);
    address internal deployAddress = vm.addr(deployPrivKey);
    IEntryPoint internal entryPoint = IEntryPoint((payable(vm.envAddress("ENTRY_POINT_ADDRESS"))));

    function run() public {
        bytes32 versionSalt = vm.envBytes32("VERSION_SALT");
        vm.startBroadcast(deployPrivKey);

        UpgradeableOpenfortAccount upgradeableOpenfortAccount = new UpgradeableOpenfortAccount{salt: versionSalt}();

        UpgradeableOpenfortFactory upgradeableOpenfortFactory =
            new UpgradeableOpenfortFactory{salt: versionSalt}(address(entryPoint), address(upgradeableOpenfortAccount));
        (upgradeableOpenfortFactory);
        // address account1 = upgradeableOpenfortFactory.accountImplementation();

        // The first call should create a new account, while the second will just return the corresponding account address
        address account2 = upgradeableOpenfortFactory.createAccountWithNonce(deployAddress, "1");
        // console.log(
        //     "Factory at address %s has created an account at address %s", address(upgradeableOpenfortFactory), account2
        // );

        // assert(account1 != account2);
        // address account3 = upgradeableOpenfortFactory.createAccountWithNonce(deployAddress, 3);
        // console.log(
        //     "Factory at address %s has created an account at address %s", address(upgradeableOpenfortFactory), account3
        // );
        // assert(account2 != account3);
        // address account4 = upgradeableOpenfortFactory.createAccountWithNonce(deployAddress, 4);
        // console.log(
        //     "Factory at address %s has created an account at address %s", address(upgradeableOpenfortFactory), account4
        // );
        // assert(account3 != account4);

        //address account3 = upgradeableOpenfortFactory.createAccount(deployAddress, bytes(""));

        //assert(account1 != account2);
        //assert(account2 == account3);

        //UpgradeableOpenfortAccount newAccount = new UpgradeableOpenfortAccount();

        //UpgradeableOpenfortAccount(payable(account2)).upgradeTo(address(newAccount));

        vm.stopBroadcast();
    }
}
