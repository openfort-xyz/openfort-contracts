// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Script} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {ManagedOpenfortAccount} from "../contracts/core/managed/ManagedOpenfortAccount.sol";
import {ManagedOpenfortFactory} from "../contracts/core/managed/ManagedOpenfortFactory.sol";
// import {MockedV2ManagedOpenfortAccount} from "../contracts/mock/MockedV2ManagedOpenfortAccount.sol";

contract ManagedOpenfortDeploy is Script {
    uint256 internal deployPrivKey = vm.deriveKey(vm.envString("MNEMONIC"), 0);
    address internal deployAddress = vm.addr(deployPrivKey);
    IEntryPoint internal entryPoint = IEntryPoint((payable(vm.envAddress("ENTRY_POINT_ADDRESS"))));

    function run() public {
        bytes32 versionSalt = vm.envBytes32("VERSION_SALT");
        vm.startBroadcast(deployPrivKey);

        // Create an acccount to server as implementation
        ManagedOpenfortAccount managedOpenfortAccount = new ManagedOpenfortAccount{salt: versionSalt}();

        // OpenfortBeacon openfortBeacon = new OpenfortBeacon(address(managedOpenfortAccount)); // not needed anymore

        // Create a factory to deploy cloned accounts
        ManagedOpenfortFactory managedOpenfortFactory =
        new ManagedOpenfortFactory{salt: versionSalt}(deployAddress, address(entryPoint), address(managedOpenfortAccount));
        (managedOpenfortFactory);
        // address account1 = managedOpenfortFactory.accountImplementation();

        // The first call should create a new account, while the second will just return the corresponding account address
        // address account2 = managedOpenfortFactory.createAccountWithNonce(deployAddress, "1");
        // console.log(
        //     "Factory at address %s has created an account at address %s", address(managedOpenfortFactory), account2
        // );

        // MockedV2ManagedOpenfortAccount mockedOpenfortAccount = new MockedV2ManagedOpenfortAccount{salt: versionSalt}();
        // (mockedOpenfortAccount);

        // assert(account1 != account2);
        // address account3 = managedOpenfortFactory.createAccountWithNonce(deployAddress, 3);
        // console.log(
        //     "Factory at address %s has created an account at address %s", address(managedOpenfortFactory), account3
        // );
        // assert(account2 != account3);
        // address account4 = managedOpenfortFactory.createAccountWithNonce(deployAddress, 4);
        // console.log(
        //     "Factory at address %s has created an account at address %s", address(managedOpenfortFactory), account4
        // );
        // assert(account3 != account4);

        vm.stopBroadcast();
    }
}
