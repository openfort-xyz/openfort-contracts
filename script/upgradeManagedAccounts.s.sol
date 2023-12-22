// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {ManagedOpenfortAccount} from "../contracts/core/managed/ManagedOpenfortAccount.sol";
import {ManagedOpenfortFactory} from "../contracts/core/managed/ManagedOpenfortFactory.sol";
import {CheckOrDeployEntryPoint} from "script/aux/checkOrDeployEntryPoint.sol";

contract ManagedOpenfortUpgrade is Script, CheckOrDeployEntryPoint {
    uint256 internal deployPrivKey = vm.envUint("PK_PAYMASTER_OWNER_TESTNET");
    address internal deployAddress = vm.addr(deployPrivKey);

    address internal factoryAddress = 0x44A7d7B291834442EE3703bD8bB7f91eD6F2577E;
    address internal oldImplementation = 0x36604309934A2Fc92C3445Cf4566b23b5b4BbAad;

    function run()
        public
        returns (ManagedOpenfortAccount managedOpenfortAccountImpl, ManagedOpenfortFactory openfortFactory)
    {
        bytes32 versionSalt = vm.envBytes32("VERSION_SALT");
        openfortFactory = ManagedOpenfortFactory(factoryAddress);

        assert(openfortFactory.implementation() == oldImplementation);
        address accountImpl = openfortFactory.implementation();
        console.log("Old account implementation: ", accountImpl);

        address exampleAccountAddress = openfortFactory.createAccountWithNonce(deployAddress, "1", true);
        console.log("Example account address: ", exampleAccountAddress);

        vm.startBroadcast(deployPrivKey);
        // Create an acccount to serve as new implementation
        managedOpenfortAccountImpl = new ManagedOpenfortAccount{salt: versionSalt}();

        // Update the account implementation
        openfortFactory.upgradeTo(address(managedOpenfortAccountImpl));
        assert(openfortFactory.implementation() == address(managedOpenfortAccountImpl));

        vm.stopBroadcast();

        accountImpl = openfortFactory.implementation();
        console.log("New account implementation: ", accountImpl);

        // Create a managed account and get its address
        address exampleAccountAddress2 = openfortFactory.createAccountWithNonce(deployAddress, "1", true);
        console.log("Example account address 2: ", exampleAccountAddress2);

        assert(exampleAccountAddress == exampleAccountAddress2);
    }
}
