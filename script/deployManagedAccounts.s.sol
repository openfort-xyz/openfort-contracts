// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {ManagedOpenfortAccount} from "../contracts/core/managed/ManagedOpenfortAccount.sol";
import {ManagedOpenfortFactory} from "../contracts/core/managed/ManagedOpenfortFactory.sol";
import {CheckOrDeployEntryPoint} from "script/auxiliary/checkOrDeployEntryPoint.sol";

contract ManagedOpenfortDeploy is Script, CheckOrDeployEntryPoint {
    uint256 internal deployPrivKey = vm.envUint("PK_PAYMASTER_OWNER_TESTNET");
    address internal deployAddress = vm.addr(deployPrivKey);
    IEntryPoint internal entryPoint;

    uint256 private constant RECOVERY_PERIOD = 2 days;
    uint256 private constant SECURITY_PERIOD = 1.5 days;
    uint256 private constant SECURITY_WINDOW = 0.5 days;
    uint256 private constant LOCK_PERIOD = 5 days;
    uint256 internal guardianPrivKey = vm.envUint("PK_GUARDIAN_TESTNET");
    address internal guardianAddress = vm.addr(guardianPrivKey);

    function run()
        public
        returns (ManagedOpenfortAccount managedOpenfortAccountImpl, ManagedOpenfortFactory openfortFactory)
    {
        bytes32 versionSalt = vm.envBytes32("VERSION_SALT");
        entryPoint = checkOrDeployEntryPoint();

        vm.startBroadcast(deployPrivKey);
        // Create an account to serve as implementation
        managedOpenfortAccountImpl = new ManagedOpenfortAccount{salt: versionSalt}();
        // deploy account factory (beacon)
        openfortFactory = new ManagedOpenfortFactory{salt: versionSalt}(
            deployAddress,
            address(entryPoint),
            address(managedOpenfortAccountImpl),
            RECOVERY_PERIOD,
            SECURITY_PERIOD,
            SECURITY_WINDOW,
            LOCK_PERIOD,
            guardianAddress
        );

        vm.stopBroadcast();

        address accountImpl = openfortFactory.implementation();
        console.log("Account implementation: ", accountImpl);

        // Create an managed account wallet and get its address
        address firstAccountAddress = openfortFactory.createAccountWithNonce(deployAddress, "1", true);
        console.log(firstAccountAddress);
        console.log("First Account Address: ", firstAccountAddress);
    }
}
