// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {ManagedOpenfortAccount} from "../contracts/core/managed/ManagedOpenfortAccount.sol";
import {ManagedOpenfortFactory} from "../contracts/core/managed/ManagedOpenfortFactory.sol";

contract ManagedOpenfortDeploy is Script {
    uint256 internal deployPrivKey = vm.envUint("PK_PAYMASTER_OWNER_MAINNET");
    address internal deployAddress = vm.addr(deployPrivKey);
    IEntryPoint internal entryPoint = IEntryPoint((payable(vm.envAddress("ENTRY_POINT_ADDRESS"))));

    uint256 private constant RECOVERY_PERIOD = 2 days;
    uint256 private constant SECURITY_PERIOD = 1.5 days;
    uint256 private constant SECURITY_WINDOW = 0.5 days;
    uint256 private constant LOCK_PERIOD = 5 days;
    address private OPENFORT_GUARDIAN = vm.envAddress("PAYMASTER_OWNER_MAINNET");
    address[] initialGuardians;

    function run() public {
        bytes32 versionSalt = vm.envBytes32("VERSION_SALT");
        vm.startBroadcast(deployPrivKey);
        initialGuardians = [OPENFORT_GUARDIAN];

        // Create an acccount to serve as implementation
        ManagedOpenfortAccount managedOpenfortAccountImpl = new ManagedOpenfortAccount{salt: versionSalt}();
        // deploy account factory (beacon)
        ManagedOpenfortFactory openfortFactory = new ManagedOpenfortFactory{salt: versionSalt}(
            deployAddress,
            address(entryPoint),
            address(managedOpenfortAccountImpl),
            RECOVERY_PERIOD,
            SECURITY_PERIOD,
            SECURITY_WINDOW,
            LOCK_PERIOD
        );

        address accountImpl = openfortFactory.implementation();
        console.log("Account implementation: ", accountImpl);

        // Create an managed account wallet and get its address
        address firstAccountAddress = openfortFactory.createAccountWithNonce(deployAddress, "1", initialGuardians);
        console.log(firstAccountAddress);
        console.log("First Account Address: ", firstAccountAddress);

        vm.stopBroadcast();
    }
}
