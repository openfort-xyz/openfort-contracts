// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {UpgradeableOpenfortAccount} from "../contracts/core/upgradeable/UpgradeableOpenfortAccount.sol";
import {UpgradeableOpenfortFactory} from "../contracts/core/upgradeable/UpgradeableOpenfortFactory.sol";
import {CheckOrDeployEntryPoint} from "script/auxiliary/checkOrDeployEntryPoint.sol";

contract UpgradeableOpenfortDeploy is Script, CheckOrDeployEntryPoint {
    address private CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    uint256 internal deployPrivKey = vm.envUint("PK_PAYMASTER_OWNER_TESTNET");
    address internal deployAddress = vm.addr(deployPrivKey);
    IEntryPoint internal entryPoint;

    uint256 private constant RECOVERY_PERIOD = 2 days;
    uint256 private constant SECURITY_PERIOD = 1.5 days;
    uint256 private constant SECURITY_WINDOW = 0.5 days;
    uint256 private constant LOCK_PERIOD = 5 days;
    uint256 internal guardianPrivKey = vm.envUint("PK_GUARDIAN_TESTNET");
    address internal guardianAddress = vm.addr(guardianPrivKey);

    event AccountImplementationDeployed(address indexed creator);

    function run()
        public
        returns (UpgradeableOpenfortAccount upgradeableOpenfortAccountImpl, UpgradeableOpenfortFactory openfortFactory)
    {
        bytes32 versionSalt = vm.envBytes32("VERSION_SALT");
        entryPoint = checkOrDeployEntryPoint();

        vm.startBroadcast(deployPrivKey);

        // deploy upgradeable account implementation
        vm.expectEmit(true, true, false, true);
        emit AccountImplementationDeployed(CREATE2_DEPLOYER);
        // Create an account to serve as implementation
        upgradeableOpenfortAccountImpl = new UpgradeableOpenfortAccount{salt: versionSalt}();
        // deploy account factory
        openfortFactory = new UpgradeableOpenfortFactory{salt: versionSalt}(
            deployAddress,
            address(entryPoint),
            address(upgradeableOpenfortAccountImpl),
            RECOVERY_PERIOD,
            SECURITY_PERIOD,
            SECURITY_WINDOW,
            LOCK_PERIOD,
            guardianAddress
        );

        vm.stopBroadcast();

        address accountImpl = openfortFactory.implementation();
        console.log("Account implementation: ", accountImpl);

        // Create an upgradeable account wallet and get its address
        address firstAccountAddress = openfortFactory.createAccountWithNonce(deployAddress, "1", true);
        console.log(firstAccountAddress);
        console.log("First Account Address: ", firstAccountAddress);
    }
}
