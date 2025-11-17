// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {UpgradeableOpenfortAccount} from "../contracts/core/upgradeable/UpgradeableOpenfortAccount.sol";
import {UpgradeableOpenfortFactory} from "../contracts/core/upgradeable/UpgradeableOpenfortFactory.sol";
import {CheckOrDeployEntryPoint} from "script/auxiliary/checkOrDeployEntryPoint.sol";

contract deployUpgradeableAccountsTest is Script, CheckOrDeployEntryPoint {
    address private CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    uint256 internal deployPrivKey = uint256(0xf08d0bfabe9a63f25ca7d98a2da32c4a0fca9fb6932b5f692ca794c5f5731d16);
    address internal deployAddress = vm.addr(deployPrivKey);
    IEntryPoint internal entryPoint;

    uint256 private constant RECOVERY_PERIOD = 2 days;
    uint256 private constant SECURITY_PERIOD = 1.5 days;
    uint256 private constant SECURITY_WINDOW = 0.5 days;
    uint256 private constant LOCK_PERIOD = 5 days;
    uint256 internal guardianPrivKey = uint256(0x647f68aed98872ce0b945196e4d0458acaa5a963cfb84cfc3f49dc64298ddf37);
    address internal guardianAddress = vm.addr(guardianPrivKey);

    event AccountImplementationDeployed(address indexed creator);

    function run()
        public
        returns (UpgradeableOpenfortAccount upgradeableOpenfortAccountImpl, UpgradeableOpenfortFactory openfortFactory)
    {
        bytes32 versionSalt = keccak256("babe");
        entryPoint = checkOrDeployEntryPoint();

        vm.startBroadcast(deployPrivKey);

        // deploy upgradeable account implementation
        vm.expectEmit(true, true, false, true);
        emit AccountImplementationDeployed(CREATE2_DEPLOYER);
        // Create an acccount to serve as implementation
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
