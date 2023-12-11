// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {UpgradeableOpenfortAccount} from "../contracts/core/upgradeable/UpgradeableOpenfortAccount.sol";
import {UpgradeableOpenfortFactory} from "../contracts/core/upgradeable/UpgradeableOpenfortFactory.sol";

contract UpgradeableOpenfortDeploy is Script {
    uint256 internal deployPrivKey = vm.envUint("PK_PAYMASTER_OWNER_TESTNET");
    address internal deployAddress = vm.addr(deployPrivKey);
    IEntryPoint internal entryPoint = IEntryPoint((payable(vm.envAddress("ENTRY_POINT_ADDRESS"))));

    uint256 private constant RECOVERY_PERIOD = 2 days;
    uint256 private constant SECURITY_PERIOD = 1.5 days;
    uint256 private constant SECURITY_WINDOW = 0.5 days;
    uint256 private constant LOCK_PERIOD = 5 days;
    address private OPENFORT_GUARDIAN = vm.envAddress("PAYMASTER_OWNER_TESTNET");

    function run()
        public
        returns (UpgradeableOpenfortAccount upgradeableOpenfortAccountImpl, UpgradeableOpenfortFactory openfortFactory)
    {
        bytes32 versionSalt = vm.envBytes32("VERSION_SALT");
        vm.startBroadcast(deployPrivKey);

        // Create an acccount to serve as implementation
        upgradeableOpenfortAccountImpl = new UpgradeableOpenfortAccount{salt: versionSalt}();
        // deploy account factory (beacon)
        openfortFactory = new UpgradeableOpenfortFactory{salt: versionSalt}(
            deployAddress,
            address(entryPoint),
            address(upgradeableOpenfortAccountImpl),
            RECOVERY_PERIOD,
            SECURITY_PERIOD,
            SECURITY_WINDOW,
            LOCK_PERIOD,
            OPENFORT_GUARDIAN
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
