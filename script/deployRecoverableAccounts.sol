// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {RecoverableOpenfortAccount} from "../contracts/core/recoverable/RecoverableOpenfortAccount.sol";
import {RecoverableOpenfortFactory} from "../contracts/core/recoverable/RecoverableOpenfortFactory.sol";

contract RecoverableOpenfortDeploy is Script {
    uint256 internal deployPrivKey = vm.deriveKey(vm.envString("MNEMONIC"), 0);
    // uint256 internal deployPrivKey = vm.envUint("PK");
    address internal deployAddress = vm.addr(deployPrivKey);
    IEntryPoint internal entryPoint = IEntryPoint((payable(vm.envAddress("ENTRY_POINT_ADDRESS"))));

    uint256 private constant RECOVERY_PERIOD = 2 days;
    uint256 private constant SECURITY_PERIOD = 1.5 days;
    uint256 private constant SECURITY_WINDOW = 0.5 days;
    uint256 private constant LOCK_PERIOD = 5 days;
    address private OPENFORT_GUARDIAN = vm.envAddress("PAYMASTER_OWNER_TESTNET");

    function run() public {
        bytes32 versionSalt = vm.envBytes32("VERSION_SALT");
        vm.startBroadcast(deployPrivKey);

        RecoverableOpenfortAccount recoverableOpenfortAccountImpl = new RecoverableOpenfortAccount{salt: versionSalt}();

        RecoverableOpenfortFactory recoverableOpenfortFactory =
        new RecoverableOpenfortFactory{salt: versionSalt}(address(entryPoint), address(recoverableOpenfortAccountImpl), RECOVERY_PERIOD, SECURITY_PERIOD, SECURITY_WINDOW, LOCK_PERIOD, OPENFORT_GUARDIAN);
        // (upgradeableOpenfortFactory);
        // address account1 = upgradeableOpenfortFactory.accountImplementation();
        // The first call should create a new account, while the second will just return the corresponding account address
        address account2 = recoverableOpenfortFactory.createAccountWithNonce(deployAddress, "1");
        console.log(
            "Factory at address %s has created an account at address %s", address(recoverableOpenfortFactory), account2
        );

        vm.stopBroadcast();
    }
}
