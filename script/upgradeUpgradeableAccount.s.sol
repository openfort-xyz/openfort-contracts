// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {UpgradeableOpenfortAccount} from "../contracts/core/upgradeable/UpgradeableOpenfortAccount.sol";
import {UpgradeableOpenfortProxy} from "../contracts/core/upgradeable/UpgradeableOpenfortProxy.sol";
import {CheckOrDeployEntryPoint} from "script/aux/checkOrDeployEntryPoint.sol";

contract UpgradeableOpenfortUpgrade is Script, CheckOrDeployEntryPoint {
    uint256 internal deployPrivKey = vm.envUint("PK_PAYMASTER_OWNER_TESTNET");
    address internal deployAddress = vm.addr(deployPrivKey);
    IEntryPoint internal entryPoint;

    address internal accountAddress = address(0);
    address internal newImplementation = address(0);

    event AccountImplementationDeployed(address indexed creator);

    function run() public {
        UpgradeableOpenfortProxy proxy = UpgradeableOpenfortProxy(payable(accountAddress));
        UpgradeableOpenfortAccount account = UpgradeableOpenfortAccount(payable(accountAddress));

        address accountImpl = proxy.implementation();
        console.log("Old account implementation: ", accountImpl);

        vm.startBroadcast(deployPrivKey);

        // Update the account implementation
        account.upgradeTo(newImplementation);

        vm.stopBroadcast();

        accountImpl = proxy.implementation();
        console.log("New account implementation: ", accountImpl);
    }
}
