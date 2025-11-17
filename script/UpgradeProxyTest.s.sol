// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {UpgradeableOpenfortAccount} from "../contracts/core/upgradeable/UpgradeableOpenfortAccount.sol";
import {UpgradeableOpenfortProxy} from "../contracts/core/upgradeable/UpgradeableOpenfortProxy.sol";

/**
 * @title UpgradeProxyTest
 * @notice Script to upgrade an existing UpgradeableOpenfortAccount proxy to a new implementation
 *         and update its EntryPoint address in a single atomic transaction.
 *
 * DEPLOYMENT ARCHITECTURE (from deployUpgradeableAccountsTest.s.sol):
 * ┌────────────────────────────────────────────────────────────────────┐
 * │ Implementation: 0xF061D03441517d3c4ecE5533219Bd857182e934b        │
 * │ (UpgradeableOpenfortAccount logic contract)                        │
 * └────────────────────────────────────────────────────────────────────┘
 *                                    ▲
 *                                    │ points to
 * ┌────────────────────────────────────────────────────────────────────┐
 * │ Factory: 0x3908A75CB3Bb22F9a728B27Ddaf249a94BEce802              │
 * │ (UpgradeableOpenfortFactory - creates account proxies)             │
 * └────────────────────────────────────────────────────────────────────┘
 *                                    │ creates
 *                                    ▼
 * ┌────────────────────────────────────────────────────────────────────┐
 * │ Account Proxy: 0xAc65E3e36f65A0B98b4CF34d8A630A2a4e718B97        │
 * │ (UpgradeableOpenfortProxy - holds state, delegates to impl)        │
 * │ ★ THIS IS WHAT WE'RE UPGRADING ★                                   │
 * └────────────────────────────────────────────────────────────────────┘
 *
 * This script demonstrates the UUPS upgrade pattern:
 * 1. Deploy new implementation contract
 * 2. Call upgradeToAndCall() on the ACCOUNT PROXY (not factory!)
 * 3. Update EntryPoint as part of the upgrade
 */
contract UpgradeProxyTest is Script {
    // Account proxy address (NOT the factory address)
    // This is the actual UpgradeableOpenfortAccount proxy that was created by the factory
    address private constant PROXY_ADDRESS = 0xAc65E3e36f65A0B98b4CF34d8A630A2a4e718B97;

    // New EntryPoint v0.7 address
    address private constant NEW_ENTRYPOINT = 0x43370900c8de573dB349BEd8DD53b4Ebd3Cce709;

    uint256 internal deployPrivKey = uint256(***REMOVED***);
    address internal deployAddress = vm.addr(deployPrivKey);

    event ImplementationUpgraded(address indexed oldImpl, address indexed newImpl);
    event EntryPointUpdated(address indexed oldEntryPoint, address indexed newEntryPoint);

    function run() public returns (address newImplementation) {
        console.log("=== UUPS Proxy Upgrade Script ===");
        console.log("Proxy Address:", PROXY_ADDRESS);
        console.log("Owner Address:", deployAddress);
        console.log("");

        // Check if the proxy exists on-chain
        uint256 codeSize;
        assembly {
            codeSize := extcodesize(PROXY_ADDRESS)
        }

        if (codeSize == 0) {
            console.log("ERROR: No contract found at proxy address!");
            console.log("");
            console.log("The account proxy does not exist on-chain yet.");
            console.log("You need to deploy it first using one of these options:");
            console.log("");
            console.log("Option 1 - Deploy using the test script:");
            console.log("  forge script script/deployUpgradeableAccountsTest.s.sol \\");
            console.log("    --rpc-url base-sepolia --broadcast --verify");
            console.log("");
            console.log("Option 2 - Deploy AND upgrade in one script:");
            console.log("  forge script script/DeployAndUpgradeTest.s.sol \\");
            console.log("    --rpc-url base-sepolia --broadcast --verify");
            console.log("");
            revert("Account proxy not deployed");
        }

        console.log("Contract found at proxy address");
        console.log("");

        UpgradeableOpenfortProxy proxy = UpgradeableOpenfortProxy(payable(PROXY_ADDRESS));
        UpgradeableOpenfortAccount account = UpgradeableOpenfortAccount(payable(PROXY_ADDRESS));

        address oldImpl = proxy.implementation();
        address oldEntryPoint = address(account.entryPoint());
        address accountOwner = account.owner();

        console.log("--- Current State ---");
        console.log("Current Implementation:", oldImpl);
        console.log("Current EntryPoint:", oldEntryPoint);
        console.log("Account Owner:", accountOwner);
        console.log("");

        require(accountOwner == deployAddress, "Deployer is not the account owner");

        vm.startBroadcast(deployPrivKey);

        console.log("--- Deploying New Implementation ---");
        UpgradeableOpenfortAccount newImpl = new UpgradeableOpenfortAccount();
        newImplementation = address(newImpl);
        console.log("New Implementation deployed at:", newImplementation);
        console.log("");

        bytes memory updateEntryPointCall = abi.encodeWithSignature(
            "updateEntryPoint(address)",
            NEW_ENTRYPOINT
        );

        console.log("--- Upgrading Proxy ---");
        console.log("Calling upgradeToAndCall...");
        account.upgradeToAndCall(newImplementation, updateEntryPointCall);

        vm.stopBroadcast();

        console.log("");
        console.log("--- Verification ---");
        address verifyImpl = proxy.implementation();
        address verifyEntryPoint = address(account.entryPoint());

        console.log("New Implementation:", verifyImpl);
        console.log("New EntryPoint:", verifyEntryPoint);
        console.log("");

        require(verifyImpl == newImplementation, "Implementation upgrade failed");
        require(verifyEntryPoint == NEW_ENTRYPOINT, "EntryPoint update failed");

        console.log("=== Upgrade Successful! ===");
        console.log("");

        emit ImplementationUpgraded(oldImpl, newImplementation);
        emit EntryPointUpdated(oldEntryPoint, NEW_ENTRYPOINT);

        return newImplementation;
    }

    /**
     * @notice Alternative function to upgrade in two separate transactions
     * @dev Use this if upgradeToAndCall fails or if you want more control
     */
    function runSeparateTransactions() public returns (address newImplementation) {
        UpgradeableOpenfortProxy proxy = UpgradeableOpenfortProxy(payable(PROXY_ADDRESS));
        UpgradeableOpenfortAccount account = UpgradeableOpenfortAccount(payable(PROXY_ADDRESS));

        address oldImpl = proxy.implementation();
        console.log("Old Implementation:", oldImpl);

        vm.startBroadcast(deployPrivKey);

        // Deploy new implementation
        UpgradeableOpenfortAccount newImpl = new UpgradeableOpenfortAccount();
        newImplementation = address(newImpl);
        console.log("New Implementation:", newImplementation);

        // Transaction 1: Upgrade to new implementation
        account.upgradeTo(newImplementation);
        console.log("Upgraded to new implementation");

        // Transaction 2: Update EntryPoint
        account.updateEntryPoint(NEW_ENTRYPOINT);
        console.log("Updated EntryPoint to:", NEW_ENTRYPOINT);

        vm.stopBroadcast();

        // Verify both changes
        address verifyImpl = proxy.implementation();
        address verifyEntryPoint = address(account.entryPoint());

        require(verifyImpl == newImplementation, "Implementation upgrade failed");
        require(verifyEntryPoint == NEW_ENTRYPOINT, "EntryPoint update failed");

        console.log("Upgrade completed successfully!");

        return newImplementation;
    }
}
