// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {UpgradeableOpenfortAccount} from "contracts/core/upgradeable/UpgradeableOpenfortAccount.sol";
import {UpgradeableOpenfortFactory} from "contracts/core/upgradeable/UpgradeableOpenfortFactory.sol";
import {CheckOrDeployEntryPoint} from "script/auxiliary/checkOrDeployEntryPoint.sol";

contract DeployFactory is Script, CheckOrDeployEntryPoint {
    address private CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    uint256 internal deployPrivKey = uint256(***REMOVED***);
    address internal deployAddress = vm.addr(deployPrivKey);
    IEntryPoint internal entryPoint;

    uint256 private constant RECOVERY_PERIOD = 2 days;
    uint256 private constant SECURITY_PERIOD = 1.5 days;
    uint256 private constant SECURITY_WINDOW = 0.5 days;
    uint256 private constant LOCK_PERIOD = 5 days;
    uint256 internal guardianPrivKey = uint256(***REMOVED***);
    address internal guardianAddress = vm.addr(guardianPrivKey);

    event AccountImplementationDeployed(address indexed creator);

    function run()
        public
        returns (UpgradeableOpenfortAccount upgradeableOpenfortAccountImpl, UpgradeableOpenfortFactory openfortFactory)
    {
        bytes32 versionSalt = keccak256("bebe");
        entryPoint = checkOrDeployEntryPoint();

        vm.startBroadcast(deployPrivKey);

        vm.expectEmit(true, true, false, true);
        emit AccountImplementationDeployed(CREATE2_DEPLOYER);

        upgradeableOpenfortAccountImpl = new UpgradeableOpenfortAccount{salt: versionSalt}();

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

        bytes32 accountNonce = keccak256(abi.encodePacked("account", block.timestamp));
        address accountProxy = openfortFactory.createAccountWithNonce(deployAddress, accountNonce, true);
        console.log("Account Proxy:", accountProxy);
    }
}

/**
 * == Return ==
 * upgradeableOpenfortAccountImpl: contract UpgradeableOpenfortAccount 0x8BE0246CEEF3a2adD7C7b11c3d3b0303F410403d
 * openfortFactory: contract UpgradeableOpenfortFactory 0x3331e1A69Af3B4974a2ee3E1cE77cF656fCF9652
 *
 * == Logs ==
 *   Account implementation:  0x8BE0246CEEF3a2adD7C7b11c3d3b0303F410403d
 *   Account Proxy: 0x4c3db33E23635A448E6C560e6782423D9a2Bc81b
 */