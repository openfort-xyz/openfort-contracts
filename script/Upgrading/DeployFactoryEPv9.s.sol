// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {UpgradeableOpenfortAccount} from "contracts/core/upgradeable/UpgradeableOpenfortAccount.sol";
import {UpgradeableOpenfortFactory} from "contracts/core/upgradeable/UpgradeableOpenfortFactory.sol";
import {CheckOrDeployEntryPoint} from "script/auxiliary/checkOrDeployEntryPoint.sol";

contract DeployFactoryEPv9 is Script, CheckOrDeployEntryPoint {
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
        bytes32 versionSalt = keccak256("bebe0001");
        entryPoint = IEntryPoint(payable(0x43370900c8de573dB349BEd8DD53b4Ebd3Cce709));

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
 * upgradeableOpenfortAccountImpl: contract UpgradeableOpenfortAccount 0x21E34D952aD526F18C50843e5dA4B8AeE5E21A95
 * openfortFactory: contract UpgradeableOpenfortFactory 0xCf275C0FE29a16078D78EDd312AA0c93279F2973
 *
 * == Logs ==
 *   Account implementation:  0x21E34D952aD526F18C50843e5dA4B8AeE5E21A95
 *   Account Proxy: 0x77D56D2A8FB389604f48ed17631B788631530d25
 */
