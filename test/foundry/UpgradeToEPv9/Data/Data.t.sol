// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import {Constants} from "./Constants.sol";
import {Test} from "lib/forge-std/src/Test.sol";
import {IEntryPoint as IEntryPointv6} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {UpgradeableOpenfortAccount} from "contracts/core/upgradeable/UpgradeableOpenfortAccount.sol";
import {UpgradeableOpenfortFactory} from "contracts/core/upgradeable/UpgradeableOpenfortFactory.sol";
import {IEntryPoint as IEntryPointv9} from "lib/account-abstraction-v09/contracts/core/EntryPoint.sol";

abstract contract Data is Test, Constants {
    UpgradeableOpenfortFactory public openfortFactoryV6;
    UpgradeableOpenfortAccount public upgradeableOpenfortAccountImplV6;

    IEntryPointv6 public entryPointV6;
    IEntryPointv9 public entryPointV9;

    address internal _OpenfortAdmin;
    uint256 internal _OpenfortAdminPK;

    address internal _AccountOwner;
    uint256 internal _AccountOwnerPK;

    address internal _Guardian;
    uint256 internal _GuardianPK;

    bytes32 public versionSalt;

    function setUp() public virtual {
        (_OpenfortAdmin, _OpenfortAdminPK) = makeAddrAndKey("_OpenfortAdmin");
        (_AccountOwner, _AccountOwnerPK) = makeAddrAndKey("_AccountOwner");
        (_Guardian, _GuardianPK) = makeAddrAndKey("_Guardian");

        versionSalt = keccak256(abi.encodePacked("SALT_0001"));

    }
}