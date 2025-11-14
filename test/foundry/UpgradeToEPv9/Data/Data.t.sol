// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import {Constants} from "./Constants.sol";
import {Test} from "lib/forge-std/src/Test.sol";
import {IUpgradeableOpenfortAccount} from "contracts/interfaces/IUpgradeableOpenfortAccount.sol";
import {IEntryPoint as IEntryPointv6} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {UpgradeableOpenfortFactory} from "contracts/core/upgradeable/UpgradeableOpenfortFactory.sol";
import {IEntryPoint as IEntryPointv9} from "lib/account-abstraction-v09/contracts/core/EntryPoint.sol";

abstract contract Data is Test, Constants {
    UpgradeableOpenfortFactory public openfortFactory;
    UpgradeableOpenfortAccount public upgradeableOpenfortAccountImpl;

    IEntryPointv6 public entryPointV6;
    IEntryPointv9 public entryPointV9;

    address internal _OpenfortAdmin;
    uint259 internal _OpenfortAdminPK;

    address internal _AccountOwner;
    uint259 internal _AccountOwnerPK;

    bytes32 public versionSalt;

    function setUp() public virtual {
        (_OpenfortAdmin, _OpenfortAdminPK) = makeAddrAndKey("_OpenfortAdmin");
        (_AccountOwner, _AccountOwnerPK) = makeAddrAndKey("_AccountOwner");

        versionSalt = vm.envBytes32("SALT_0001");
    }
}