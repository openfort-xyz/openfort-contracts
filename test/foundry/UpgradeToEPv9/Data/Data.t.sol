// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {Constants} from "./Constants.sol";
import {Test} from "lib/forge-std/src/Test.sol";
import {IEntryPoint, EntryPoint} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {IUpgradeableOpenfortAccount} from "contracts/interfaces/IUpgradeableOpenfortAccount.sol";
import {UpgradeableOpenfortFactory} from "contracts/core/upgradeable/UpgradeableOpenfortFactory.sol";

abstract contract Data is Test, Constants {
    UpgradeableOpenfortFactory public openfortFactory;
    UpgradeableOpenfortAccount public upgradeableOpenfortAccountImpl;

    IEntryPoint public entryPoint;

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