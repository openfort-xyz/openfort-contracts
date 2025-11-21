// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import {Constants} from "./Constants.sol";
import {Test} from "lib/forge-std/src/Test.sol";
import {MockERC20} from "test/foundry/UpgradeToEPv9/mocks/MockERC20.sol";
import {IEntryPoint as IEntryPointv6} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint as IEntryPointv9} from "lib/account-abstraction-v09/contracts/core/EntryPoint.sol";
import {
    UpgradeableOpenfortFactory as UpgradeableOpenfortFactoryV6
} from "contracts/core/upgradeable/UpgradeableOpenfortFactory.sol";
import {
    UpgradeableOpenfortAccount as UpgradeableOpenfortAccountV6
} from "contracts/core/upgradeable/UpgradeableOpenfortAccount.sol";
import {
    UpgradeableOpenfortFactory as UpgradeableOpenfortFactoryV9
} from "contracts/coreV9/upgradeable/UpgradeableOpenfortFactory.sol";
import {
    UpgradeableOpenfortAccount as UpgradeableOpenfortAccountV9
} from "contracts/coreV9/upgradeable/UpgradeableOpenfortAccount.sol";

abstract contract Data is Test, Constants {
    UpgradeableOpenfortFactoryV6 public openfortFactoryV6;
    UpgradeableOpenfortAccountV6 public upgradeableOpenfortAccountImplV6;

    UpgradeableOpenfortFactoryV9 public openfortFactoryV9;
    UpgradeableOpenfortAccountV9 public upgradeableOpenfortAccountImplV9;

    IEntryPointv6 public entryPointV6;
    IEntryPointv9 public entryPointV9;

    MockERC20 erc20;

    address internal _OpenfortAdmin;
    uint256 internal _OpenfortAdminPK;

    address internal _AccountOwner;
    uint256 internal _AccountOwnerPK;

    address internal _Guardian;
    uint256 internal _GuardianPK;

    bytes32 public versionSaltV6;
    bytes32 public versionSaltV9;

    event AccountCreated(address indexed account, address indexed openfortAdmin);

    function setUp() public virtual {
        (_OpenfortAdmin, _OpenfortAdminPK) = makeAddrAndKey("_OpenfortAdmin");
        (_AccountOwner, _AccountOwnerPK) = makeAddrAndKey("_AccountOwner");
        (_Guardian, _GuardianPK) = makeAddrAndKey("_Guardian");

        versionSaltV6 = keccak256(abi.encodePacked("SALT_0001"));
        versionSaltV9 = keccak256(abi.encodePacked("SALT_0002"));
    }
}
