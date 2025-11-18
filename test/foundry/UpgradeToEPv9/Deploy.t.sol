// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import {AAHelper} from "test/foundry/UpgradeToEPv9/helpers/AAHelper.t.sol";
import {IStakeManager} from "lib/account-abstraction/contracts/interfaces/IStakeManager.sol";
import {
    EntryPoint as EntryPointV6,
    IEntryPoint as IEntryPointv6
} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {
    EntryPoint as EntryPointV9,
    IEntryPoint as IEntryPointv9
} from "lib/account-abstraction-v09/contracts/core/EntryPoint.sol";
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

contract Deploy is AAHelper {
    function setUp() public virtual override {
        super.setUp();

        EntryPointV6 deployedEntryPointV6 = new EntryPointV6();
        vm.etch(ENTRY_POINT_V6, address(deployedEntryPointV6).code);
        vm.label(ENTRY_POINT_V6, "EntryPointV6");
        entryPointV6 = IEntryPointv6(payable(ENTRY_POINT_V6));

        EntryPointV9 deployedEntryPointV9 = new EntryPointV9();
        entryPointV9 = IEntryPointv9(payable(address(deployedEntryPointV9)));
        vm.label(address(entryPointV9), "EntryPointV9");

        vm.startPrank(_OpenfortAdmin);
        upgradeableOpenfortAccountImplV6 = new UpgradeableOpenfortAccountV6{salt: versionSaltV6}();
        openfortFactoryV6 = new UpgradeableOpenfortFactoryV6{salt: versionSaltV6}(
            _OpenfortAdmin,
            address(entryPointV6),
            address(upgradeableOpenfortAccountImplV6),
            RECOVERY_PERIOD,
            SECURITY_PERIOD,
            SECURITY_WINDOW,
            LOCK_PERIOD,
            _Guardian
        );

        upgradeableOpenfortAccountImplV9 = new UpgradeableOpenfortAccountV9{salt: versionSaltV9}();
        openfortFactoryV9 = new UpgradeableOpenfortFactoryV9{salt: versionSaltV9}(
            _OpenfortAdmin,
            address(entryPointV9),
            address(upgradeableOpenfortAccountImplV9),
            RECOVERY_PERIOD,
            SECURITY_PERIOD,
            SECURITY_WINDOW,
            LOCK_PERIOD,
            _Guardian
        );
        vm.stopPrank();

        _dealAll();
        _depositToEp();
    }

    function test_AfterDeploy() external {
        assertEq(address(entryPointV6), ENTRY_POINT_V6);
        assertTrue(address(entryPointV9) != address(0), "EntryPointV9 not deployed");
        assertEq(openfortFactoryV6.owner(), _OpenfortAdmin);
        assertEq(openfortFactoryV6.initialGuardian(), _Guardian);
        assertEq(openfortFactoryV6.implementation(), address(upgradeableOpenfortAccountImplV6));
        assertEq(openfortFactoryV6.entrypointContract(), ENTRY_POINT_V6);
        assertEq(openfortFactoryV6.lockPeriod(), LOCK_PERIOD);
        assertEq(openfortFactoryV6.recoveryPeriod(), RECOVERY_PERIOD);
        assertEq(openfortFactoryV6.securityPeriod(), SECURITY_PERIOD);
        assertEq(openfortFactoryV6.securityWindow(), SECURITY_WINDOW);
        _assertEPDeposits();
    }

    function _dealAll() internal {
        _deal(_OpenfortAdmin, 5 ether);
        _deal(_AccountOwner, 5 ether);
        _deal(_Guardian, 5 ether);
    }

    function _depositToEp() internal {
        _depositTo(_OpenfortAdmin, _OpenfortAdmin, EP_Version.V6);
        _depositTo(_OpenfortAdmin, _OpenfortAdmin, EP_Version.V9);
        _depositTo(_AccountOwner, _AccountOwner, EP_Version.V6);
        _depositTo(_AccountOwner, _AccountOwner, EP_Version.V9);
    }

    function _assertEPDeposits() internal {
        IStakeManager.DepositInfo memory DI;
        DI = entryPointV6.getDepositInfo(_OpenfortAdmin);
        assertEq(DI.deposit, 0.1 ether);
        DI = entryPointV6.getDepositInfo(_OpenfortAdmin);
        assertEq(DI.deposit, 0.1 ether);
        DI = entryPointV6.getDepositInfo(_AccountOwner);
        assertEq(DI.deposit, 0.1 ether);
        DI = entryPointV6.getDepositInfo(_AccountOwner);
        assertEq(DI.deposit, 0.1 ether);
    }
}
