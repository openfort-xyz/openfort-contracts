// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import {AAHelper} from "test/foundry/UpgradeToEPv9/helpers/AAHelper.t.sol";
import {IStakeManager} from "lib/account-abstraction/contracts/interfaces/IStakeManager.sol";
import {UpgradeableOpenfortAccount} from "contracts/core/upgradeable/UpgradeableOpenfortAccount.sol";
import {UpgradeableOpenfortFactory} from "contracts/core/upgradeable/UpgradeableOpenfortFactory.sol";
import {EntryPoint as EntryPointV6, IEntryPoint as IEntryPointv6} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {EntryPoint as EntryPointV9, IEntryPoint as IEntryPointv9} from "lib/account-abstraction-v09/contracts/core/EntryPoint.sol";
contract Deploy is AAHelper {
    function setUp() public virtual override {
        super.setUp();
        
        EntryPointV6 deployedEntryPointV6 = new EntryPointV6();
        vm.etch(ENTRY_POINT_V6, address(deployedEntryPointV6).code);
        vm.label(ENTRY_POINT_V6, "EntryPointV6");
        entryPointV6 = IEntryPointv6(payable(ENTRY_POINT_V6));

        EntryPointV9 deployedEntryPointV9 = new EntryPointV9();
        vm.etch(ENTRY_POINT_V9, address(deployedEntryPointV9).code);
        vm.label(ENTRY_POINT_V9, "EntryPointV9");
        entryPointV9 = IEntryPointv9(payable(ENTRY_POINT_V9));

        vm.startPrank(_OpenfortAdmin);
        upgradeableOpenfortAccountImpl = new UpgradeableOpenfortAccount{salt: versionSalt}();
        openfortFactory = new UpgradeableOpenfortFactory{salt: versionSalt}(
            _OpenfortAdmin,
            address(entryPointV6),
            address(upgradeableOpenfortAccountImpl),
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
        assertEq(address(entryPointV9), ENTRY_POINT_V9);
        assertEq(openfortFactory.owner(), _OpenfortAdmin);
        assertEq(openfortFactory.initialGuardian(), _Guardian);
        assertEq(openfortFactory.implementation(), address(upgradeableOpenfortAccountImpl));
        assertEq(openfortFactory.entrypointContract(), ENTRY_POINT_V6);
        assertEq(openfortFactory.lockPeriod(), LOCK_PERIOD);
        assertEq(openfortFactory.recoveryPeriod(), RECOVERY_PERIOD);
        assertEq(openfortFactory.securityPeriod(), SECURITY_PERIOD);
        assertEq(openfortFactory.securityWindow(), SECURITY_WINDOW);
        _assertEPDeposits();
    }

    function _dealAll() internal {
        _deal(_OpenfortAdmin, 5 ether);
        _deal(_AccountOwner, 5 ether);
        _deal(_Guardian, 5 ether);
    }

    function _depositToEp()  internal {
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