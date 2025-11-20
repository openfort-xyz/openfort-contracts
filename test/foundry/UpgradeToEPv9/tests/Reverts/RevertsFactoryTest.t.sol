// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {Test} from "lib/forge-std/src/Test.sol";
import {IEntryPoint} from "lib/account-abstraction-v09/contracts/interfaces/IEntryPoint.sol";
import {
    UpgradeableOpenfortFactory as UpgradeableOpenfortFactoryV9
} from "contracts/coreV9/upgradeable/UpgradeableOpenfortFactory.sol";
import {
    UpgradeableOpenfortAccount as UpgradeableOpenfortAccountV9
} from "contracts/coreV9/upgradeable/UpgradeableOpenfortAccount.sol";

contract RevertsFactoryTest is Test {
    address internal _Owner;
    address internal _Attacker;
    address internal _Guardian;
    address internal _NewGuardian;

    address internal EP_V9;
    UpgradeableOpenfortAccountV9 internal accountImpl;
    UpgradeableOpenfortFactoryV9 internal factory;

    uint256 internal constant RECOVERY_PERIOD = 2 days;
    uint256 internal constant SECURITY_PERIOD = 1.5 days;
    uint256 internal constant SECURITY_WINDOW = 0.5 days;
    uint256 internal constant LOCK_PERIOD = 7 days;

    error ZeroAddressNotAllowed();
    error NotAContract();
    error InsecurePeriod();
    error OwnableUnauthorizedAccount(address account);

    function setUp() public {
        _Owner = makeAddr("owner");
        _Attacker = makeAddr("attacker");
        _Guardian = makeAddr("guardian");
        _NewGuardian = makeAddr("newGuardian");

        IEntryPoint ep = IEntryPoint(payable(makeAddr("entryPoint")));
        vm.etch(address(ep), hex"00");
        EP_V9 = address(ep);

        accountImpl = new UpgradeableOpenfortAccountV9();

        factory = new UpgradeableOpenfortFactoryV9(
            _Owner, EP_V9, address(accountImpl), RECOVERY_PERIOD, SECURITY_PERIOD, SECURITY_WINDOW, LOCK_PERIOD, _Guardian
        );
    }

    function test_revert_constructor_zeroOwner() external {
        vm.expectRevert(ZeroAddressNotAllowed.selector);
        new UpgradeableOpenfortFactoryV9(
            address(0), EP_V9, address(accountImpl), RECOVERY_PERIOD, SECURITY_PERIOD, SECURITY_WINDOW, LOCK_PERIOD, _Guardian
        );
    }
}
