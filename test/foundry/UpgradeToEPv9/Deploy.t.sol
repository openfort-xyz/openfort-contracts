// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import {Data} from "test/foundry/UpgradeToEPv9/Data/Data.t.sol";
import {IUpgradeableOpenfortAccount} from "contracts/interfaces/IUpgradeableOpenfortAccount.sol";
import {UpgradeableOpenfortFactory} from "contracts/core/upgradeable/UpgradeableOpenfortFactory.sol";
import {EntryPoint as EntryPointV6, IEntryPoint as IEntryPointv6} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {EntryPoint as EntryPointV9, IEntryPoint as IEntryPointv9} from "lib/account-abstraction-v09/contracts/core/EntryPoint.sol";

contract Deploy is Data {
    function setUp() public virtual override {
        super.setUp();
        
        EntryPointV6 deployedEntryPointV6 = new EntryPointV6();
        vm.etch(ENTRY_POINT_V6, address(deployedEntryPointV6).code);
        vm.label(ENTRY_POINT_V6, "EntryPointV6");
        entryPointV6 = IEntryPointv6(payable(ENTRY_POINT_V6));

        EntryPointV9 deployedEntryPointV9 = new EntryPointV9();
        vm.etch(ENTRY_POINT_V9, address(deployedEntryPointV9).code);
        vm.label(ENTRY_POINT_V9, "EntryPointV9");
        entryPointV9 = IEntryPointv6(payable(ENTRY_POINT_V9));
    }
}