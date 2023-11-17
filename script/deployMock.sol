// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {UpgradeableOpenfortFactory} from "../contracts/core/upgradeable/UpgradeableOpenfortFactory.sol";
import {MockERC20} from "../contracts/mock/MockERC20.sol";

contract DeployMock is Script {
    uint256 internal deployPrivKey = vm.deriveKey(vm.envString("MNEMONIC"), 0);
    // uint256 internal deployPrivKey = vm.envUint("PK");
    address internal deployAddress = vm.addr(deployPrivKey);
    IEntryPoint internal entryPoint = IEntryPoint((payable(vm.envAddress("ENTRY_POINT_ADDRESS"))));

    function run() public {
        vm.startBroadcast(deployPrivKey);

        MockERC20 mockERC20 = new MockERC20();
        (mockERC20);

        vm.stopBroadcast();
    }
}
