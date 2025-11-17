// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Script, console} from "forge-std/Script.sol";

import {UpgradeableOpenfortFactory} from "contracts/core/upgradeable/UpgradeableOpenfortFactory.sol";

contract DeployNewAccountWithFactory is Script {
    uint256 internal deployPrivKey = uint256(0xf08d0bfabe9a63f25ca7d98a2da32c4a0fca9fb6932b5f692ca794c5f5731d16);
    address internal deployAddress = vm.addr(deployPrivKey);

    address internal factory = 0xCf275C0FE29a16078D78EDd312AA0c93279F2973;
    
    function run() public {
        bytes32 accountNonce = keccak256(abi.encodePacked("account", block.timestamp));

        vm.startBroadcast(deployPrivKey);

        UpgradeableOpenfortFactory openfortFactory = UpgradeableOpenfortFactory(payable(factory));

        address accountProxy = openfortFactory.createAccountWithNonce(deployAddress, accountNonce, false);
        console.log("Account Proxy:", accountProxy);

        vm.stopBroadcast();
    }
}
/**
== Logs ==
  Account Proxy: 0x2898201c9075FBE8D7bfF185aF02fb9442695f26
  Account Proxy: 0x7fBCFb9ABeaeaAcb81A20EA220104Fa08C56b7A7
*/