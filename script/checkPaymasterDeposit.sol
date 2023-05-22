// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {Script, console} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {OpenfortPaymaster} from "../contracts/paymaster/OpenfortPaymaster.sol";

contract CheckPaymasterDeposit is Script {
    uint256 internal deployPrivKey = vm.deriveKey(vm.envString("MNEMONIC"), 0);
    address internal deployAddress = makeAddr(vm.envString("MNEMONIC"));
    IEntryPoint internal entryPoint = IEntryPoint((payable(vm.envAddress("ENTRY_POINT_ADDRESS"))));
    OpenfortPaymaster openfortPaymaster = OpenfortPaymaster((payable(vm.envAddress("PAYMASTER_ADDRESS"))));

    uint256 internal goerliFork = vm.createFork(vm.envString("GOERLI_RPC"));
    uint256 internal mumbaiFork = vm.createFork(vm.envString("POLYGON_MUMBAI_RPC"));
    uint256 internal fujiFork = vm.createFork(vm.envString("AVALANCHE_FUJI_RPC"));
    uint256 internal bscFork = vm.createFork(vm.envString("BSC_TESTNET_RPC"));

    function setUp() public {}

    function checkPaymasterDeposit(uint256 fork_id) internal {
        vm.selectFork(fork_id);
        vm.startBroadcast(deployPrivKey);
        console.log("\tPaymaster at address %s", address(openfortPaymaster));
        console.log(
            "\tDeposit on chain ID %s is: %s wei (%s ETH)\n",
            block.chainid,
            openfortPaymaster.getDeposit(),
            openfortPaymaster.getDeposit() / 10 ** 18
        );
        vm.stopBroadcast();
    }

    function run() public {
        console.log("EntryPoint adress: %s\n", address(entryPoint));
        console.log("Checking current deposit for the Paymaster on Goerli:");
        checkPaymasterDeposit(goerliFork);

        console.log("Checking current deposit for the Paymaster on Mumbai:");
        checkPaymasterDeposit(mumbaiFork);

        console.log("Checking current deposit for the Paymaster on Fuji:");
        checkPaymasterDeposit(fujiFork);

        console.log("Checking current deposit for the Paymaster on BSC testnet:");
        checkPaymasterDeposit(bscFork);
    }
}
