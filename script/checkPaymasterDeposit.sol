// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import {Script, console} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {OpenfortPaymaster} from "../contracts/paymaster/OpenfortPaymaster.sol";

contract CheckPaymasterDeposit is Script {
    IEntryPoint internal entryPoint = IEntryPoint((payable(vm.envAddress("ENTRY_POINT_ADDRESS"))));
    OpenfortPaymaster openfortPaymaster = OpenfortPaymaster((payable(vm.envAddress("PAYMASTER_ADDRESS"))));

    uint256 internal goerliFork = vm.createFork(vm.envString("GOERLI_RPC"));
    uint256 internal mumbaiFork = vm.createFork(vm.envString("POLYGON_MUMBAI_RPC"));
    uint256 internal fujiFork = vm.createFork(vm.envString("AVALANCHE_FUJI_RPC"));
    uint256 internal bscFork = vm.createFork(vm.envString("BSC_TESTNET_RPC"));

    function checkPaymasterDeposit(uint256 fork_id) internal {
        vm.selectFork(fork_id);

        console.log("\tPaymaster at address %s", address(openfortPaymaster));
        uint256 paymasterDeposit = openfortPaymaster.getDeposit();
        console.log(
            "\tDeposit on chain ID %s is: %s wei (%s ETH)\n",
            block.chainid,
            paymasterDeposit,
            paymasterDeposit / 10 ** 18
        );

        if (paymasterDeposit < 2 ether) {
            console.log("ALERT: deposit too low on chain ID %s!\n", block.chainid);
        }
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
