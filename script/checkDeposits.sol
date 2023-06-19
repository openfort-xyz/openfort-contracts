// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {OpenfortPaymaster} from "../contracts/paymaster/OpenfortPaymaster.sol";

contract CheckDeposits is Script {
    IEntryPoint internal entryPoint = IEntryPoint((payable(vm.envAddress("ENTRY_POINT_ADDRESS"))));
    OpenfortPaymaster openfortPaymaster = OpenfortPaymaster((payable(vm.envAddress("PAYMASTER_ADDRESS"))));
    address internal openfortPatron = vm.envAddress("PATRON_ADDRESS");

    uint256 internal goerliFork = vm.createFork(vm.envString("GOERLI_RPC"));
    uint256 internal mumbaiFork = vm.createFork(vm.envString("POLYGON_MUMBAI_RPC"));
    uint256 internal fujiFork = vm.createFork(vm.envString("AVALANCHE_FUJI_RPC"));
    uint256 internal bscFork = vm.createFork(vm.envString("BSC_TESTNET_RPC"));
    uint256 internal arbitrumFork = vm.createFork(vm.envString("ARBITRUM_GOERLI_RPC"));

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
            console.log("ALERT: deposit too low on chain ID %s! Deposit: %s\n", block.chainid, paymasterDeposit);
        }
    }

    function checkPatronBalance(uint256 fork_id) internal {
        vm.selectFork(fork_id);

        console.log("\tPatron at address %s", openfortPatron);
        uint256 patronBalance = openfortPatron.balance;
        console.log(
            "\tBalance of patron on chain ID %s is: %s wei (%s ETH)\n",
            block.chainid,
            patronBalance,
            patronBalance / 10 ** 18
        );

        if (patronBalance < 2 ether) {
            console.log("ALERT: balance of Patron too low on chain ID %s! Deposit: %s\n", block.chainid, patronBalance);
        }
    }

    function run() public {
        console.log("EntryPoint adress: %s\n", address(entryPoint));
        console.log("Paymaster adress: %s\n", address(openfortPaymaster));
        console.log("Patron adress: %s\n", openfortPatron);
        console.log("---------------");

        console.log("Checking Paymaster and Patron on Goerli:");
        checkPaymasterDeposit(goerliFork);
        checkPatronBalance(goerliFork);

        console.log("Checking Paymaster and Patron on Mumbai:");
        checkPaymasterDeposit(mumbaiFork);
        checkPatronBalance(mumbaiFork);

        console.log("Checking Paymaster and Patron on Fuji:");
        checkPaymasterDeposit(fujiFork);
        checkPatronBalance(fujiFork);

        console.log("Checking Paymaster and Patron on BSC testnet:");
        checkPaymasterDeposit(bscFork);
        checkPatronBalance(bscFork);

        console.log("Checking Paymaster and Patron on Arbirtum Goerli testnet:");
        checkPaymasterDeposit(arbitrumFork);
        checkPatronBalance(arbitrumFork);
    }
}
