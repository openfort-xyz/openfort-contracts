// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {OpenfortPaymaster} from "../contracts/paymaster/OpenfortPaymaster.sol";

contract CheckDeposits is Script {
    IEntryPoint internal entryPoint = IEntryPoint((payable(vm.envAddress("ENTRY_POINT_ADDRESS"))));
    OpenfortPaymaster openfortPaymasterTestnet =
        OpenfortPaymaster((payable(vm.envAddress("PAYMASTER_ADDRESS_TESTNET"))));
    OpenfortPaymaster openfortPaymasterMainnet =
        OpenfortPaymaster((payable(vm.envAddress("PAYMASTER_ADDRESS_MAINNET"))));
    address internal openfortPaymasterOwnerTestnet = vm.envAddress("PAYMASTER_OWNER_TESTNET");
    address internal openfortPaymasterOwnerMainnet = vm.envAddress("PAYMASTER_OWNER_MAINNET");

    uint256 internal goerliFork = vm.createFork(vm.envString("GOERLI_RPC"));
    uint256 internal mumbaiFork = vm.createFork(vm.envString("POLYGON_MUMBAI_RPC"));
    uint256 internal fujiFork = vm.createFork(vm.envString("AVALANCHE_FUJI_RPC"));
    uint256 internal bscTestFork = vm.createFork(vm.envString("BSC_TESTNET_RPC"));
    uint256 internal arbitrumTestFork = vm.createFork(vm.envString("ARBITRUM_GOERLI_RPC"));
    uint256 internal baseGoerliFork = vm.createFork(vm.envString("GOERLI_BASE_RPC"));
    uint256 internal beamTestnetFork = vm.createFork(vm.envString("BEAM_TESTNET_RPC"));
    uint256 internal chiadoFork = vm.createFork(vm.envString("GNOSIS_CHIADO_RPC"));

    uint256 internal polygonFork = vm.createFork(vm.envString("POLYGON_RPC"));
    uint256 internal avalancheFork = vm.createFork(vm.envString("AVALANCHE_RPC"));
    uint256 internal bscFork = vm.createFork(vm.envString("BSC_RPC"));
    uint256 internal arbitrumFork = vm.createFork(vm.envString("ARBITRUM_ONE_RPC"));
    uint256 internal baseFork = vm.createFork(vm.envString("MAINNET_BASE_RPC"));
    uint256 internal beamFork = vm.createFork(vm.envString("BEAM_RPC"));

    uint256 internal constant BASE_MAIN = 8453;
    uint256 internal constant ARBITRUM_MAIN = 42161;

    function checkPaymasterDeposit(uint256 _forkId, OpenfortPaymaster _paymaster) internal {
        vm.selectFork(_forkId);

        console.log("\tPaymaster at address %s", address(_paymaster));
        uint256 paymasterDeposit = _paymaster.getDeposit();
        console.log(
            "\tDeposit on chain ID %s is: %s wei (%s ETH)\n",
            block.chainid,
            paymasterDeposit,
            paymasterDeposit / 10 ** 18
        );

        if (block.chainid == BASE_MAIN || block.chainid == ARBITRUM_MAIN) {
            if (paymasterDeposit < 0.15 ether) {
                console.log("ALERT: deposit too low on chain ID %s! Deposit: %s\n", block.chainid, paymasterDeposit);
            }
        } else {
            if (paymasterDeposit < 1.5 ether) {
                console.log("ALERT: deposit too low on chain ID %s! Deposit: %s\n", block.chainid, paymasterDeposit);
            }
        }
    }

    function checkPaymasterOwnerBalance(uint256 _forkId, address _paymasterOwnerAddress) internal {
        vm.selectFork(_forkId);

        console.log("\tPaymasterOwner at address %s", _paymasterOwnerAddress);
        uint256 paymasterOwnerBalance = _paymasterOwnerAddress.balance;
        console.log(
            "\tBalance of paymasterOwner on chain ID %s is: %s wei (%s ETH)\n",
            block.chainid,
            paymasterOwnerBalance,
            paymasterOwnerBalance / 10 ** 18
        );

        if (block.chainid == BASE_MAIN || block.chainid == ARBITRUM_MAIN) {
            if (paymasterOwnerBalance < 0.15 ether) {
                console.log(
                    "ALERT: balance of PaymasterOwner too low on chain ID %s! Deposit: %s\n",
                    block.chainid,
                    paymasterOwnerBalance
                );
            }
        } else {
            if (paymasterOwnerBalance < 1.5 ether) {
                console.log(
                    "ALERT: balance of PaymasterOwner too low on chain ID %s! Deposit: %s\n",
                    block.chainid,
                    paymasterOwnerBalance
                );
            }
        }
    }

    function run() public {
        console.log("EntryPoint adress: %s\n", address(entryPoint));
        console.log("----------------");
        console.log("----Testnets----");
        console.log("----------------");
        console.log("Paymaster adress: %s", address(openfortPaymasterTestnet));
        console.log("PaymasterOwner adress: %s\n", openfortPaymasterOwnerTestnet);

        console.log("Checking Paymaster and PaymasterOwner on Goerli:");
        checkPaymasterDeposit(goerliFork, openfortPaymasterTestnet);
        checkPaymasterOwnerBalance(goerliFork, openfortPaymasterOwnerTestnet);

        console.log("Checking Paymaster and PaymasterOwner on Mumbai:");
        checkPaymasterDeposit(mumbaiFork, openfortPaymasterTestnet);
        checkPaymasterOwnerBalance(mumbaiFork, openfortPaymasterOwnerTestnet);

        console.log("Checking Paymaster and PaymasterOwner on Fuji:");
        checkPaymasterDeposit(fujiFork, openfortPaymasterTestnet);
        checkPaymasterOwnerBalance(fujiFork, openfortPaymasterOwnerTestnet);

        console.log("Checking Paymaster and PaymasterOwner on BSC testnet:");
        checkPaymasterDeposit(bscTestFork, openfortPaymasterTestnet);
        checkPaymasterOwnerBalance(bscTestFork, openfortPaymasterOwnerTestnet);

        console.log("Checking Paymaster and PaymasterOwner on Arbirtum Goerli testnet:");
        checkPaymasterDeposit(arbitrumTestFork, openfortPaymasterTestnet);
        checkPaymasterOwnerBalance(arbitrumTestFork, openfortPaymasterOwnerTestnet);

        console.log("Checking Paymaster and PaymasterOwner on Base Goerli testnet:");
        checkPaymasterDeposit(baseGoerliFork, openfortPaymasterTestnet);
        checkPaymasterOwnerBalance(baseGoerliFork, openfortPaymasterOwnerTestnet);

        console.log("Checking Paymaster and PaymasterOwner on Beam testnet:");
        checkPaymasterDeposit(beamTestnetFork, openfortPaymasterTestnet);
        checkPaymasterOwnerBalance(beamTestnetFork, openfortPaymasterOwnerTestnet);

        console.log("Checking Paymaster and PaymasterOwner on Gnosis Chiado testnet:");
        checkPaymasterDeposit(chiadoFork, openfortPaymasterTestnet);
        checkPaymasterOwnerBalance(chiadoFork, openfortPaymasterOwnerTestnet);

        console.log("----------------");
        console.log("----Mainnets----");
        console.log("----------------");

        console.log("Paymaster adress: %s", address(openfortPaymasterMainnet));
        console.log("PaymasterOwner adress: %s\n", openfortPaymasterOwnerMainnet);

        console.log("Checking Paymaster and PaymasterOwner on Polygon:");
        checkPaymasterDeposit(polygonFork, openfortPaymasterMainnet);
        checkPaymasterOwnerBalance(polygonFork, openfortPaymasterOwnerMainnet);

        console.log("Checking Paymaster and PaymasterOwner on Avalanche:");
        checkPaymasterDeposit(avalancheFork, openfortPaymasterMainnet);
        checkPaymasterOwnerBalance(avalancheFork, openfortPaymasterOwnerMainnet);

        console.log("Checking Paymaster and PaymasterOwner on BSC:");
        checkPaymasterDeposit(bscFork, openfortPaymasterMainnet);
        checkPaymasterOwnerBalance(bscFork, openfortPaymasterOwnerMainnet);

        console.log("Checking Paymaster and PaymasterOwner on Arbitrum:");
        checkPaymasterDeposit(arbitrumFork, openfortPaymasterMainnet);
        checkPaymasterOwnerBalance(arbitrumFork, openfortPaymasterOwnerMainnet);

        console.log("Checking Paymaster and PaymasterOwner on Base:");
        checkPaymasterDeposit(baseFork, openfortPaymasterMainnet);
        checkPaymasterOwnerBalance(baseFork, openfortPaymasterOwnerMainnet);

        console.log("Checking Paymaster and PaymasterOwner on Beam:");
        checkPaymasterDeposit(beamFork, openfortPaymasterMainnet);
        checkPaymasterOwnerBalance(beamFork, openfortPaymasterOwnerMainnet);
    }
}
