// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {console} from "forge-std/console.sol";
import {IBaseOpenfortPaymaster} from "../contracts/interfaces/IBaseOpenfortPaymaster.sol";
import {OpenfortForksConfig} from "./OpenfortForksConfig.s.sol";

contract CheckDeposits is OpenfortForksConfig {
    function checkPaymasterDepositAndOwnerBalance(uint256 _forkId) internal {
        vm.selectFork(_forkId);
        checkPaymasterDeposit(paymasterAddresses[_forkId]);
        checkPaymasterOwnerBalance(paymasterOwnerAddresses[_forkId]);
    }

    function checkPaymasterDeposit(address _paymaster) internal view {
        console.log("\tPaymaster at address %s", _paymaster);
        uint256 paymasterDeposit = IBaseOpenfortPaymaster(_paymaster).getDeposit();
        console.log(
            "\tDeposit on chain ID %s is: %s wei (%s ETH)\n",
            block.chainid,
            paymasterDeposit,
            paymasterDeposit / 10 ** 18
        );

        if (block.chainid == BASE_MAIN || block.chainid == ARBITRUM_MAIN || block.chainid == ARBITRUM_NOVA) {
            if (paymasterDeposit < 0.1 ether) {
                console.log("ALERT: deposit too low on chain ID %s! Deposit: %s\n", block.chainid, paymasterDeposit);
            }
        } else if (block.chainid == BEAM_MAIN || block.chainid == BEAM_TESTNET_MAIN) {
            if (paymasterDeposit < 4 ether) {
                console.log("ALERT: deposit too low on chain ID %s! Deposit: %s\n", block.chainid, paymasterDeposit);
            }
        } else {
            if (paymasterDeposit < 1 ether) {
                console.log("ALERT: deposit too low on chain ID %s! Deposit: %s\n", block.chainid, paymasterDeposit);
            }
        }
    }

    function checkPaymasterOwnerBalance(address _paymasterOwnerAddress) internal view {
        console.log("\tPaymasterOwner at address %s", _paymasterOwnerAddress);
        uint256 paymasterOwnerBalance = _paymasterOwnerAddress.balance;
        console.log(
            "\tBalance of paymasterOwner on chain ID %s is: %s wei (%s ETH)\n",
            block.chainid,
            paymasterOwnerBalance,
            paymasterOwnerBalance / 10 ** 18
        );

        if (block.chainid == BASE_MAIN || block.chainid == ARBITRUM_MAIN || block.chainid == ARBITRUM_NOVA) {
            if (paymasterOwnerBalance < 0.1 ether) {
                console.log(
                    "ALERT: balance of PaymasterOwner too low on chain ID %s! Balance: %s\n",
                    block.chainid,
                    paymasterOwnerBalance
                );
            }
        } else {
            if (paymasterOwnerBalance < 1 ether) {
                console.log(
                    "ALERT: balance of PaymasterOwner too low on chain ID %s! Balance: %s\n",
                    block.chainid,
                    paymasterOwnerBalance
                );
            }
        }
    }

    function run() public {
        console.log("EntryPoint address: %s\n", entryPoint);
        console.log("----------------");
        console.log("----Testnets----");
        console.log("----------------");
        console.log("PaymasterOwner address: %s\n", openfortPaymasterOwnerTestnet);

        console.log("Checking Paymaster and PaymasterOwner on Goerli testnet:");
        checkPaymasterDepositAndOwnerBalance(uint256(Forks.GoerliFork));

        console.log("Checking Paymaster and PaymasterOwner on Sepolia testnet:");
        checkPaymasterDepositAndOwnerBalance(uint256(Forks.SepoliaFork));

        console.log("Checking Paymaster and PaymasterOwner on Mumbai testnet:");
        checkPaymasterDepositAndOwnerBalance(uint256(Forks.MumbaiFork));

        console.log("Checking Paymaster and PaymasterOwner on Fuji testnet:");
        checkPaymasterDepositAndOwnerBalance(uint256(Forks.FujiFork));

        console.log("Checking Paymaster and PaymasterOwner on BSC testnet:");
        checkPaymasterDepositAndOwnerBalance(uint256(Forks.BscTestFork));

        console.log("Checking Paymaster and PaymasterOwner on Arbirtum Goerli testnet:");
        checkPaymasterDepositAndOwnerBalance(uint256(Forks.ArbitrumTestFork));

        console.log("Checking Paymaster and PaymasterOwner on Base Goerli testnet:");
        checkPaymasterDepositAndOwnerBalance(uint256(Forks.BaseGoerliFork));

        console.log("Checking Paymaster and PaymasterOwner on Beam testnet:");
        checkPaymasterDepositAndOwnerBalance(uint256(Forks.BeamTestnetFork));

        console.log("Checking Paymaster and PaymasterOwner on Gnosis Chiado testnet:");
        checkPaymasterDepositAndOwnerBalance(uint256(Forks.ChiadoFork));

        console.log("Checking Paymaster and PaymasterOwner on Linea testnet:");
        checkPaymasterDepositAndOwnerBalance(uint256(Forks.LineaTestnetFork));

        console.log("----------------");
        console.log("----Mainnets----");
        console.log("----------------");

        console.log("PaymasterOwner address: %s\n", openfortPaymasterOwnerMainnet);

        console.log("Checking Paymaster and PaymasterOwner on Polygon Mainnet:");
        checkPaymasterDepositAndOwnerBalance(uint256(Forks.PolygonFork));

        console.log("Checking Paymaster and PaymasterOwner on Avalanche Mainnet:");
        checkPaymasterDepositAndOwnerBalance(uint256(Forks.AvalancheFork));

        console.log("Checking Paymaster and PaymasterOwner on BSC Mainnet:");
        checkPaymasterDepositAndOwnerBalance(uint256(Forks.BscFork));

        console.log("Checking Paymaster and PaymasterOwner on Arbitrum Mainnet:");
        checkPaymasterDepositAndOwnerBalance(uint256(Forks.ArbitrumFork));

        console.log("Checking Paymaster and PaymasterOwner on Arbitrum Nova Mainnet:");
        checkPaymasterDepositAndOwnerBalance(uint256(Forks.ArbitrumNovaFork));

        console.log("Checking Paymaster and PaymasterOwner on Base Mainnet:");
        checkPaymasterDepositAndOwnerBalance(uint256(Forks.BaseFork));

        console.log("Checking Paymaster and PaymasterOwner on Beam Mainnet:");
        checkPaymasterDepositAndOwnerBalance(uint256(Forks.BeamFork));
    }
}
