// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {Script} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {OpenfortPaymaster} from "../contracts/paymaster/OpenfortPaymaster.sol";

abstract contract OpenfortScriptBase is Script {
    IEntryPoint internal entryPoint = IEntryPoint((payable(vm.envAddress("ENTRY_POINT_ADDRESS"))));
    OpenfortPaymaster openfortPaymasterTestnet =
        OpenfortPaymaster((payable(vm.envAddress("PAYMASTER_ADDRESS_TESTNET"))));
    OpenfortPaymaster openfortPaymasterMainnet =
        OpenfortPaymaster((payable(vm.envAddress("PAYMASTER_ADDRESS_MAINNET"))));
    address internal openfortPaymasterOwnerTestnet;
    address internal openfortPaymasterOwnerMainnet;

    uint256 internal goerliFork;
    uint256 internal mumbaiFork;
    uint256 internal fujiFork;
    uint256 internal bscTestFork;
    uint256 internal arbitrumTestFork;
    uint256 internal baseGoerliFork;
    uint256 internal beamTestnetFork;
    uint256 internal chiadoFork;

    uint256 internal polygonFork;
    uint256 internal avalancheFork;
    uint256 internal bscFork;
    uint256 internal arbitrumFork;
    uint256 internal baseFork;
    uint256 internal beamFork;

    uint256 internal constant BASE_MAIN = 8453;
    uint256 internal constant ARBITRUM_MAIN = 42161;

    constructor() {
        openfortPaymasterOwnerTestnet = vm.envAddress("PAYMASTER_OWNER_TESTNET");
        openfortPaymasterOwnerMainnet = vm.envAddress("PAYMASTER_OWNER_MAINNET");

        goerliFork = vm.createFork(vm.envString("GOERLI_RPC"));
        mumbaiFork = vm.createFork(vm.envString("POLYGON_MUMBAI_RPC"));
        fujiFork = vm.createFork(vm.envString("AVALANCHE_FUJI_RPC"));
        bscTestFork = vm.createFork(vm.envString("BSC_TESTNET_RPC"));
        arbitrumTestFork = vm.createFork(vm.envString("ARBITRUM_GOERLI_RPC"));
        baseGoerliFork = vm.createFork(vm.envString("GOERLI_BASE_RPC"));
        beamTestnetFork = vm.createFork(vm.envString("BEAM_TESTNET_RPC"));
        chiadoFork = vm.createFork(vm.envString("GNOSIS_CHIADO_RPC"));

        polygonFork = vm.createFork(vm.envString("POLYGON_RPC"));
        avalancheFork = vm.createFork(vm.envString("AVALANCHE_RPC"));
        bscFork = vm.createFork(vm.envString("BSC_RPC"));
        arbitrumFork = vm.createFork(vm.envString("ARBITRUM_ONE_RPC"));
        baseFork = vm.createFork(vm.envString("MAINNET_BASE_RPC"));
        beamFork = vm.createFork(vm.envString("BEAM_RPC"));
    }

}
