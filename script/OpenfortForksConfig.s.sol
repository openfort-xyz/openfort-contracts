// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {Script} from "forge-std/Script.sol";

/**
 * @title Abstract contract to add the configuration of diffetent paymasters
 * @author Eloi<eloi@openfort.xyz>
 * @notice Steps to add/remove a supported chain:
 * 1- Update the `NUM_ACCEPTED_CHAINS` constant to make sure it contains the number of chains available (test and main).
 * 2- Add/remove the related fork information based on the previous examples (createFork, paymasterAddresses, etc.).
 */
abstract contract OpenfortForksConfig is Script {
    address internal immutable entryPoint = vm.envAddress("ENTRY_POINT_ADDRESS");
    uint256 internal constant NUM_ACCEPTED_CHAINS = 14;

    enum Forks {
        GoerliFork, // 0
        MumbaiFork, // 1
        FujiFork, // ...
        BscTestFork,
        ArbitrumTestFork,
        BaseGoerliFork,
        BeamTestnetFork,
        ChiadoFork,
        // Mainnets
        PolygonFork,
        AvalancheFork,
        BscFork,
        ArbitrumFork,
        BaseFork,
        BeamFork // NUM_ACCEPTED_CHAINS-1
    }

    address[NUM_ACCEPTED_CHAINS] internal paymasterAddresses;
    address[NUM_ACCEPTED_CHAINS] internal paymasterOwnerAddresses;

    address internal immutable openfortPaymasterOwnerTestnet;
    address internal immutable openfortPaymasterOwnerMainnet;

    address internal immutable verifyingPaymasterTestnet;
    address internal immutable verifyingPaymasterMainnet;

    uint256 internal constant BASE_MAIN = 8453;
    uint256 internal constant ARBITRUM_MAIN = 42161;

    constructor() {
        /*//////////////////////////////////////////////////////////////////////////
                                    PAYMASTER OWNERS
        //////////////////////////////////////////////////////////////////////////*/
        openfortPaymasterOwnerTestnet = vm.envAddress("PAYMASTER_OWNER_TESTNET");
        openfortPaymasterOwnerMainnet = vm.envAddress("PAYMASTER_OWNER_MAINNET");

        /*//////////////////////////////////////////////////////////////////////////
                                   PAYMASTER ADDRESSES
        //////////////////////////////////////////////////////////////////////////*/
        verifyingPaymasterTestnet = vm.envAddress("PAYMASTER_ADDRESS_TESTNET");
        verifyingPaymasterMainnet = vm.envAddress("PAYMASTER_ADDRESS_MAINNET");

        /*//////////////////////////////////////////////////////////////////////////
                                    TESTNET FORKS
        //////////////////////////////////////////////////////////////////////////*/
        // Fork 0: Ethereum Goerli testnet
        // ToDo in the future: wrap each `vm.createFork` in a try-catch
        // (not trivial as fork number will not match the Fork enum anymore)
        vm.createFork(vm.envString("GOERLI_RPC"));
        paymasterOwnerAddresses[uint256(Forks.GoerliFork)] = openfortPaymasterOwnerTestnet;
        paymasterAddresses[uint256(Forks.GoerliFork)] = verifyingPaymasterTestnet;

        // Fork: Mumbai testnet
        vm.createFork(vm.envString("POLYGON_MUMBAI_RPC"));
        paymasterOwnerAddresses[uint256(Forks.MumbaiFork)] = openfortPaymasterOwnerTestnet;
        paymasterAddresses[uint256(Forks.MumbaiFork)] = verifyingPaymasterTestnet;

        // Fork: Fuji testnet
        vm.createFork(vm.envString("AVALANCHE_FUJI_RPC"));
        paymasterOwnerAddresses[uint256(Forks.FujiFork)] = openfortPaymasterOwnerTestnet;
        paymasterAddresses[uint256(Forks.FujiFork)] = verifyingPaymasterTestnet;

        // Fork: BSC testnet
        vm.createFork(vm.envString("BSC_TESTNET_RPC"));
        paymasterOwnerAddresses[uint256(Forks.BscTestFork)] = openfortPaymasterOwnerTestnet;
        paymasterAddresses[uint256(Forks.BscTestFork)] = verifyingPaymasterTestnet;

        // Fork: Arbitrum Goerli testnet
        vm.createFork(vm.envString("ARBITRUM_GOERLI_RPC"));
        paymasterOwnerAddresses[uint256(Forks.ArbitrumTestFork)] = openfortPaymasterOwnerTestnet;
        paymasterAddresses[uint256(Forks.ArbitrumTestFork)] = verifyingPaymasterTestnet;

        // Fork: Base Goerli testnet
        vm.createFork(vm.envString("GOERLI_BASE_RPC"));
        paymasterOwnerAddresses[uint256(Forks.BaseGoerliFork)] = openfortPaymasterOwnerTestnet;
        paymasterAddresses[uint256(Forks.BaseGoerliFork)] = verifyingPaymasterTestnet;

        // Fork: Beam testnet
        vm.createFork(vm.envString("BEAM_TESTNET_RPC"));
        paymasterOwnerAddresses[uint256(Forks.BeamTestnetFork)] = openfortPaymasterOwnerTestnet;
        paymasterAddresses[uint256(Forks.BeamTestnetFork)] = verifyingPaymasterTestnet;

        // Fork: Gnosis Chiado testnet
        vm.createFork(vm.envString("GNOSIS_CHIADO_RPC"));
        paymasterOwnerAddresses[uint256(Forks.ChiadoFork)] = openfortPaymasterOwnerTestnet;
        paymasterAddresses[uint256(Forks.ChiadoFork)] = verifyingPaymasterTestnet;

        /*//////////////////////////////////////////////////////////////////////////
                                    MAINNET FORKS
        //////////////////////////////////////////////////////////////////////////*/

        // Fork: Polygon Mainnet
        vm.createFork(vm.envString("POLYGON_RPC"));
        paymasterOwnerAddresses[uint256(Forks.PolygonFork)] = openfortPaymasterOwnerMainnet;
        paymasterAddresses[uint256(Forks.PolygonFork)] = verifyingPaymasterMainnet;

        // Fork: Avalanche Mainnet
        vm.createFork(vm.envString("AVALANCHE_RPC"));
        paymasterOwnerAddresses[uint256(Forks.AvalancheFork)] = openfortPaymasterOwnerMainnet;
        paymasterAddresses[uint256(Forks.AvalancheFork)] = verifyingPaymasterMainnet;

        // Fork: Avalanche Mainnet
        vm.createFork(vm.envString("BSC_RPC"));
        paymasterOwnerAddresses[uint256(Forks.BscFork)] = openfortPaymasterOwnerMainnet;
        paymasterAddresses[uint256(Forks.BscFork)] = verifyingPaymasterMainnet;

        // Fork: Arbitrum Mainnet
        vm.createFork(vm.envString("ARBITRUM_ONE_RPC"));
        paymasterOwnerAddresses[uint256(Forks.ArbitrumFork)] = openfortPaymasterOwnerMainnet;
        paymasterAddresses[uint256(Forks.ArbitrumFork)] = verifyingPaymasterMainnet;

        // Fork: Base Mainnet
        vm.createFork(vm.envString("MAINNET_BASE_RPC"));
        paymasterOwnerAddresses[uint256(Forks.BaseFork)] = openfortPaymasterOwnerMainnet;
        paymasterAddresses[uint256(Forks.BaseFork)] = verifyingPaymasterMainnet;

        // Fork: Beam Mainnet
        vm.createFork(vm.envString("BEAM_RPC"));
        paymasterOwnerAddresses[uint256(Forks.BeamFork)] = openfortPaymasterOwnerMainnet;
        paymasterAddresses[uint256(Forks.BeamFork)] = verifyingPaymasterMainnet;
    }
}
