// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Script} from "forge-std/Script.sol";
import {IEntryPoint, EntryPoint} from "account-abstraction/core/EntryPoint.sol";

contract CheckOrDeployEntryPoint is Script {
    uint256 private ANVIL_CHAINID = 31337;

    function checkOrDeployEntryPoint() public returns (IEntryPoint entryPoint) {
        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        // If we are in a fork
        if (vm.envAddress("ENTRY_POINT_ADDRESS").code.length > 0) {
            entryPoint = IEntryPoint(payable(vm.envAddress("ENTRY_POINT_ADDRESS")));
        }
        // If not a fork, deploy entryPoint (at correct address)
        else if (chainId == ANVIL_CHAINID) {
            EntryPoint entryPointAux = new EntryPoint();
            bytes memory code = address(entryPointAux).code;
            address targetAddr = address(vm.envAddress("ENTRY_POINT_ADDRESS"));
            vm.etch(targetAddr, code);
            entryPoint = IEntryPoint(payable(targetAddr));
        } else {
            revert("No EntryPoint in this chain");
        }
    }
}
