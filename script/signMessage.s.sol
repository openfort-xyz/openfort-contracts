// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Script, console} from "forge-std/Script.sol";

contract SignMessages is Script {
    uint256 internal deployPrivKey = vm.deriveKey(vm.envString("MNEMONIC"), 0);
    address internal deployAddress = vm.addr(deployPrivKey);

    function run() public {
        vm.startBroadcast(deployPrivKey);

        bytes memory text = "Signed by Openfort";
        bytes32 hash = keccak256(text);
        console.log("Hash:");
        console.logBytes32(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deployPrivKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);
        console.log("Signature:");
        console.logBytes(signature);
        address signer = ecrecover(hash, v, r, s);
        console.log("Signer:");
        console.log(signer);

        vm.stopBroadcast();
    }
}
