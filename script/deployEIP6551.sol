// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {VIPNFT} from "contracts/mock/VipNFT.sol";
import {EIP6551OpenfortAccount} from "contracts/core/eip6551/EIP6551OpenfortAccount.sol";
import {ERC6551Registry} from "../contracts/core/eip6551/ERC6551Registry.sol";

contract EIP6551OpenfortDeploy is Script {
    uint256 internal deployPrivKey = vm.deriveKey(vm.envString("MNEMONIC"), 0);
    address internal deployAddress = vm.addr(deployPrivKey);
    IEntryPoint internal entryPoint = IEntryPoint((payable(vm.envAddress("ENTRY_POINT_ADDRESS"))));
    VIPNFT testToken;

    function run() public {
        bytes32 versionSalt = vm.envBytes32("VERSION_SALT");
        vm.startBroadcast(deployPrivKey);

        // Create an acccount to serve as implementation
        EIP6551OpenfortAccount eip6551OpenfortAccount = new EIP6551OpenfortAccount{salt: versionSalt}();

        // Create a factory to deploy cloned accounts
        ERC6551Registry erc6551Registry = new ERC6551Registry{salt: versionSalt}();

        uint256 chainId;
        assembly {
            chainId := chainid()
        }

        // deploy a new VIPNFT collection
        testToken = new VIPNFT();

        // The first call should create a new account, while the second will just return the corresponding account address
        address account2 = erc6551Registry.createAccount(
            address(eip6551OpenfortAccount),
            chainId,
            address(testToken),
            1,
            1,
            abi.encodeWithSignature("initialize(address)", address(entryPoint))
        );
        console.log("Registry at address %s has created an account at address %s", address(erc6551Registry), account2);

        vm.stopBroadcast();
    }
}
