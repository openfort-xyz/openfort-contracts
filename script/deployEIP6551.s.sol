// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {MockERC721} from "contracts/mock/MockERC721.sol";
import {ERC6551OpenfortAccount} from "contracts/core/erc6551/ERC6551OpenfortAccount.sol";
import {IERC6551Registry} from "lib/erc6551/src/ERC6551Registry.sol";

contract ERC6551OpenfortDeploy is Script {
    uint256 internal deployPrivKey = vm.deriveKey(vm.envString("MNEMONIC"), 0);
    address internal deployAddress = vm.addr(deployPrivKey);
    IEntryPoint internal entryPoint = IEntryPoint((payable(vm.envAddress("ENTRY_POINT_ADDRESS"))));
    IERC6551Registry internal erc6551Registry = IERC6551Registry((payable(vm.envAddress("ERC6551_REGISTRY_ADDRESS"))));
    MockERC721 internal nft721;

    function run() public {
        bytes32 versionSalt = vm.envBytes32("VERSION_SALT");
        vm.startBroadcast(deployPrivKey);

        // Create an account to serve as implementation
        ERC6551OpenfortAccount erc6551OpenfortAccount = new ERC6551OpenfortAccount{salt: versionSalt}();

        vm.stopBroadcast();

        uint256 chainId;
        assembly {
            chainId := chainid()
        }

        // deploy a new MockERC721 collection
        nft721 = new MockERC721{salt: versionSalt}();

        // The first call should create a new account, while the second will just return the corresponding account address
        address account2 =
            erc6551Registry.createAccount(address(erc6551OpenfortAccount), versionSalt, chainId, address(nft721), 1);
        console.log("Registry at address %s has created an account at address %s", address(erc6551Registry), account2);
    }
}
