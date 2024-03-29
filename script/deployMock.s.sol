// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Script} from "forge-std/Script.sol";
import {MockERC20} from "../contracts/mock/MockERC20.sol";
import {MockERC721} from "../contracts/mock/MockERC721.sol";
import {MockERC1155} from "../contracts/mock/MockERC1155.sol";

contract DeployMock is Script {
    uint256 internal deployPrivKey = vm.envUint("PK_PAYMASTER_OWNER_TESTNET");
    address internal deployAddress = vm.addr(deployPrivKey);

    function run() public returns (MockERC20 mockERC20, MockERC721 mockERC721, MockERC1155 mockERC1155) {
        bytes32 versionSalt = bytes32(0x0);
        vm.startBroadcast(deployPrivKey);

        mockERC20 = new MockERC20{salt: versionSalt}();
        mockERC721 = new MockERC721{salt: versionSalt}();
        mockERC1155 = new MockERC1155{salt: versionSalt}();

        vm.stopBroadcast();
    }
}
