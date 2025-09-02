// SPDX-LIcense-Idnetifier: MIT

pragma solidity ^0.8.29;

import {Test} from "lib/forge-std/src/Test.sol";
import {IEntryPoint} from "@account-abstraction-v8/interfaces/IEntryPoint.sol";

contract PaymasterDataTest is Test {
    IEntryPoint ENTRY_POINT_V8 = IEntryPoint(0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108);
    uint256 ownerPK;
    address owner;
    uint256 managerPK;
    address manager;
    uint256[] signersPK;
    address[] signers;

    uint256 constant signersLength = 3;

    uint256 forkId;
    string SEPOLIA_RPC_URL = "https://eth-sepolia.g.alchemy.com/v2/EIOmdDtOw7ulufI5S27isOfZfW51PQXB";

    function setUp() public virtual {
        forkId = vm.createFork(SEPOLIA_RPC_URL);
        vm.selectFork(forkId);

        (owner, ownerPK) = makeAddrAndKey("owner");
        (manager, managerPK) = makeAddrAndKey("manager");

        for (uint256 i = 0; i < signersLength;) {
            (address signer, uint256 signerPK) = makeAddrAndKey(string.concat("signer", vm.toString(i)));
            signers.push(signer);
            signersPK.push(signerPK);
            unchecked {
                i++;
            }
        }
    }
}
