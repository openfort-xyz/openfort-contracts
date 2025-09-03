// SPDX-LIcense-Idnetifier: MIT

pragma solidity ^0.8.29;

import {Test} from "lib/forge-std/src/Test.sol";
import {IEntryPoint} from "@account-abstraction-v8/interfaces/IEntryPoint.sol";
import {UserOperationLib} from "@account-abstraction-v8/core/UserOperationLib.sol";
import {PackedUserOperation} from "@account-abstraction-v8/interfaces/PackedUserOperation.sol";

contract PaymasterDataTest is Test {
    IEntryPoint ENTRY_POINT_V8 = IEntryPoint(0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108);
    uint256 ownerPK;
    address owner;
    uint256 managerPK;
    address manager;
    uint256[] signersPK;
    address[] signers;

    uint256 senderPK;
    address sender;

    uint256 constant signersLength = 3;

    uint256 forkId;
    string SEPOLIA_RPC_URL = "https://eth-sepolia.g.alchemy.com/v2/EIOmdDtOw7ulufI5S27isOfZfW51PQXB";

    address treasury;
    uint8 constant ERC20_MODE = 1;
    uint8 constant VERIFYING_MODE = 0;
    uint8 constant ERC20_PAYMASTER_DATA_LENGTH = 117;
    uint8 immutable VERIFYING_PAYMASTER_DATA_LENGTH = 12;
    uint8 immutable MODE_AND_ALLOW_ALL_BUNDLERS_LENGTH = 1;
    uint256 immutable PAYMASTER_DATA_OFFSET = UserOperationLib.PAYMASTER_DATA_OFFSET;

    function setUp() public virtual {
        forkId = vm.createFork(SEPOLIA_RPC_URL);
        vm.selectFork(forkId);

        treasury = makeAddr("treasury");
        (owner, ownerPK) = makeAddrAndKey("owner");
        (sender, senderPK) = makeAddrAndKey("sender");
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

    function _getFreshUserOp() internal view returns (PackedUserOperation memory userOp) {
        userOp.sender = sender;
        userOp.nonce = 0;
        userOp.initCode = hex"";
        userOp.callData = hex"";
        userOp.accountGasLimits = hex"";
        userOp.preVerificationGas = 0;
        userOp.gasFees = hex"";
        userOp.paymasterAndData = hex"";
        userOp.signature = hex"";
    }
}
