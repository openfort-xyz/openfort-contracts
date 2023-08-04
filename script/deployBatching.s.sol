// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {Script, console} from "forge-std/Script.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";
import {UserOperation, EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {StaticOpenfortFactory} from "../contracts/core/static/StaticOpenfortFactory.sol";

contract DeployBatching is Script {
    using ECDSA for bytes32;

    StaticOpenfortFactory public staticOpenfortFactory;
    TestCounter public testCounter;

    uint256 internal deployPrivKey = vm.deriveKey(vm.envString("MNEMONIC"), 0);
    address internal deployAddress = vm.addr(deployPrivKey);
    EntryPoint internal entryPoint = EntryPoint((payable(vm.envAddress("ENTRY_POINT_ADDRESS"))));

    function setUp() public {}

    /*
     * Auxiliary function to generate a userOP
     */
    function _setupUserOp(
        address sender,
        uint256 _signerPKey,
        bytes memory _initCode,
        bytes memory _callDataForEntrypoint
    ) internal view returns (UserOperation[] memory ops) {
        uint256 nonce = entryPoint.getNonce(sender, 0);

        // Get user op fields
        UserOperation memory op = UserOperation({
            sender: sender,
            nonce: nonce,
            initCode: _initCode,
            callData: _callDataForEntrypoint,
            callGasLimit: 500_000,
            verificationGasLimit: 500_000,
            preVerificationGas: 500_000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: bytes(""),
            signature: bytes("")
        });

        // Sign UserOp
        bytes32 opHash = EntryPoint(entryPoint).getUserOpHash(op);
        bytes32 msgHash = ECDSA.toEthSignedMessageHash(opHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_signerPKey, msgHash);
        bytes memory userOpSignature = abi.encodePacked(r, s, v);

        address recoveredSigner = ECDSA.recover(msgHash, v, r, s);
        address expectedSigner = vm.addr(_signerPKey);
        assert(recoveredSigner == expectedSigner);

        op.signature = userOpSignature;

        // Store UserOp
        ops = new UserOperation[](1);
        ops[0] = op;
    }

    /* 
     * Auxiliary function to generate a userOP using the executeBatch()
     * from the account
     */
    function _setupUserOpExecuteBatch(
        address sender,
        uint256 _signerPKey,
        bytes memory _initCode,
        address[] memory _target,
        uint256[] memory _value,
        bytes[] memory _callData
    ) internal view returns (UserOperation[] memory) {
        bytes memory callDataForEntrypoint =
            abi.encodeWithSignature("executeBatch(address[],uint256[],bytes[])", _target, _value, _callData);

        return _setupUserOp(sender, _signerPKey, _initCode, callDataForEntrypoint);
    }

    function run() public {
        vm.startBroadcast(deployPrivKey);

        // Due to errors with Foundry and create2, let's use hardcoded addresses for testing:
        // Created with
        // forge create StaticOpenfortFactory --mnemonic $MNEMONIC --constructor-args $ENTRY_POINT_ADDRESS --rpc-url $POLYGON_MUMBAI_RPC --verify
        staticOpenfortFactory = StaticOpenfortFactory(0xe9B5fb44f377Ce5a03427d5Be7D9d073bf8FE1f0);
        // Created with
        // forge create TestCounter --mnemonic $MNEMONIC --rpc-url $POLYGON_MUMBAI_RPC --verify
        testCounter = TestCounter(0x1A09053F78695ad7372D0539E5246d025b254A4c);

        // Created with:
        // $forge create StaticOpenfortAccount --constructor-args $ENTRY_POINT_ADDRESS 0x6E767F52d49b0abD686003727b8bc0684011819B --mnemonic $MNEMONIC --rpc-url $POLYGON_MUMBAI_RPC --verify
        address account = staticOpenfortFactory.createAccountWithNonce(deployAddress, "1");

        uint256 count = 3;
        address[] memory targets = new address[](count);
        uint256[] memory values = new uint256[](count);
        bytes[] memory callData = new bytes[](count);

        for (uint256 i = 0; i < count; i += 1) {
            targets[i] = address(testCounter);
            values[i] = 0;
            callData[i] = abi.encodeWithSignature("count()");
        }

        UserOperation[] memory userOp =
            _setupUserOpExecuteBatch(account, deployPrivKey, bytes(""), targets, values, callData);

        entryPoint.depositTo{value: 10000000000000000}(account);
        entryPoint.handleOps(userOp, payable(deployAddress));

        console.log(testCounter.counters(account));

        vm.stopBroadcast();
    }
}
