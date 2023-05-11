// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {Script} from "forge-std/Script.sol";
import {Test, console} from "lib/forge-std/src/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";
import {EntryPoint, UserOperation, IEntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {StaticAccountFactory} from "../contracts/core/static/StaticAccountFactory.sol";

contract StaticAccountFactoryDeploy is Script, Test {
    using ECDSA for bytes32;

    EntryPoint public entryPoint;
    StaticAccountFactory public staticAccountFactory;
    TestCounter public testCounter;

    uint256 deployPrivKey;
    address deployAddress;

    function setUp() public {
        deployPrivKey = vm.deriveKey(vm.envString("MNEMONIC"), 0);
        deployAddress = vm.addr(deployPrivKey);

        entryPoint = EntryPoint(payable(vm.envAddress("ENTRY_POINT_ADDRESS")));
        staticAccountFactory = StaticAccountFactory(0x928495bddb41FB3eFdee06dABd6840184f6aBf21);
        testCounter = new TestCounter();
    }

    /*
     * Auxiliary function to generate a userOP
     */
    function _setupUserOp(
        address sender,
        uint256 _signerPKey,
        bytes memory _initCode,
        bytes memory _callDataForEntrypoint
    ) internal returns (UserOperation[] memory ops) {
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
        assertEq(recoveredSigner, expectedSigner);

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
    ) internal returns (UserOperation[] memory) {
        bytes memory callDataForEntrypoint = abi.encodeWithSignature(
            "executeBatch(address[],uint256[],bytes[])",
            _target,
            _value,
            _callData
        );

        return _setupUserOp(sender, _signerPKey, _initCode, callDataForEntrypoint);
    }

    function run() public {
        vm.startBroadcast(deployPrivKey);

        // Create an static account wallet and get its address
        address account = staticAccountFactory.getAddress(deployAddress);

        // Verifiy that the counter is stil set to 0
        // assertEq(testCounter.counters(account), 0);
        
        uint256 count = 3;
        address[] memory targets = new address[](count);
        uint256[] memory values = new uint256[](count);
        bytes[] memory callData = new bytes[](count);

        for (uint256 i = 0; i < count; i += 1) {
            targets[i] = address(testCounter);
            values[i] = 0;
            callData[i] = abi.encodeWithSignature("count()");
        }

        UserOperation[] memory userOp = _setupUserOpExecuteBatch(
            account,
            deployPrivKey,
            bytes(""),
            targets,
            values,
            callData
        );

        entryPoint.depositTo{value: 10000000000000000}(account);
        entryPoint.handleOps(userOp, payable(deployAddress));

        // Verifiy that the counter has increased
        // assertEq(testCounter.counters(account), 3);

        vm.stopBroadcast();
    }
}
