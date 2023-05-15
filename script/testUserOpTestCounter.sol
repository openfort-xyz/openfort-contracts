// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {Script} from "forge-std/Script.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {StaticOpenfortAccountFactory, StaticOpenfortAccount, IEntryPoint} from "../contracts/core/static/StaticOpenfortAccountFactory.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";
import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol";


contract StaticOpenfortAccountFactoryDeploy is Script {
    using ECDSA for bytes32;

    uint256 deployPrivKey;
    address deployAddress;
    IEntryPoint entryPoint;
    StaticOpenfortAccountFactory staticOpenfortAccountFactory;
    StaticOpenfortAccount staticOpenfortAccount;
    TestCounter testCounter;

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
            preVerificationGas: 80_000,
            maxFeePerGas: 1_500_000_030,
            maxPriorityFeePerGas: 1_500_000_000,
            paymasterAndData: bytes(""),
            signature: bytes("")
        });

        // Sign UserOp
        bytes32 opHash = IEntryPoint(entryPoint).getUserOpHash(op);
        bytes32 msgHash = ECDSA.toEthSignedMessageHash(opHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_signerPKey, msgHash);
        bytes memory userOpSignature = abi.encodePacked(r, s, v);

        address recoveredSigner = ECDSA.recover(msgHash, v, r, s);
        address expectedSigner = vm.addr(_signerPKey);
        require(recoveredSigner == expectedSigner);

        op.signature = userOpSignature;

        // Store UserOp
        ops = new UserOperation[](1);
        ops[0] = op;
    }

    /* 
     * Auxiliary function to generate a userOP using the execute()
     * from the account
     */
    function _setupUserOpExecute(
        address sender,
        uint256 _signerPKey,
        bytes memory _initCode,
        address _target,
        uint256 _value,
        bytes memory _callData
    ) internal returns (UserOperation[] memory) {
        bytes memory callDataForEntrypoint = abi.encodeWithSignature(
            "execute(address,uint256,bytes)",
            _target,
            _value,
            _callData
        );

        return _setupUserOp(sender, _signerPKey, _initCode, callDataForEntrypoint);
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

    function setUp() public {
        deployPrivKey = vm.deriveKey(vm.envString("MNEMONIC"), 0);
        deployAddress = vm.addr(deployPrivKey);
        entryPoint = IEntryPoint(payable(vm.envAddress("ENTRY_POINT_ADDRESS")));
        staticOpenfortAccountFactory = StaticOpenfortAccountFactory(0xfaE7940051e23EE8B7E267E7f3d207069E250842);
        staticOpenfortAccount = StaticOpenfortAccount(payable(0x330a919e0605E91D62f8136D9Ee8a9a0b8ff92CF));
        testCounter = TestCounter(0x1A09053F78695ad7372D0539E5246d025b254A4c);
    }

    function run() public {
        vm.startBroadcast(deployPrivKey);

        // Count using deployPrivKey
        testCounter.count();

        // Count using userOp
        UserOperation[] memory userOp = _setupUserOpExecute(
            address(staticOpenfortAccount),
            deployPrivKey,
            bytes(""),
            address(testCounter),
            0,
            abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 100000000000000000}(address(staticOpenfortAccount));
        entryPoint.handleOps(userOp, payable(deployAddress));

        // Verifiy that the counter has increased
        //assertEq(testCounter.counters(deployAddress), 1);

        vm.stopBroadcast();
    }
}
