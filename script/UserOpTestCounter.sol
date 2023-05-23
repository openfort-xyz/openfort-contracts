// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {Script, console} from "forge-std/Script.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {StaticOpenfortFactory, StaticOpenfortAccount} from "../contracts/core/static/StaticOpenfortFactory.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {UserOperation, UserOperationLib} from "account-abstraction/interfaces/UserOperation.sol";

contract UserOpTestCounter is Script {
    using ECDSA for bytes32;
    using UserOperationLib for UserOperation;

    uint256 public mumbaiFork = vm.createFork(vm.envString("POLYGON_MUMBAI_RPC"));

    uint256 internal deployPrivKey = vm.deriveKey(vm.envString("MNEMONIC"), 0);
    address internal deployAddress = vm.addr(deployPrivKey);
    EntryPoint internal entryPoint = EntryPoint((payable(vm.envAddress("ENTRY_POINT_ADDRESS"))));

    StaticOpenfortFactory staticOpenfortFactory;
    StaticOpenfortAccount staticOpenfortAccount;
    TestCounter testCounter;

    function calcPreVerificationGas(UserOperation calldata userOp) public {
        console.logBytes(userOp.pack());
    }

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
            preVerificationGas: 80_000,
            maxFeePerGas: 1_500_000_030,
            maxPriorityFeePerGas: 1_500_000_000,
            paymasterAndData: bytes(""),
            signature: bytes("")
        });

        // Sign UserOp
        bytes32 opHash = entryPoint.getUserOpHash(op);
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
    ) internal view returns (UserOperation[] memory) {
        bytes memory callDataForEntrypoint =
            abi.encodeWithSignature("execute(address,uint256,bytes)", _target, _value, _callData);

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
    ) internal view returns (UserOperation[] memory) {
        bytes memory callDataForEntrypoint =
            abi.encodeWithSignature("executeBatch(address[],uint256[],bytes[])", _target, _value, _callData);

        return _setupUserOp(sender, _signerPKey, _initCode, callDataForEntrypoint);
    }

    function setUp() public {
        vm.selectFork(mumbaiFork);

        // Due to errors with Foundry and create2, let's use hardcoded addresses for testing:
        staticOpenfortFactory = StaticOpenfortFactory(0xe9B5fb44f377Ce5a03427d5Be7D9d073bf8FE1f0);
        testCounter = new TestCounter();
    }

    function run() public {
        vm.startBroadcast(deployPrivKey);

        // Verifiy that the counter is still set to 0
        assert(testCounter.counters(deployAddress) == 0);
        // Count using deployPrivKey
        testCounter.count();
        assert(testCounter.counters(deployAddress) == 1);

        address account = staticOpenfortFactory.createAccount(deployAddress, "");

        // Count using userOp
        UserOperation[] memory userOp = _setupUserOpExecute(
            account, deployPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        this.calcPreVerificationGas(userOp[0]);

        entryPoint.depositTo{value: 10000000000000000}(account);
        entryPoint.handleOps(userOp, payable(deployAddress));

        vm.stopBroadcast();
    }
}
