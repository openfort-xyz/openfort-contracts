// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import {Test, console} from "lib/forge-std/src/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint, UserOperation, IEntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";
import {StaticAccountFactory} from "contracts/core/static/StaticAccountFactory.sol";
import {StaticAccount} from "contracts/core/static/StaticAccount.sol";

contract StaticAccountTest is Test {
    using ECDSA for bytes32;

    EntryPoint public entryPoint;
    StaticAccountFactory public staticAccountFactory;
    TestCounter public testCounter;
    
    // Testing addresses
    address private factoryAdmin;
    uint256 private factoryAdminPKey;

    address private accountAdmin;
    uint256 private accountAdminPKey;
    
    address payable beneficiary = payable(makeAddr("beneficiary"));

    event AccountCreated(address indexed account, address indexed accountAdmin);

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

    /**
     * @notice Initialize the StaticAccount testing contract.
     * Scenario:
     * - factoryAdmin is the deployer (and owner) of the staticAccountFactory
     * - accountAdmin is the account used to deploy new static accounts
     * - entryPoint is the singleton EntryPoint
     * - testCounter is the counter used to test userOps
     */
    function setUp() public {
        // Setup and fund signers
        (factoryAdmin, factoryAdminPKey) = makeAddrAndKey("factoryAdmin");
        vm.deal(factoryAdmin, 100 ether);
        (accountAdmin, accountAdminPKey) = makeAddrAndKey("accountAdmin");
        vm.deal(accountAdmin, 100 ether);

        // deploy entryPoint
        entryPoint = new EntryPoint();
        // deploy account factory
        vm.prank(factoryAdmin);
        staticAccountFactory = new StaticAccountFactory(IEntryPoint(payable(address(entryPoint))));

        testCounter = new TestCounter();
    }

    /// Create an account by directly calling the factory.
    function testCreateAccountViaFactory() public {
        // Get the counterfactual address
        address account = staticAccountFactory.getAddress(accountAdmin);

        // Expect that we will see an event containing the account and admin
        vm.expectEmit(true, true, false, true);
        emit AccountCreated(account, accountAdmin);

        // Deploy a static account to the counterfactual address
        staticAccountFactory.createAccount(accountAdmin, bytes(""));

        // Make sure the counterfactual address has not been altered
        account = staticAccountFactory.getAddress(accountAdmin);
    }

    /// Create an account by directly calling the factory and make it call count() directly.
    function testCreateAccountTestCounterDirect() public {
        // Create an static account wallet and get its address
        staticAccountFactory.createAccount(accountAdmin,"");
        address account = staticAccountFactory.getAddress(accountAdmin);

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        // Make the admin of the static account wallet (deployer) call "count"
        vm.prank(accountAdmin);
        StaticAccount(payable(account)).execute(address(testCounter), 0, abi.encodeWithSignature("count()"));

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /// Create an account by directly calling the factory and make it call count() via EntryPoint.
    function testCreateAccountTestCounterViaEntrypoint() public {
        // Create an static account wallet and get its address
        staticAccountFactory.createAccount(accountAdmin,"");
        address account = staticAccountFactory.getAddress(accountAdmin);

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account,
            accountAdminPKey,
            bytes(""),
            address(testCounter),
            0,
            abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /// Create an account by directly calling the factory and make it call count() via EntryPoint.
    function testCreateAccountTestCounterViaEntrypointBatching() public {
        // Create an static account wallet and get its address
        staticAccountFactory.createAccount(accountAdmin,"");
        address account = staticAccountFactory.getAddress(accountAdmin);

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        uint256 count = 1;
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
            accountAdminPKey,
            bytes(""),
            targets,
            values,
            callData
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 3);
    }
}
