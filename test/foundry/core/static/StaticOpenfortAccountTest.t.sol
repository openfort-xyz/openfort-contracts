// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import {Test, console} from "lib/forge-std/src/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint, UserOperation, IEntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";
import {StaticOpenfortAccountFactory} from "contracts/core/static/StaticOpenfortAccountFactory.sol";
import {StaticOpenfortAccount} from "contracts/core/static/StaticOpenfortAccount.sol";

contract StaticOpenfortAccountTest is Test {
    using ECDSA for bytes32;

    EntryPoint public entryPoint;
    StaticOpenfortAccountFactory public staticOpenfortAccountFactory;
    TestCounter public testCounter;
    
    // Testing addresses
    address private factoryAdmin;
    uint256 private factoryAdminPKey;

    address private accountAdmin;
    uint256 private accountAdminPKey;
    
    address payable private beneficiary = payable(makeAddr("beneficiary"));

    event AccountCreated(address indexed account, address indexed accountAdmin);

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

    /**
     * @notice Initialize the StaticOpenfortAccount testing contract.
     * Scenario:
     * - factoryAdmin is the deployer (and owner) of the StaticOpenfortAccountFactory
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
        staticOpenfortAccountFactory = new StaticOpenfortAccountFactory(IEntryPoint(payable(address(entryPoint))));

        testCounter = new TestCounter();
    }

    /*
     * Create an account by directly calling the factory.
     */
    function testCreateAccountViaFactory() public {
        // Get the counterfactual address
        address account = staticOpenfortAccountFactory.getAddress(accountAdmin);

        // Expect that we will see an event containing the account and admin
        vm.expectEmit(true, true, false, true);
        emit AccountCreated(account, accountAdmin);

        // Deploy a static account to the counterfactual address
        staticOpenfortAccountFactory.createAccount(accountAdmin, bytes(""));

        // Make sure the counterfactual address has not been altered
        assertEq(account, staticOpenfortAccountFactory.getAddress(accountAdmin));
    }

    /*
     * Create an account by directly calling the factory and make it call count() directly.
     */
    function testCreateAccountTestCounterDirect() public {
        // Create an static account wallet and get its address
        address account = staticOpenfortAccountFactory.createAccount(accountAdmin, "");

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        // Make the admin of the static account wallet (deployer) call "count"
        vm.prank(accountAdmin);
        StaticOpenfortAccount(payable(account)).execute(address(testCounter), 0, abi.encodeWithSignature("count()"));

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Create an account by directly calling the factory and make it call count()
     * using the execute() function using the EntryPoint (userOp). Leaveraging ERC-4337.
     */
    function testCreateAccountTestCounterViaEntrypoint() public {
        // Create an static account wallet and get its address
        address account = staticOpenfortAccountFactory.createAccount(accountAdmin, "");

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

    /*
     * Create an account by directly calling the factory and make it call count()
     * using the executeBatching() function using the EntryPoint (userOp). Leaveraging ERC-4337.
     */
    function testCreateAccountTestCounterViaEntrypointBatching() public {
        // Create an static account wallet and get its address
        address account = staticOpenfortAccountFactory.createAccount(accountAdmin, "");

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

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

    /*
     *  Should fail, try to use a sessionKey that is not registered.
     */
    function testFailCreateAccountTestCounterViaSessionKeyNotregistered() public {
        // Create an static account wallet and get its address
        address account = staticOpenfortAccountFactory.createAccount(accountAdmin, "");

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        UserOperation[] memory userOp = _setupUserOpExecute(
            account,
            sessionKeyPrivKey,
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

    /*
     * Use a sessionKey that is registered.
     */
    function testCreateAccountTestCounterViaSessionKey() public {
        // Create an static account wallet and get its address
        address account = staticOpenfortAccountFactory.createAccount(accountAdmin, "");

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        vm.prank(accountAdmin);
        StaticOpenfortAccount(payable(account)).registerSessionKey(sessionKey , 0, 2**48 - 1);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account,
            sessionKeyPrivKey,
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

    /*
     *  Should fail, try to use a sessionKey that is expired.
     */
    function testFailCreateAccountTestCounterViaSessionKeyExpired() public {
        // Create an static account wallet and get its address
        address account = staticOpenfortAccountFactory.createAccount(accountAdmin, "");

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        vm.prank(accountAdmin);
        StaticOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 0);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account,
            sessionKeyPrivKey,
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

    /*
     *  Should fail, try to use a sessionKey that is revoked.
     */
    function testFailCreateAccountTestCounterViaSessionKeyRevoked() public {
        // Create an static account wallet and get its address
        address account = staticOpenfortAccountFactory.createAccount(accountAdmin, "");

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        vm.prank(accountAdmin);
        StaticOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 0);
        StaticOpenfortAccount(payable(account)).revokeSessionKey(sessionKey);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account,
            sessionKeyPrivKey,
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

    /*
     *  Should fail, try to revoke a sessionKey using a non-privileged user
     */
    function testFailRevokeSessionKeyInvalidUser() public {
        // Create an static account wallet and get its address
        address account = staticOpenfortAccountFactory.createAccount(accountAdmin, "");

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        vm.prank(accountAdmin);
        StaticOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 0);
        vm.prank(beneficiary);
        StaticOpenfortAccount(payable(account)).revokeSessionKey(sessionKey);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account,
            sessionKeyPrivKey,
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

    /*
     * Test account creation using nonces
     */
    function testCreateAccountWithNonce() public {
        // Create an static account wallet and get its address
        address account = staticOpenfortAccountFactory.createAccount(accountAdmin, "");
        address account2 = staticOpenfortAccountFactory.createAccount(accountAdmin, "");

        // Verifiy that createAccount() always generate the same address when used with the same admin
        assertEq(account, account2);

        // Create a new account with accountAdmin using a nonce
        account2 = staticOpenfortAccountFactory.createAccountWithNonce(accountAdmin, "", 0);

        // Verifiy that the new account is indeed different now
        assertNotEq(account, account2);
    }
}
