// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test, console} from "lib/forge-std/src/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {EntryPoint, UserOperation} from "account-abstraction/core/EntryPoint.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";
import {TestToken} from "account-abstraction/test/TestToken.sol";
import {RecoverableOpenfortAccount} from "contracts/core/recoverable/RecoverableOpenfortAccount.sol";
import {RecoverableOpenfortFactory} from "contracts/core/recoverable/RecoverableOpenfortFactory.sol";
import {OpenfortRecoverableProxy} from "contracts/core/recoverable/OpenfortRecoverableProxy.sol";

contract RecoverableOpenfortAccountTest is Test {
    using ECDSA for bytes32;

    EntryPoint public entryPoint;
    RecoverableOpenfortAccount public recoverableOpenfortAccountImpl;
    RecoverableOpenfortFactory public recoverableOpenfortFactory;
    address public account;
    TestCounter public testCounter;
    TestToken public testToken;

    // Testing addresses
    address private factoryAdmin;
    uint256 private factoryAdminPKey;

    address private accountAdmin;
    uint256 private accountAdminPKey;

    address payable private beneficiary = payable(makeAddr("beneficiary"));

    uint256 private constant RECOVERY_PERIOD = 36;
    uint256 private constant SECURITY_PERIOD = 24;
    uint256 private constant SECURITY_WINDOW = 12;
    uint256 private constant LOCK_PERIOD = 50;
    address private OPENFORT_GUARDIAN;
    uint256 private OPENFORT_GUARDIAN_PKEY;

    event AccountCreated(address indexed account, address indexed accountAdmin);
    event GuardianProposed(address indexed guardian, uint256 executeAfter);
    event GuardianProposalCancelled(address indexed guardian);
    event GuardianRevocationRequested(address indexed guardian, uint256 executeAfter);
    event GuardianRevocationCancelled(address indexed guardian);

    error ZeroAddressNotAllowed();
    error AccountLocked();
    error AccountNotLocked();
    error MustBeGuardian();
    error DuplicatedGuardian();
    error GuardianCannotBeOwner();
    error NoOngoingRecovery();
    error OngoingRecovery();
    error InvalidRecoverySignatures();

    // keccak256("Recover(address recoveryAddress,uint64 executeAfter,uint32 guardianCount"));
    bytes32 RECOVER_TYPEHASH = 0x601b3fa0ae18d2a4c446b40cd6b8e0e911bbbb5dd66b248922e3d91efafa0969;

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
    ) internal returns (UserOperation[] memory) {
        bytes memory callDataForEntrypoint =
            abi.encodeWithSignature("executeBatch(address[],uint256[],bytes[])", _target, _value, _callData);

        return _setupUserOp(sender, _signerPKey, _initCode, callDataForEntrypoint);
    }

    /**
     * @notice Initialize the RecoverableOpenfortAccount testing contract.
     * Scenario:
     * - factoryAdmin is the deployer (and owner) of the RecoverableOpenfortFactory
     * - accountAdmin is the account used to deploy new upgradeable accounts
     * - entryPoint is the singleton EntryPoint
     * - testCounter is the counter used to test userOps
     */
    function setUp() public {
        // Setup and fund signers
        (factoryAdmin, factoryAdminPKey) = makeAddrAndKey("factoryAdmin");
        vm.deal(factoryAdmin, 100 ether);
        (accountAdmin, accountAdminPKey) = makeAddrAndKey("accountAdmin");
        vm.deal(accountAdmin, 100 ether);

        vm.startPrank(factoryAdmin);
        // If we are in a fork
        if (vm.envAddress("ENTRY_POINT_ADDRESS").code.length > 0) {
            entryPoint = EntryPoint(payable(vm.envAddress("ENTRY_POINT_ADDRESS")));
        }
        // If not a fork, deploy entryPoint (at correct address)
        else {
            EntryPoint entryPoint_aux = new EntryPoint();
            bytes memory code = address(entryPoint_aux).code;
            address targetAddr = address(vm.envAddress("ENTRY_POINT_ADDRESS"));
            vm.etch(targetAddr, code);
            entryPoint = EntryPoint(payable(targetAddr));
        }
        (OPENFORT_GUARDIAN, OPENFORT_GUARDIAN_PKEY) = makeAddrAndKey("OPENFORT_GUARDIAN");
        // deploy upgradeable account implementation
        recoverableOpenfortAccountImpl = new RecoverableOpenfortAccount();
        // deploy upgradeable account factory
        recoverableOpenfortFactory = new RecoverableOpenfortFactory(
            payable(address(entryPoint)), 
            address(recoverableOpenfortAccountImpl),
            RECOVERY_PERIOD,
            SECURITY_PERIOD,
            SECURITY_WINDOW,
            LOCK_PERIOD,
            OPENFORT_GUARDIAN
        );

        // Create an upgradeable account wallet and get its address
        account = recoverableOpenfortFactory.createAccountWithNonce(accountAdmin, "1");

        // deploy a new TestCounter
        testCounter = new TestCounter();
        // deploy a new TestToken (ERC20)
        testToken = new TestToken();
        vm.stopPrank();
    }

    function testCreateWrongFactory() public {
        vm.expectRevert(ZeroAddressNotAllowed.selector);
        vm.prank(factoryAdmin);
        recoverableOpenfortFactory = new RecoverableOpenfortFactory(
            payable(address(entryPoint)), 
            address(0),
            RECOVERY_PERIOD,
            SECURITY_PERIOD,
            SECURITY_WINDOW,
            LOCK_PERIOD,
            OPENFORT_GUARDIAN
        );
    }

    function testCreateWrongAccount() public {
        vm.expectRevert(ZeroAddressNotAllowed.selector);
        vm.prank(accountAdmin);
        account = address(
            new OpenfortRecoverableProxy{salt: 0}(
                address(recoverableOpenfortAccountImpl),
                abi.encodeCall(
                    RecoverableOpenfortAccount.initialize,
                    (
                        address(0x0),
                        address(entryPoint),
                        RECOVERY_PERIOD,
                        SECURITY_PERIOD,
                        SECURITY_WINDOW,
                        LOCK_PERIOD,
                        OPENFORT_GUARDIAN)
                    )
                )
        );
    }

    /*
     * Create an account by directly calling the factory.
     */
    function testCreateAccountWithNonceViaFactory() public {
        // Get the counterfactual address
        vm.prank(factoryAdmin);
        address accountAddress2 = recoverableOpenfortFactory.getAddressWithNonce(accountAdmin, "2");

        // Expect that we will see an event containing the account and admin
        vm.expectEmit(true, true, false, true);
        emit AccountCreated(accountAddress2, accountAdmin);

        // Deploy a upgradeable account to the counterfactual address
        vm.prank(factoryAdmin);
        recoverableOpenfortFactory.createAccountWithNonce(accountAdmin, "2");

        // Calling it again should just return the address and not create another account
        vm.prank(factoryAdmin);
        recoverableOpenfortFactory.createAccountWithNonce(accountAdmin, "2");

        // Make sure the counterfactual address has not been altered
        vm.prank(factoryAdmin);
        assertEq(accountAddress2, recoverableOpenfortFactory.getAddressWithNonce(accountAdmin, "2"));
    }

    /*
     * Create an account calling the factory via EntryPoint.
     * Use initCode
     */
    function testCreateAccountViaEntryPoint() public {
        // It is not correct to use the Factory using the EntryPoint anymore
        // Accounts created using factories are depend on msg.sender now
        // revert();

        // Make sure the smart account does not have any code yet
        address account2 = recoverableOpenfortFactory.getAddressWithNonce(accountAdmin, bytes32("2"));
        assertEq(account2.code.length, 0);

        bytes memory initCallData =
            abi.encodeWithSignature("createAccountWithNonce(address,bytes32)", accountAdmin, bytes32("2"));
        bytes memory initCode = abi.encodePacked(abi.encodePacked(address(recoverableOpenfortFactory)), initCallData);

        UserOperation[] memory userOpCreateAccount =
            _setupUserOpExecute(account2, accountAdminPKey, initCode, address(0), 0, bytes(""));

        // Expect that we will see an event containing the account and admin
        vm.expectEmit(true, true, false, true);
        emit AccountCreated(account2, accountAdmin);

        entryPoint.handleOps(userOpCreateAccount, beneficiary);

        // Make sure the smart account does have some code now
        assert(account2.code.length > 0);

        // Make sure the counterfactual address has not been altered
        assertEq(account2, recoverableOpenfortFactory.getAddressWithNonce(accountAdmin, bytes32("2")));
    }

    /*
     * Create an account using the factory and make it call count() directly.
     */
    function testIncrementCounterDirect() public {
        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        // Make the admin of the upgradeable account wallet (deployer) call "count"
        vm.prank(accountAdmin);
        RecoverableOpenfortAccount(payable(account)).execute(
            address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Create an account by directly calling the factory and make it call count()
     * using the execute() function using the EntryPoint (userOp). Leaveraging ERC-4337.
     */
    function testIncrementCounterViaEntrypoint() public {
        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, accountAdminPKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Create an account by directly calling the factory and make it call count()
     * using the executeBatching() function using the EntryPoint (userOp). Leaveraging ERC-4337.
     */
    function testIncrementCounterViaEntrypointBatching() public {
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

        UserOperation[] memory userOp =
            _setupUserOpExecuteBatch(account, accountAdminPKey, bytes(""), targets, values, callData);

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 3);
    }

    /*
     *  Should fail, try to use a sessionKey that is not registered.
     */
    function testFailIncrementCounterViaSessionKeyNotregistered() public {
        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has not increased
        assertEq(testCounter.counters(account), 0);
    }

    /*
     * Use a sessionKey that is registered.
     */
    function testIncrementCounterViaSessionKey() public {
        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        vm.prank(accountAdmin);
        RecoverableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Register a sessionKey via userOp calling the execute() function
     * using the EntryPoint (userOp). Then use the sessionKey to count
     */
    function testRegisterSessionKeyViaEntrypoint() public {
        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        UserOperation[] memory userOp = _setupUserOpExecute(
            account,
            accountAdminPKey,
            bytes(""),
            account,
            0,
            abi.encodeWithSignature("registerSessionKey(address,uint48,uint48)", sessionKey, 0, 2 ** 48 - 1)
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has not increased
        assertEq(testCounter.counters(account), 0);

        userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Register a master sessionKey via userOp calling the execute() function
     * using the EntryPoint (userOp). Then use that sessionKey to register a second one
     */
    function testRegisterSessionKeyViaEntrypoint2ndKey() public {
        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        UserOperation[] memory userOp = _setupUserOpExecute(
            account,
            accountAdminPKey,
            bytes(""),
            account,
            0,
            abi.encodeWithSignature("registerSessionKey(address,uint48,uint48)", sessionKey, 0, 2 ** 48 - 1)
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has not increased
        assertEq(testCounter.counters(account), 0);

        userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);

        address sessionKeyAttack;
        uint256 sessionKeyPrivKeyAttack;
        (sessionKeyAttack, sessionKeyPrivKeyAttack) = makeAddrAndKey("sessionKeyAttack");

        userOp = _setupUserOpExecute(
            account,
            sessionKeyPrivKey,
            bytes(""),
            account,
            0,
            abi.encodeWithSignature("registerSessionKey(address,uint48,uint48)", sessionKeyAttack, 0, 2 ** 48 - 1)
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);
    }

    /*
     * Register a limited sessionKey via userOp calling the execute() function
     * using the EntryPoint (userOp). Then use that sessionKey to register a second one
     */
    function testFailAttackRegisterSessionKeyViaEntrypoint2ndKey() public {
        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        UserOperation[] memory userOp = _setupUserOpExecute(
            account,
            accountAdminPKey,
            bytes(""),
            account,
            0,
            abi.encodeWithSignature("registerSessionKey(address,uint48,uint48,uint48)", sessionKey, 0, 2 ** 48 - 1, 10)
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has not increased
        assertEq(testCounter.counters(account), 0);

        userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);

        // Verify that the registered key is not a MasterKey nor has whitelisting
        bool isMasterKey;
        bool isWhitelisted;
        (,,, isMasterKey, isWhitelisted) = RecoverableOpenfortAccount(payable(account)).sessionKeys(sessionKey);
        assert(!isMasterKey);
        assert(!isWhitelisted);

        address sessionKeyAttack;
        uint256 sessionKeyPrivKeyAttack;
        (sessionKeyAttack, sessionKeyPrivKeyAttack) = makeAddrAndKey("sessionKeyAttack");

        userOp = _setupUserOpExecute(
            account,
            sessionKeyPrivKey,
            bytes(""),
            account,
            0,
            abi.encodeWithSignature("registerSessionKey(address,uint48,uint48)", sessionKeyAttack, 0, 2 ** 48 - 1)
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);
    }

    /*
     *  Should fail, try to use a sessionKey that is expired.
     */
    function testIncrementCounterViaSessionKeyExpired() public {
        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        vm.warp(100);
        vm.prank(accountAdmin);
        RecoverableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 99);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        vm.expectRevert();
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has not increased
        assertEq(testCounter.counters(account), 0);
    }

    /*
     *  Should fail, try to use a sessionKey that is revoked.
     */
    function testFailIncrementCounterViaSessionKeyRevoked() public {
        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        vm.prank(accountAdmin);
        RecoverableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 0);
        RecoverableOpenfortAccount(payable(account)).revokeSessionKey(sessionKey);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     *  Should fail, try to use a sessionKey that reached its limit.
     */
    function testFailIncrementCounterViaSessionKeyReachLimit() public {
        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        // We are now in block 100, but our session key is valid until block 150
        vm.warp(100);
        vm.prank(accountAdmin);
        RecoverableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 150, 1);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has only increased by one
        assertEq(testCounter.counters(account), 1);
    }

    /*
     *  Should fail, try to use a sessionKey that reached its limit.
     */
    function testFailIncrementCounterViaSessionKeyReachLimitBatching() public {
        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        // We are now in block 100, but our session key is valid until block 150
        vm.warp(100);
        vm.prank(accountAdmin);
        RecoverableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 150, 2);

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
            _setupUserOpExecuteBatch(account, sessionKeyPrivKey, bytes(""), targets, values, callData);

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has not increased
        assertEq(testCounter.counters(account), 0);
    }

    /*
     *  Should fail, try to revoke a sessionKey using a non-privileged user
     */
    function testFailRevokeSessionKeyInvalidUser() public {
        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        vm.prank(accountAdmin);
        RecoverableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 0);
        vm.prank(beneficiary);
        RecoverableOpenfortAccount(payable(account)).revokeSessionKey(sessionKey);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Use a sessionKey with whitelisting to call Execute().
     */
    function testIncrementCounterViaSessionKeyWhitelisting() public {
        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        address[] memory whitelist = new address[](1);
        whitelist[0] = address(testCounter);
        vm.prank(accountAdmin);
        RecoverableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1, 1, whitelist);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Should fail, try to register a sessionKey with a large whitelist.
     */
    function testFailIncrementCounterViaSessionKeyWhitelistingTooBig() public {
        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        address[] memory whitelist = new address[](11);
        vm.prank(accountAdmin);
        RecoverableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1, 1, whitelist);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has not increased
        assertEq(testCounter.counters(account), 0);
    }

    /*
     * Use a sessionKey with whitelisting to call ExecuteBatch().
     */
    function testIncrementCounterViaSessionKeyWhitelistingBatch() public {
        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        address[] memory whitelist = new address[](1);
        whitelist[0] = address(testCounter);
        vm.prank(accountAdmin);
        RecoverableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1, 3, whitelist);

        // Verify that the registered key is not a MasterKey but has whitelisting
        bool isMasterKey;
        bool isWhitelisted;
        (,,, isMasterKey, isWhitelisted) = RecoverableOpenfortAccount(payable(account)).sessionKeys(sessionKey);
        assert(!isMasterKey);
        assert(isWhitelisted);

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
            _setupUserOpExecuteBatch(account, sessionKeyPrivKey, bytes(""), targets, values, callData);

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 3);
    }

    /*
     * Should fail, try to use a sessionKey with invalid whitelisting to call Execute().
     */
    function testFailIncrementCounterViaSessionKeyWhitelistingWrongAddress() public {
        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        address[] memory whitelist = new address[](1);
        whitelist[0] = address(account);
        vm.prank(accountAdmin);
        RecoverableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1, 1, whitelist);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Should fail, try to use a sessionKey with invalid whitelisting to call ExecuteBatch().
     */
    function testFailIncrementCounterViaSessionKeyWhitelistingBatchWrongAddress() public {
        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        address[] memory whitelist = new address[](1);
        whitelist[0] = address(account);
        vm.prank(accountAdmin);
        RecoverableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1, 1, whitelist);

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
            sessionKeyPrivKey, //Sign the userOp using the sessionKey's private key
            bytes(""),
            targets,
            values,
            callData
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has not increased
        assertEq(testCounter.counters(account), 0);
    }

    /*
     * Change the owner of an account and call TestCounter directly.
     * Important use-case:
     * 1- accountAdmin is Openfort's master wallet and is managing the account of the user.
     * 2- The user claims the ownership of the account to Openfort so Openfort calls
     * transferOwnership() to the account.
     * 3- The user has to "officially" claim the ownership of the account by directly
     * interacting with the smart contract using the acceptOwnership() function.
     * 4- From now on, the user is the owner of the account and can register and revoke session keys themselves.
     * 5- Test that the new owner can directly interact with the account and make it call the testCounter contract.
     */
    function testChangeOwnershipAndCountDirect() public {
        address accountAdmin2;
        uint256 accountAdmin2PKey;
        (accountAdmin2, accountAdmin2PKey) = makeAddrAndKey("accountAdmin2");

        vm.prank(accountAdmin);
        RecoverableOpenfortAccount(payable(account)).transferOwnership(accountAdmin2);
        vm.prank(accountAdmin2);
        RecoverableOpenfortAccount(payable(account)).acceptOwnership();

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        // Make the admin of the upgradeable account wallet (deployer) call "count"
        vm.prank(accountAdmin2);
        RecoverableOpenfortAccount(payable(account)).execute(
            address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Change the owner of an account and call TestCounter though the Entrypoint
     */
    function testChangeOwnershipAndCountEntryPoint() public {
        address accountAdmin2;
        uint256 accountAdmin2PKey;
        (accountAdmin2, accountAdmin2PKey) = makeAddrAndKey("accountAdmin2");

        vm.prank(accountAdmin);
        RecoverableOpenfortAccount(payable(account)).transferOwnership(accountAdmin2);
        vm.prank(accountAdmin2);
        RecoverableOpenfortAccount(payable(account)).acceptOwnership();

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, accountAdmin2PKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Test an account with testToken instead of TestCount.
     */
    function testMintTokenAccount() public {
        // Verifiy that the totalSupply is stil 0
        assertEq(testToken.totalSupply(), 0);

        // Mint 1 to beneficiary
        testToken.mint(beneficiary, 1);
        assertEq(testToken.totalSupply(), 1);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account,
            accountAdminPKey,
            bytes(""),
            address(testToken),
            0,
            abi.encodeWithSignature("mint(address,uint256)", beneficiary, 1)
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the totalSupply has increased
        assertEq(testToken.totalSupply(), 2);
    }

    /*
     * Test receive native tokens.
     */
    function testReceiveNativeToken() public {
        assertEq(address(account).balance, 0);

        vm.prank(accountAdmin);
        (bool success,) = payable(account).call{value: 1000}("");
        assert(success);
        assertEq(address(account).balance, 1000);
    }

    /*
     * Transfer native tokens out of an account.
     */
    function testTransferOutNativeToken() public {
        uint256 value = 1000;

        assertEq(address(account).balance, 0);
        vm.prank(accountAdmin);
        (bool success,) = payable(account).call{value: value}("");
        assertEq(address(account).balance, value);
        assert(success);
        assertEq(beneficiary.balance, 0);

        UserOperation[] memory userOp =
            _setupUserOpExecute(account, accountAdminPKey, bytes(""), address(beneficiary), value, bytes(""));

        EntryPoint(entryPoint).handleOps(userOp, beneficiary);
        assertEq(beneficiary.balance, value);
    }

    /*
     * Basic test of simulateValidation() to check that it always reverts.
     */
    function testSimulateValidation() public {
        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, accountAdminPKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        // Expect the simulateValidation() to always revert
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);

        // Verifiy that the counter has not increased
        assertEq(testCounter.counters(account), 0);
    }

    // /*
    //  * Create an account and upgrade its implementation
    //  */
    // function testUpgradeAccount() public {
    //     assertEq(RecoverableOpenfortAccount(payable(account)).version(), 1);
    //     MockedV2RecoverableOpenfortAccount newAccountImplementation = new MockedV2RecoverableOpenfortAccount();
    //     OpenfortUpgradeableProxy p = OpenfortUpgradeableProxy(payable(account));
    //     // Printing account address and the implementation address
    //     console.log(account);
    //     console.log(p.implementation());

    //     vm.expectRevert("Ownable: caller is not the owner");
    //     RecoverableOpenfortAccount(payable(account)).upgradeTo(address(newAccountImplementation));

    //     vm.prank(accountAdmin);
    //     RecoverableOpenfortAccount(payable(account)).upgradeTo(address(newAccountImplementation));

    //     // Notice that, even though we bind the address to the old implementation, version() now returns 2
    //     assertEq(RecoverableOpenfortAccount(payable(account)).version(), 2);

    //     // Printing account address and the implementation address. Impl address should have changed
    //     console.log(account);
    //     console.log(p.implementation());
    // }

    /*
     * 1- Deploy a factory using the old EntryPoint to create an account.
     * 2- Inform the account of the new EntryPoint by calling updateEntryPoint()
     */
    function testUpdateEntryPoint() public {
        address oldEntryPoint = address(0x0576a174D229E3cFA37253523E645A78A0C91B57);
        address newEntryPoint = vm.envAddress("ENTRY_POINT_ADDRESS");
        RecoverableOpenfortFactory recoverableOpenfortFactoryOld = new RecoverableOpenfortFactory(
            payable(oldEntryPoint),
            address(recoverableOpenfortAccountImpl),
            RECOVERY_PERIOD,
            SECURITY_PERIOD,
            SECURITY_WINDOW,
            LOCK_PERIOD,
            OPENFORT_GUARDIAN
        );

        // Create an upgradeable account wallet using the old EntryPoint and get its address
        address payable accountOld = payable(recoverableOpenfortFactoryOld.createAccountWithNonce(accountAdmin, "999"));
        RecoverableOpenfortAccount upgradeableAccount = RecoverableOpenfortAccount(accountOld);
        assertEq(address(upgradeableAccount.entryPoint()), oldEntryPoint);

        vm.expectRevert("Ownable: caller is not the owner");
        upgradeableAccount.updateEntryPoint(newEntryPoint);

        vm.expectRevert(ZeroAddressNotAllowed.selector);
        vm.prank(accountAdmin);
        upgradeableAccount.updateEntryPoint(address(0));

        vm.prank(accountAdmin);
        upgradeableAccount.updateEntryPoint(newEntryPoint);

        assertEq(address(upgradeableAccount.entryPoint()), newEntryPoint);
    }

    /**
     * Lock tests *
     */

    /*
     * Test locking the Openfort account using the default guardian.
     */
    function testLockAccount() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        assertEq(recoverableOpenfortAccount.isLocked(), false);
        assertEq(recoverableOpenfortAccount.getLock(), 0);

        vm.expectRevert(MustBeGuardian.selector);
        recoverableOpenfortAccount.lock();

        vm.prank(OPENFORT_GUARDIAN);
        recoverableOpenfortAccount.lock();

        assertEq(recoverableOpenfortAccount.isLocked(), true);
        assertEq(recoverableOpenfortAccount.getLock(), LOCK_PERIOD + 1);

        vm.expectRevert(AccountLocked.selector);
        vm.prank(OPENFORT_GUARDIAN);
        recoverableOpenfortAccount.lock();

        // Automatically unlock
        skip(LOCK_PERIOD + 1);
        assertEq(recoverableOpenfortAccount.isLocked(), false);
        assertEq(recoverableOpenfortAccount.getLock(), 0);
    }

    /*
     * Test unlocking the Openfort account using the default guardian.
     */
    function testUnlockAccount() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        assertEq(recoverableOpenfortAccount.isLocked(), false);
        assertEq(recoverableOpenfortAccount.getLock(), 0);

        vm.expectRevert(MustBeGuardian.selector);
        recoverableOpenfortAccount.lock();

        vm.prank(OPENFORT_GUARDIAN);
        recoverableOpenfortAccount.lock();

        assertEq(recoverableOpenfortAccount.isLocked(), true);
        assertEq(recoverableOpenfortAccount.getLock(), LOCK_PERIOD + 1);

        skip(LOCK_PERIOD / 2);

        vm.expectRevert(MustBeGuardian.selector);
        recoverableOpenfortAccount.unlock();
        assertEq(recoverableOpenfortAccount.isLocked(), true);

        vm.prank(OPENFORT_GUARDIAN);
        recoverableOpenfortAccount.unlock();

        assertEq(recoverableOpenfortAccount.isLocked(), false);
        assertEq(recoverableOpenfortAccount.getLock(), 0);

        vm.expectRevert(AccountNotLocked.selector);
        vm.prank(OPENFORT_GUARDIAN);
        recoverableOpenfortAccount.unlock();
    }

    /**
     * Add guardians tests *
     */

    /*
     * Test proposing a guardian (by the owner) and accepting it (by the owner).
     * Successfully propose a guardian and confirm it after SECURITY_PERIOD
     */
    function testAddEOAGuardian() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        recoverableOpenfortAccount.getGuardians();

        // Verify that the number of guardians is 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);

        // Create a friend EOA
        address friendAccount = makeAddr("friend");

        // Trying to proposa a guardian not using the owner
        vm.expectRevert("Ownable: caller is not the owner");
        recoverableOpenfortAccount.proposeGuardian(friendAccount);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.proposeGuardian(friendAccount);

        // Verify that the number of guardians is still 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);

        // Friend account should not be a guardian yet
        assertEq(recoverableOpenfortAccount.isGuardian(friendAccount), false);

        // Test if zero address is a guardian
        assertEq(recoverableOpenfortAccount.isGuardian(address(0)), false);

        skip(1);

        vm.expectRevert("Pending proposal not over");
        recoverableOpenfortAccount.confirmGuardianProposal(friendAccount);

        skip(SECURITY_PERIOD);
        recoverableOpenfortAccount.confirmGuardianProposal(friendAccount);

        // Verify that the number of guardians is now 2
        assertEq(recoverableOpenfortAccount.guardianCount(), 2);

        // Friend account should be a guardian now
        assertEq(recoverableOpenfortAccount.isGuardian(friendAccount), true);
    }

    /*
     * Test proposing a guardian, but its proposal expires before accepting.
     * An expired proposal cannot be accepted. A proposal expires after SECURITY_PERIOD and SECURITY_WINDOW.
     */
    function testAddEOAGuardianExpired() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        // Verify that the number of guardians is 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);

        // Create a friend EOA
        address friendAccount = makeAddr("friend");

        // Trying to proposa a guardian not using the owner
        vm.expectRevert("Ownable: caller is not the owner");
        recoverableOpenfortAccount.proposeGuardian(friendAccount);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.proposeGuardian(friendAccount);

        // Verify that the number of guardians is still 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);

        // Friend account should not be a guardian yet
        assertEq(recoverableOpenfortAccount.isGuardian(friendAccount), false);

        skip(1);

        vm.expectRevert("Pending proposal not over");
        recoverableOpenfortAccount.confirmGuardianProposal(friendAccount);

        skip(SECURITY_PERIOD + SECURITY_WINDOW);
        vm.expectRevert("Pending proposal expired");
        recoverableOpenfortAccount.confirmGuardianProposal(friendAccount);

        // Verify that the number of guardians is still 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);

        // Friend account should not be a guardian yet
        assertEq(recoverableOpenfortAccount.isGuardian(friendAccount), false);
    }

    /*
     * Test proposing a guardian, but its proposal expires before accepting. Re-add again
     * An expired proposal cannot be accepted. A proposal expires after SECURITY_PERIOD and SECURITY_WINDOW.
     */
    function testAddEOAGuardianExpiredThenReAdd() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        // Verify that the number of guardians is 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);

        // Create a friend EOA
        address friendAccount = makeAddr("friend");

        // Trying to proposa a guardian not using the owner
        vm.expectRevert("Ownable: caller is not the owner");
        recoverableOpenfortAccount.proposeGuardian(friendAccount);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.proposeGuardian(friendAccount);

        // Verify that the number of guardians is still 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);

        // Friend account should not be a guardian yet
        assertEq(recoverableOpenfortAccount.isGuardian(friendAccount), false);

        skip(1);

        vm.expectRevert("Pending proposal not over");
        recoverableOpenfortAccount.confirmGuardianProposal(friendAccount);

        skip(SECURITY_PERIOD + SECURITY_WINDOW);
        vm.expectRevert("Pending proposal expired");
        recoverableOpenfortAccount.confirmGuardianProposal(friendAccount);

        // Verify that the number of guardians is still 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);

        // Friend account should not be a guardian yet
        assertEq(recoverableOpenfortAccount.isGuardian(friendAccount), false);

        /* Let's try it again (re-add) */
        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.proposeGuardian(friendAccount);

        // Verify that the number of guardians is still 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);

        // Friend account should not be a guardian yet
        assertEq(recoverableOpenfortAccount.isGuardian(friendAccount), false);

        skip(1);
        skip(SECURITY_PERIOD);
        recoverableOpenfortAccount.confirmGuardianProposal(friendAccount);

        // Verify that the number of guardians is now 2
        assertEq(recoverableOpenfortAccount.guardianCount(), 2);

        // Friend account should not be a guardian yet
        assertEq(recoverableOpenfortAccount.isGuardian(friendAccount), true);
    }

    /*
     * Test proposing a guardian twice. Make sure a new proposal is not created and the original still works.
     * An expired proposal cannot be accepted. A proposal expires after SECURITY_PERIOD and SECURITY_WINDOW.
     */
    function testAddEOAGuardianDuplicatedPorposal() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        // Verify that the number of guardians is 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);

        // Create a friend EOA
        address friendAccount = makeAddr("friend");

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.proposeGuardian(friendAccount);

        // Verify that the number of guardians is still 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);

        // Friend account should not be a guardian yet
        assertEq(recoverableOpenfortAccount.isGuardian(friendAccount), false);

        skip(1);

        vm.expectRevert();
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.proposeGuardian(friendAccount);

        // Now let's check that, even after the revert, it is possible to confirm the proposal (no DoS)
        skip(SECURITY_PERIOD);
        recoverableOpenfortAccount.confirmGuardianProposal(friendAccount);

        // Verify that the number of guardians is now 2
        assertEq(recoverableOpenfortAccount.guardianCount(), 2);

        // Friend account should not be a guardian yet
        assertEq(recoverableOpenfortAccount.isGuardian(friendAccount), true);
    }

    /*
     * Test proposing a guardian and cancel its proposal before accepting or expiring
     * Only the owner can cancel an ongoing proposal.
     */
    function testAddEOAGuardianCancel() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        // Verify that the number of guardians is 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);

        // Create a friend EOA
        address friendAccount = makeAddr("friend");

        // Trying to proposa a guardian not using the owner
        vm.expectRevert("Ownable: caller is not the owner");
        recoverableOpenfortAccount.proposeGuardian(friendAccount);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.proposeGuardian(friendAccount);

        // Verify that the number of guardians is still 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);
        // Friend account should not be a guardian yet
        assertEq(recoverableOpenfortAccount.isGuardian(friendAccount), false);

        skip(1);
        vm.expectRevert("Pending proposal not over");
        recoverableOpenfortAccount.confirmGuardianProposal(friendAccount);

        skip(SECURITY_PERIOD);
        vm.expectRevert("Ownable: caller is not the owner");
        recoverableOpenfortAccount.cancelGuardianProposal(friendAccount);

        vm.expectEmit(true, true, false, true);
        emit GuardianProposalCancelled(friendAccount);
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.cancelGuardianProposal(friendAccount);

        // Verify that the number of guardians is still 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);
        // Friend account should not be a guardian yet
        assertEq(recoverableOpenfortAccount.isGuardian(friendAccount), false);

        vm.prank(accountAdmin);
        vm.expectRevert("Unknown pending proposal");
        recoverableOpenfortAccount.confirmGuardianProposal(friendAccount);

        // Verify that the number of guardians is still 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);
        // Friend account should not be a guardian yet
        assertEq(recoverableOpenfortAccount.isGuardian(friendAccount), false);
    }

    /*
     * Test proposing owner as guardian. It should revert.
     * Successfully propose a guardian and confirm it after SECURITY_PERIOD
     */
    function testAddOwnerAsGuardianNotAllowed() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        recoverableOpenfortAccount.getGuardians();

        // Verify that the number of guardians is 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);

        // Expect revert because the owner cannot be proposed as guardian
        vm.expectRevert();
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.proposeGuardian(accountAdmin);

        // Verify that the number of guardians is still 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);

        // Owner account should not be a guardian yet
        assertEq(recoverableOpenfortAccount.isGuardian(accountAdmin), false);

        // Expect revert because the default guardian cannot be proposed again
        vm.expectRevert(DuplicatedGuardian.selector);
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.proposeGuardian(OPENFORT_GUARDIAN);

        // Verify that the number of guardians is still 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);

        // OPENFORT_GUARDIAN account should stil be a guardian
        assertEq(recoverableOpenfortAccount.isGuardian(OPENFORT_GUARDIAN), true);
    }

    /*
     * Test proposing multiple guardians (by the owner) and accepting them afterwards (by the owner).
     * Successfully propose guardians and confirm them after SECURITY_PERIOD
     */
    function testAddMultipleEOAGuardians() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        recoverableOpenfortAccount.getGuardians();

        // Verify that the number of guardians is 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);

        // Create multiple friend EOAs
        address[] memory friends = new address[](5);
        friends[0] = makeAddr("friend");
        friends[1] = makeAddr("friend2");
        friends[2] = makeAddr("friend3");
        friends[3] = makeAddr("friend4");
        friends[4] = makeAddr("friend5");

        for (uint256 index = 0; index < friends.length; index++) {
            // Expect that we will see an event containing the friend account and security period
            vm.expectEmit(true, true, false, true);
            emit GuardianProposed(friends[index], block.timestamp + SECURITY_PERIOD);
            vm.prank(accountAdmin);
            recoverableOpenfortAccount.proposeGuardian(friends[index]);
        }

        // Verify that the number of guardians is still 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);
        // Friend account should not be a guardian yet
        assertEq(recoverableOpenfortAccount.isGuardian(friends[0]), false);

        skip(1);
        skip(SECURITY_PERIOD);

        for (uint256 index = 0; index < friends.length; index++) {
            recoverableOpenfortAccount.confirmGuardianProposal(friends[index]);
        }

        // Verify that the number of guardians is now 6
        assertEq(recoverableOpenfortAccount.guardianCount(), 6);

        // First friend account should be a guardian now
        assertEq(recoverableOpenfortAccount.isGuardian(friends[0]), true);
    }

    /**
     * Revoke guardians tests *
     */

    /*
     * Test revoking a guardian using owner.
     * Only the owner can revoke a guardian.
     */
    function testRevokeGuardian() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        // Verify that the number of guardians is 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);

        // Create a friend EOA
        address friendAccount = makeAddr("friend");

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.proposeGuardian(friendAccount);

        skip(1);
        skip(SECURITY_PERIOD);
        recoverableOpenfortAccount.confirmGuardianProposal(friendAccount);

        // Verify that the number of guardians is now 2
        assertEq(recoverableOpenfortAccount.guardianCount(), 2);

        // Friend account should be a guardian now
        assertEq(recoverableOpenfortAccount.isGuardian(friendAccount), true);

        // Trying to revoke a guardian not using the owner
        vm.expectRevert("Ownable: caller is not the owner");
        recoverableOpenfortAccount.revokeGuardian(friendAccount);

        // Trying to revoke a non-existen guardian (random beneficiary address)
        vm.expectRevert("Must be existing guardian");
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.revokeGuardian(beneficiary);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianRevocationRequested(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.revokeGuardian(friendAccount);

        // Anyone can confirm a revokation. However, the security period has not passed yet
        skip(1);
        vm.expectRevert("Pending revoke not over");
        recoverableOpenfortAccount.confirmGuardianRevocation(friendAccount);

        // Anyone can confirm a revokation after security period
        skip(SECURITY_PERIOD);
        recoverableOpenfortAccount.confirmGuardianRevocation(friendAccount);

        // Friend account is not a guardian anymore
        assertEq(recoverableOpenfortAccount.isGuardian(friendAccount), false);
        // Verify that the number of guardians is 1 again
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);
    }

    /*
     * Test revoking the default guardian when having registered another (custom) one.
     * Only the owner can revoke a guardian.
     */
    function testRevokeDefaultGuardian() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        recoverableOpenfortAccount.getGuardians();

        // Verify that the number of guardians is 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);

        // Create a friend EOA
        address friendAccount = makeAddr("friend");

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.proposeGuardian(friendAccount);

        skip(1);
        skip(SECURITY_PERIOD);
        recoverableOpenfortAccount.confirmGuardianProposal(friendAccount);

        // Verify that the number of guardians is now 2
        assertEq(recoverableOpenfortAccount.guardianCount(), 2);

        // Friend account should be a guardian now
        assertEq(recoverableOpenfortAccount.isGuardian(friendAccount), true);

        // Trying to revoke a guardian not using the owner
        vm.expectRevert("Ownable: caller is not the owner");
        recoverableOpenfortAccount.revokeGuardian(OPENFORT_GUARDIAN);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianRevocationRequested(OPENFORT_GUARDIAN, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.revokeGuardian(OPENFORT_GUARDIAN);

        // Anyone can confirm a revokation. However, the security period has not passed yet
        skip(1);
        vm.expectRevert("Pending revoke not over");
        recoverableOpenfortAccount.confirmGuardianRevocation(OPENFORT_GUARDIAN);

        // Anyone can confirm a revokation after security period
        skip(SECURITY_PERIOD);
        recoverableOpenfortAccount.confirmGuardianRevocation(OPENFORT_GUARDIAN);

        // Default account is not a guardian anymore
        assertEq(recoverableOpenfortAccount.isGuardian(OPENFORT_GUARDIAN), false);
        // Verify that the number of guardians is 1 again
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);
    }

    /*
     * Test revoking all guardians using owner.
     * Only the owner can revoke a guardian.
     */
    function testRevokeAllGuardians() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        // Verify that the number of guardians is 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);

        // Create a friend EOA
        address friendAccount = makeAddr("friend");

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.proposeGuardian(friendAccount);

        skip(1);
        skip(SECURITY_PERIOD);
        recoverableOpenfortAccount.confirmGuardianProposal(friendAccount);

        // Verify that the number of guardians is now 2
        assertEq(recoverableOpenfortAccount.guardianCount(), 2);

        // Friend account should be a guardian now
        assertEq(recoverableOpenfortAccount.isGuardian(friendAccount), true);

        // Trying to revoke a guardian not using the owner
        vm.expectRevert("Ownable: caller is not the owner");
        recoverableOpenfortAccount.revokeGuardian(friendAccount);

        // Trying to revoke a non-existen guardian (random beneficiary address)
        vm.expectRevert("Must be existing guardian");
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.revokeGuardian(beneficiary);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianRevocationRequested(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.revokeGuardian(friendAccount);

        // Anyone can confirm a revokation. However, the security period has not passed yet
        skip(1);
        vm.expectRevert("Pending revoke not over");
        recoverableOpenfortAccount.confirmGuardianRevocation(friendAccount);

        // Anyone can confirm a revokation after security period
        skip(SECURITY_PERIOD);
        recoverableOpenfortAccount.confirmGuardianRevocation(friendAccount);

        // Friend account is not a guardian anymore
        assertEq(recoverableOpenfortAccount.isGuardian(friendAccount), false);
        // Verify that the number of guardians is 1 again
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianRevocationRequested(OPENFORT_GUARDIAN, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.revokeGuardian(OPENFORT_GUARDIAN);

        // Anyone can confirm a revokation. However, the security period has not passed yet
        skip(1);
        vm.expectRevert("Pending revoke not over");
        recoverableOpenfortAccount.confirmGuardianRevocation(OPENFORT_GUARDIAN);

        // Anyone can confirm a revokation after security period
        skip(SECURITY_PERIOD);
        recoverableOpenfortAccount.confirmGuardianRevocation(OPENFORT_GUARDIAN);

        // Default account is not a guardian anymore
        assertEq(recoverableOpenfortAccount.isGuardian(OPENFORT_GUARDIAN), false);
        // Verify that the number of guardians is 1 again
        assertEq(recoverableOpenfortAccount.guardianCount(), 0);
    }

    /*
     * Test revoking a guardian, but its revocation expired before confirming.
     * An expired revocation cannot be confirmed. A revocation expires after SECURITY_PERIOD + SECURITY_WINDOW.
     */
    function testRevokeEOAGuardianExpired() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        // Verify that the number of guardians is 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);

        // Create a friend EOA
        address friendAccount = makeAddr("friend");

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.proposeGuardian(friendAccount);

        skip(1);
        skip(SECURITY_PERIOD);
        recoverableOpenfortAccount.confirmGuardianProposal(friendAccount);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianRevocationRequested(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.revokeGuardian(friendAccount);

        skip(1);
        skip(SECURITY_PERIOD + SECURITY_WINDOW);
        vm.expectRevert("Pending revoke expired");
        recoverableOpenfortAccount.confirmGuardianRevocation(friendAccount);

        // Verify that the number of guardians is still 2. No revocation took place
        assertEq(recoverableOpenfortAccount.guardianCount(), 2);

        // Friend account should still be a guardian
        assertEq(recoverableOpenfortAccount.isGuardian(friendAccount), true);
    }

    /*
     * Test revoking a guardian twice. Make sure a new revocation is not created and the original still works.
     * An expired revocation cannot be confirmed. A revocation expires after SECURITY_PERIOD and SECURITY_WINDOW.
     */
    function testRevokeEOAGuardianDuplicatedPorposal() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        // Verify that the number of guardians is 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);

        // Create a friend EOA
        address friendAccount = makeAddr("friend");

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.proposeGuardian(friendAccount);

        skip(1);
        skip(SECURITY_PERIOD);
        recoverableOpenfortAccount.confirmGuardianProposal(friendAccount);

        // Verify that the number of guardians is now 2
        assertEq(recoverableOpenfortAccount.guardianCount(), 2);
        // Friend account should now be a guardian
        assertEq(recoverableOpenfortAccount.isGuardian(friendAccount), true);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianRevocationRequested(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        // Now let's check that, even after the revert, it is possible to confirm the proposal (no DoS)
        recoverableOpenfortAccount.revokeGuardian(friendAccount);

        vm.expectRevert("Duplicate pending revoke");
        skip(1);
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.revokeGuardian(friendAccount);

        skip(SECURITY_PERIOD);
        recoverableOpenfortAccount.confirmGuardianRevocation(friendAccount);

        // Verify that the number of guardians is now 1
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);
        // Friend account should not be a guardian anymore
        assertEq(recoverableOpenfortAccount.isGuardian(friendAccount), false);
    }

    /*
     * Test revoking the default guardian and add it back.
     */
    function testRevokeDefaultGuardianAndAddBack() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        // Verify that the number of guardians is 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianRevocationRequested(OPENFORT_GUARDIAN, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        // Now let's check that, even after the revert, it is possible to confirm the proposal (no DoS)
        recoverableOpenfortAccount.revokeGuardian(OPENFORT_GUARDIAN);

        skip(SECURITY_PERIOD + 1);
        recoverableOpenfortAccount.confirmGuardianRevocation(OPENFORT_GUARDIAN);

        // Verify that the number of guardians is now 0
        assertEq(recoverableOpenfortAccount.guardianCount(), 0);
        // deault (openfort) account should not be a guardian anymore
        assertEq(recoverableOpenfortAccount.isGuardian(OPENFORT_GUARDIAN), false);

        // Expect that we will see an event containing the deault (openfort) account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(OPENFORT_GUARDIAN, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.proposeGuardian(OPENFORT_GUARDIAN);

        skip(SECURITY_PERIOD + 1);
        recoverableOpenfortAccount.confirmGuardianProposal(OPENFORT_GUARDIAN);

        // Verify that the number of guardians is now 1 again
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);
        // deault (openfort) account should be a guardian again
        assertEq(recoverableOpenfortAccount.isGuardian(OPENFORT_GUARDIAN), true);
    }

    /*
     * Test revoking a guardian using owner and cancel before confirming.
     * Only the owner can revoke a guardian and cancel its revocation before confirming.
     */
    function testCancelRevokeGuardian() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        // Verify that the number of guardians is 1 (default)
        assertEq(recoverableOpenfortAccount.guardianCount(), 1);

        // Create a friend EOA
        address friendAccount = makeAddr("friend");

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.proposeGuardian(friendAccount);

        skip(1);
        skip(SECURITY_PERIOD);
        recoverableOpenfortAccount.confirmGuardianProposal(friendAccount);

        // Verify that the number of guardians is now 2
        assertEq(recoverableOpenfortAccount.guardianCount(), 2);
        // Friend account should be a guardian now
        assertEq(recoverableOpenfortAccount.isGuardian(friendAccount), true);

        // Trying to revoke a guardian not using the owner
        vm.expectRevert("Ownable: caller is not the owner");
        recoverableOpenfortAccount.revokeGuardian(friendAccount);

        // Trying to revoke a non-existen guardian (random beneficiary address)
        vm.expectRevert("Must be existing guardian");
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.revokeGuardian(beneficiary);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianRevocationRequested(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.revokeGuardian(friendAccount);

        // Anyone can confirm a revokation. However, the security period has not passed yet
        skip(1);
        vm.expectRevert("Pending revoke not over");
        recoverableOpenfortAccount.confirmGuardianRevocation(friendAccount);

        vm.expectRevert("Ownable: caller is not the owner");
        recoverableOpenfortAccount.cancelGuardianRevocation(friendAccount);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianRevocationCancelled(friendAccount);
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.cancelGuardianRevocation(friendAccount);

        // Friend account is not a guardian anymore
        assertEq(recoverableOpenfortAccount.isGuardian(friendAccount), true);
        // Verify that the number of guardians is 1 again
        assertEq(recoverableOpenfortAccount.guardianCount(), 2);

        // Cancelled revocation should not be able to be confirmed now
        skip(SECURITY_PERIOD);
        vm.expectRevert("Unknown pending revoke");
        recoverableOpenfortAccount.confirmGuardianRevocation(friendAccount);
    }

    /*
     * Random extra tests to mess up with the logic
     */
    function testMessingUpWithGuardianRegister() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        // Create 4 friends
        address friendAccount;
        uint256 friendAccountPK;
        (friendAccount, friendAccountPK) = makeAddrAndKey("friend");

        address friendAccount2;
        uint256 friendAccount2PK;
        (friendAccount2, friendAccount2PK) = makeAddrAndKey("friend2");

        // Adding and removing guardians
        vm.startPrank(accountAdmin);
        recoverableOpenfortAccount.proposeGuardian(friendAccount);
        recoverableOpenfortAccount.proposeGuardian(friendAccount2);
        vm.stopPrank();

        skip(SECURITY_PERIOD + 1);
        recoverableOpenfortAccount.confirmGuardianProposal(friendAccount);
        vm.expectRevert("Unknown guardian");
        recoverableOpenfortAccount.confirmGuardianRevocation(friendAccount2); // Notice this tries to confirm a non-existent revocation!
        vm.expectRevert("Unknown pending revoke");
        recoverableOpenfortAccount.confirmGuardianRevocation(friendAccount); // Notice this tries to confirm a non-existent revocation!
        vm.prank(accountAdmin);
        vm.expectRevert("Must be existing guardian");
        recoverableOpenfortAccount.revokeGuardian(friendAccount2); // Notice this tries to revoke a non-existent guardian!
        vm.expectRevert(DuplicatedGuardian.selector);
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.proposeGuardian(friendAccount); // Notice this tries to register a guardian AGAIN!
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.revokeGuardian(friendAccount); // Starting a valid revocation process
        skip(SECURITY_PERIOD + 1);
        vm.expectRevert("Guardian already exists");
        recoverableOpenfortAccount.confirmGuardianProposal(friendAccount); // Notice this tries to confirm a guardian that is already valid and pending to revoke!
    }

    /**
     * Recovery tests *
     */

    /*
     * Check the correct functionallity of startRecovery()
     */
    function testStartRecovery() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        vm.expectRevert("Recovery can only be started by a guardian");
        recoverableOpenfortAccount.startRecovery(OPENFORT_GUARDIAN);

        vm.prank(OPENFORT_GUARDIAN);
        vm.expectRevert("Recovery address cannot be a guardian");
        recoverableOpenfortAccount.startRecovery(OPENFORT_GUARDIAN);

        vm.prank(OPENFORT_GUARDIAN);
        recoverableOpenfortAccount.startRecovery(address(beneficiary));

        assertEq(recoverableOpenfortAccount.isLocked(), true);
    }

    /*
     * Checks that incorrect parameters should always fail when trying to complete a recovery
     */
    function testBasicChecksCompleteRecovery() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        vm.prank(OPENFORT_GUARDIAN);
        recoverableOpenfortAccount.startRecovery(address(beneficiary));

        assertEq(recoverableOpenfortAccount.isLocked(), true);

        // The recovery time period has not passed. The user should wait to recover.
        vm.expectRevert("Ongoing recovery period");
        bytes[] memory signatures = new bytes[](1);
        recoverableOpenfortAccount.completeRecovery(signatures);

        // Providing an empty array when it is expecting one guardian
        skip(RECOVERY_PERIOD + 1);
        vm.expectRevert("Wrong number of signatures");
        bytes[] memory signatures_wrong_length = new bytes[](3);
        recoverableOpenfortAccount.completeRecovery(signatures_wrong_length);

        // Since signatures are empty, it should return an ECDSA error
        vm.expectRevert("ECDSA: invalid signature length");
        recoverableOpenfortAccount.completeRecovery(signatures);
    }

    /*
     * Auxiliary function to get a valid EIP712 signature using _eip721conrtact's domains separator,
     * a valid hash of the message to sign (_structHash) and a private key (_pk)
     */
    function getEIP712SignatureFrom(address _eip721conrtact, bytes32 _structHash, uint256 _pk)
        internal
        returns (bytes memory signature721)
    {
        (, string memory name, string memory version, uint256 chainId, address verifyingContract,,) =
            IERC5267(_eip721conrtact).eip712Domain();
        bytes32 _TYPE_HASH =
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
        bytes32 domainSeparator = keccak256(
            abi.encode(_TYPE_HASH, keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifyingContract)
        );
        bytes32 hash712 = domainSeparator.toTypedDataHash(_structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_pk, hash712);
        signature721 = abi.encodePacked(r, s, v);
        assertEq(ecrecover(hash712, v, r, s), vm.addr(_pk));
    }

    /*
     * Most basic, yet complete, recovery flow
     * The default Openfort guardian is used to start and complete a recovery process.
     * Ownership is transferred to beneficiary
     */
    function testBasicCompleteRecovery() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        // Default Openfort guardian starts a recovery process because the owner lost the PK
        vm.prank(OPENFORT_GUARDIAN);
        recoverableOpenfortAccount.startRecovery(address(beneficiary));
        assertEq(recoverableOpenfortAccount.isLocked(), true);

        bytes32 structHash = keccak256(
            abi.encode(RECOVER_TYPEHASH, address(beneficiary), uint64(block.timestamp + RECOVERY_PERIOD), uint32(1))
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = getEIP712SignatureFrom(account, structHash, OPENFORT_GUARDIAN_PKEY);

        skip(RECOVERY_PERIOD + 1);
        recoverableOpenfortAccount.completeRecovery(signatures);

        assertEq(recoverableOpenfortAccount.isLocked(), false);
        assertEq(recoverableOpenfortAccount.owner(), address(beneficiary));
    }

    /*
     * Case: User added 2 guardians and keeps the default (Openfort)
     * The 2 added guardians (friends) are used to recover the account and transfer
     * the ownership to beneficiary
     * @notice Remember that signatures need to be ordered by the guardian's address.
     */
    function test3GuardiansCompleteRecovery() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        // Create two friends
        address friendAccount;
        uint256 friendAccountPK;
        (friendAccount, friendAccountPK) = makeAddrAndKey("friend");

        address friendAccount2;
        uint256 friendAccount2PK;
        (friendAccount2, friendAccount2PK) = makeAddrAndKey("friend2");

        {
            // Expect that we will see an event containing the friend account and security period
            vm.expectEmit(true, true, false, true);
            emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
            vm.prank(accountAdmin);
            recoverableOpenfortAccount.proposeGuardian(friendAccount);
            vm.expectEmit(true, true, false, true);
            emit GuardianProposed(friendAccount2, block.timestamp + SECURITY_PERIOD);
            vm.prank(accountAdmin);
            recoverableOpenfortAccount.proposeGuardian(friendAccount2);

            skip(1);
            skip(SECURITY_PERIOD);
            recoverableOpenfortAccount.confirmGuardianProposal(friendAccount);
            recoverableOpenfortAccount.confirmGuardianProposal(friendAccount2);
        }

        {
            // Default Openfort guardian starts a recovery process because the owner lost the PK
            vm.prank(OPENFORT_GUARDIAN);
            recoverableOpenfortAccount.startRecovery(address(beneficiary));
            assertEq(recoverableOpenfortAccount.isLocked(), true);
        }

        bytes32 structHash = keccak256(
            abi.encode(RECOVER_TYPEHASH, address(beneficiary), uint64(block.timestamp + RECOVERY_PERIOD), uint32(2))
        );

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = getEIP712SignatureFrom(account, structHash, friendAccount2PK); // Using friendAccount2 first because it has a lower address
        signatures[1] = getEIP712SignatureFrom(account, structHash, friendAccountPK);

        skip(RECOVERY_PERIOD + 1);
        recoverableOpenfortAccount.completeRecovery(signatures);

        assertEq(recoverableOpenfortAccount.isLocked(), false);
        assertEq(recoverableOpenfortAccount.owner(), address(beneficiary));
    }

    /*
     * Case: User added 2 guardians and keeps the default (Openfort)
     * The 2 added guardians (friends) are used to recover the account and transfer
     * the ownership to beneficiary. Faild due to unsorted signatures
     * @notice Remember that signatures need to be ordered by the guardian's address.
     */
    function test3GuardiansUnorderedCompleteRecovery() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        // Create two friends
        address friendAccount;
        uint256 friendAccountPK;
        (friendAccount, friendAccountPK) = makeAddrAndKey("friend");

        address friendAccount2;
        uint256 friendAccount2PK;
        (friendAccount2, friendAccount2PK) = makeAddrAndKey("friend2");

        {
            // Expect that we will see an event containing the friend account and security period
            vm.expectEmit(true, true, false, true);
            emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
            vm.prank(accountAdmin);
            recoverableOpenfortAccount.proposeGuardian(friendAccount);
            vm.expectEmit(true, true, false, true);
            emit GuardianProposed(friendAccount2, block.timestamp + SECURITY_PERIOD);
            vm.prank(accountAdmin);
            recoverableOpenfortAccount.proposeGuardian(friendAccount2);

            skip(1);
            skip(SECURITY_PERIOD);
            recoverableOpenfortAccount.confirmGuardianProposal(friendAccount);
            recoverableOpenfortAccount.confirmGuardianProposal(friendAccount2);
        }

        {
            // Default Openfort guardian starts a recovery process because the owner lost the PK
            vm.prank(OPENFORT_GUARDIAN);
            recoverableOpenfortAccount.startRecovery(address(beneficiary));
            assertEq(recoverableOpenfortAccount.isLocked(), true);
        }

        bytes32 structHash = keccak256(
            abi.encode(RECOVER_TYPEHASH, address(beneficiary), uint64(block.timestamp + RECOVERY_PERIOD), uint32(2))
        );

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = getEIP712SignatureFrom(account, structHash, friendAccountPK); // Unsorted!
        signatures[1] = getEIP712SignatureFrom(account, structHash, friendAccount2PK);

        skip(RECOVERY_PERIOD + 1);
        vm.expectRevert(InvalidRecoverySignatures.selector);
        recoverableOpenfortAccount.completeRecovery(signatures);

        // it should still be locked and the admin still be the same
        assertEq(recoverableOpenfortAccount.isLocked(), true);
        assertEq(recoverableOpenfortAccount.owner(), accountAdmin);
    }

    /*
     * Case: User added 4 guardians and removes the default (Openfort)
     * One guardian (friend) is used to start a recovery process
     * The guardian that initiatied the recovery + another one are used to complete the flow.
     * @notice Remember that signatures need to be ordered by the guardian's address.
     */
    function test4GuardiansNoDefaultCompleteRecovery() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        // Create 4 friends
        address friendAccount;
        uint256 friendAccountPK;
        (friendAccount, friendAccountPK) = makeAddrAndKey("friend");

        address friendAccount2;
        uint256 friendAccount2PK;
        (friendAccount2, friendAccount2PK) = makeAddrAndKey("friend2");

        // Create 2 more friends. We don't need their PK now as they are not going to sign
        address friendAccount3 = makeAddr("friend3");
        address friendAccount4 = makeAddr("friend4");

        // Adding and removing guardians
        {
            vm.startPrank(accountAdmin);
            recoverableOpenfortAccount.proposeGuardian(friendAccount);
            recoverableOpenfortAccount.proposeGuardian(friendAccount2);
            recoverableOpenfortAccount.proposeGuardian(friendAccount3);
            recoverableOpenfortAccount.proposeGuardian(friendAccount4);
            vm.stopPrank();

            skip(SECURITY_PERIOD + 1);
            recoverableOpenfortAccount.confirmGuardianProposal(friendAccount);
            recoverableOpenfortAccount.confirmGuardianProposal(friendAccount2);
            recoverableOpenfortAccount.confirmGuardianProposal(friendAccount3);
            recoverableOpenfortAccount.confirmGuardianProposal(friendAccount4);

            vm.prank(accountAdmin);
            recoverableOpenfortAccount.revokeGuardian(OPENFORT_GUARDIAN);
            vm.expectRevert("Pending revoke not over");
            recoverableOpenfortAccount.confirmGuardianRevocation(OPENFORT_GUARDIAN);
            skip(SECURITY_PERIOD + 1);
            recoverableOpenfortAccount.confirmGuardianRevocation(OPENFORT_GUARDIAN);
        }

        // Start the recovery process
        {
            // Default Openfort guardian tries starts a recovery process because the owner lost the PK
            // It should not work as it is not a guardian anymore
            vm.expectRevert("Recovery can only be started by a guardian");
            vm.prank(OPENFORT_GUARDIAN);
            recoverableOpenfortAccount.startRecovery(address(beneficiary));
            vm.prank(friendAccount2);
            recoverableOpenfortAccount.startRecovery(address(beneficiary));
            assertEq(recoverableOpenfortAccount.isLocked(), true);
        }

        bytes32 structHash = keccak256(
            abi.encode(RECOVER_TYPEHASH, address(beneficiary), uint64(block.timestamp + RECOVERY_PERIOD), uint32(2))
        );

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = getEIP712SignatureFrom(account, structHash, friendAccount2PK); // Using friendAccount2 first because it has a lower address
        signatures[1] = getEIP712SignatureFrom(account, structHash, friendAccountPK);

        skip(RECOVERY_PERIOD + 1);
        recoverableOpenfortAccount.completeRecovery(signatures);

        assertEq(recoverableOpenfortAccount.isLocked(), false);
        assertEq(recoverableOpenfortAccount.owner(), address(beneficiary));
    }

    /*
     * Case: User added 2 guardians and keeps the default (Openfort)
     * The 2 added guardians (friends) are used to recover the account and transfer
     * the ownership to beneficiary. Wrong signatures used
     * @notice Remember that signatures need to be ordered by the guardian's address.
     */
    function test3GuardiansFailCompleteRecovery() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        // Create two friends
        address friendAccount;
        uint256 friendAccountPK;
        (friendAccount, friendAccountPK) = makeAddrAndKey("friend");

        address friendAccount2;
        uint256 friendAccount2PK;
        (friendAccount2, friendAccount2PK) = makeAddrAndKey("friend2");

        {
            // Expect that we will see an event containing the friend account and security period
            vm.expectEmit(true, true, false, true);
            emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
            vm.prank(accountAdmin);
            recoverableOpenfortAccount.proposeGuardian(friendAccount);
            vm.expectEmit(true, true, false, true);
            emit GuardianProposed(friendAccount2, block.timestamp + SECURITY_PERIOD);
            vm.prank(accountAdmin);
            recoverableOpenfortAccount.proposeGuardian(friendAccount2);

            skip(1);
            skip(SECURITY_PERIOD);
            recoverableOpenfortAccount.confirmGuardianProposal(friendAccount);
            recoverableOpenfortAccount.confirmGuardianProposal(friendAccount2);
        }

        {
            // Default Openfort guardian starts a recovery process because the owner lost the PK
            vm.prank(OPENFORT_GUARDIAN);
            recoverableOpenfortAccount.startRecovery(address(beneficiary));
            assertEq(recoverableOpenfortAccount.isLocked(), true);
        }

        // notice: wrong new oner!!!
        bytes32 structHash =
            keccak256(abi.encode(RECOVER_TYPEHASH, factoryAdmin, uint64(block.timestamp + RECOVERY_PERIOD), uint32(2)));

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = getEIP712SignatureFrom(account, structHash, friendAccount2PK); // Using friendAccount2 first because it has a lower address
        signatures[1] = getEIP712SignatureFrom(account, structHash, friendAccountPK);

        skip(RECOVERY_PERIOD + 1);
        vm.expectRevert(InvalidRecoverySignatures.selector);
        recoverableOpenfortAccount.completeRecovery(signatures);

        // it should still be locked and the admin still be the same
        assertEq(recoverableOpenfortAccount.isLocked(), true);
        assertEq(recoverableOpenfortAccount.owner(), accountAdmin);
    }

    /*
     * Testing the functionality to cancel a recovery process
     */
    function testCancelRecovery() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        // Default Openfort guardian starts a recovery process because the owner lost the PK
        vm.prank(OPENFORT_GUARDIAN);
        recoverableOpenfortAccount.startRecovery(address(beneficiary));
        assertEq(recoverableOpenfortAccount.isLocked(), true);

        vm.expectRevert("Ownable: caller is not the owner");
        recoverableOpenfortAccount.cancelRecovery();

        vm.prank(accountAdmin);
        recoverableOpenfortAccount.cancelRecovery();

        bytes32 structHash = keccak256(
            abi.encode(RECOVER_TYPEHASH, address(beneficiary), uint64(block.timestamp + RECOVERY_PERIOD), uint32(1))
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = getEIP712SignatureFrom(account, structHash, OPENFORT_GUARDIAN_PKEY);

        skip(RECOVERY_PERIOD + 1);
        vm.expectRevert(NoOngoingRecovery.selector);
        recoverableOpenfortAccount.completeRecovery(signatures);

        assertEq(recoverableOpenfortAccount.isLocked(), false);
        assertEq(recoverableOpenfortAccount.owner(), address(accountAdmin));
    }

    /*
     * Testing the startRecovery twice in a row
     */
    function testStartRecoveryTwice() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        // Default Openfort guardian starts a recovery process because the owner lost the PK
        vm.prank(OPENFORT_GUARDIAN);
        recoverableOpenfortAccount.startRecovery(address(beneficiary));
        assertEq(recoverableOpenfortAccount.isLocked(), true);

        // Calling startRecovery() again should revert and have no effect
        vm.expectRevert(OngoingRecovery.selector);
        vm.prank(OPENFORT_GUARDIAN);
        recoverableOpenfortAccount.startRecovery(address(beneficiary));

        // The accounts should still be locked
        assertEq(recoverableOpenfortAccount.isLocked(), true);
        assertEq(recoverableOpenfortAccount.owner(), accountAdmin);
    }

    /**
     * Transfer ownership tests *
     */

    /*
     * Try to transfer ownership to a guardian.
     * Should not be allowed.
     */
    function testTransferOwnerNotGuardian() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        // Create a friend EOA
        address friendAccount = makeAddr("friend");

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        recoverableOpenfortAccount.proposeGuardian(friendAccount);

        skip(1);
        skip(SECURITY_PERIOD);
        recoverableOpenfortAccount.confirmGuardianProposal(friendAccount);

        // It should fail as friendAccount is a guardian
        vm.expectRevert(GuardianCannotBeOwner.selector);
        recoverableOpenfortAccount.transferOwnership(friendAccount);
    }

    /*
     * Try to transfer ownership to a valid account.
     * Should be allowed.
     */
    function testTransferOwner() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));

        // Create a new owner EOA
        address newOwner = makeAddr("newOwner");

        vm.expectRevert("Ownable: caller is not the owner");
        recoverableOpenfortAccount.transferOwnership(newOwner);

        vm.prank(accountAdmin);
        recoverableOpenfortAccount.transferOwnership(newOwner);

        vm.prank(newOwner);
        recoverableOpenfortAccount.acceptOwnership();

        // New owner should be now newOwner
        assertEq(recoverableOpenfortAccount.owner(), address(newOwner));
    }

    /*
     * Temporal test function for coverage purposes showing
     * that isGuardianOrGuardianSigner() always returns false.
     */
    function testStubFakeMockTempisGuardian() public {
        RecoverableOpenfortAccount recoverableOpenfortAccount = RecoverableOpenfortAccount(payable(account));
        assertEq(recoverableOpenfortAccount.isGuardianOrGuardianSigner(OPENFORT_GUARDIAN), false);
    }
}
