// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {console} from "lib/forge-std/src/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {EntryPoint, UserOperation} from "account-abstraction/core/EntryPoint.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";
import {MockERC20} from "contracts/mock/MockERC20.sol";
import {ManagedOpenfortAccount} from "contracts/core/managed/ManagedOpenfortAccount.sol";
import {ManagedOpenfortFactory} from "contracts/core/managed/ManagedOpenfortFactory.sol";
import {OpenfortManagedProxy} from "contracts/core/managed/OpenfortManagedProxy.sol";
import {MockV2ManagedOpenfortAccount} from "contracts/mock/MockV2ManagedOpenfortAccount.sol";
import {OpenfortBaseTest} from "../OpenfortBaseTest.t.sol";

contract ManagedOpenfortAccountTest is OpenfortBaseTest {
    using ECDSA for bytes32;

    ManagedOpenfortAccount public managedOpenfortAccount;
    ManagedOpenfortFactory public managedOpenfortFactory;

    /**
     * @notice Initialize the ManagedOpenfortAccount testing contract.
     * Scenario:
     * - factoryAdmin is the deployer (and owner) of the managedOpenfortAccount and managedOpenfortFactory/Beacon
     * - accountAdmin is the account used to deploy new managed accounts using the factory
     * - entryPoint is the singleton EntryPoint
     * - testCounter is the counter used to test userOps
     */
    function setUp() public {
        // Setup and fund signers
        (factoryAdmin, factoryAdminPKey) = makeAddrAndKey("factoryAdmin");
        vm.deal(factoryAdmin, 100 ether);
        (accountAdmin, accountAdminPKey) = makeAddrAndKey("accountAdmin");
        vm.deal(accountAdmin, 100 ether);
        (OPENFORT_GUARDIAN, OPENFORT_GUARDIAN_PKEY) = makeAddrAndKey("OPENFORT_GUARDIAN");

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
        // deploy account implementation
        managedOpenfortAccount = new ManagedOpenfortAccount{salt: versionSalt}();
        // deploy account factory (beacon)
        managedOpenfortFactory = new ManagedOpenfortFactory{salt: versionSalt}(
            factoryAdmin,
            address(entryPoint),
            address(managedOpenfortAccount),
            RECOVERY_PERIOD,
            SECURITY_PERIOD,
            SECURITY_WINDOW,
            LOCK_PERIOD,
            OPENFORT_GUARDIAN
        );
        // Create an managed account wallet and get its address
        account = managedOpenfortFactory.createAccountWithNonce(accountAdmin, "1");
        // deploy a new TestCounter
        testCounter = new TestCounter{salt: versionSalt}();
        // deploy a new MockERC20 (ERC20)
        mockERC20 = new MockERC20{salt: versionSalt}();
        vm.stopPrank();
    }

    /*
     * Create an account by directly calling the factory.
     */
    function testCreateAccountWithNonceViaFactory() public {
        // Get the counterfactual address
        vm.prank(factoryAdmin);
        address account2 = managedOpenfortFactory.getAddressWithNonce(accountAdmin, "2");

        // Expect that we will see an event containing the account and admin
        vm.expectEmit(true, true, false, true);
        emit AccountCreated(account2, accountAdmin);

        // Deploy a managed account to the counterfactual address
        vm.prank(factoryAdmin);
        managedOpenfortFactory.createAccountWithNonce(accountAdmin, "2");

        // Calling it again should just return the address and not create another account
        vm.prank(factoryAdmin);
        managedOpenfortFactory.createAccountWithNonce(accountAdmin, "2");

        // Make sure the counterfactual address has not been altered
        vm.prank(factoryAdmin);
        assertEq(account2, managedOpenfortFactory.getAddressWithNonce(accountAdmin, "2"));
    }

    /*
     * Create an account by directly calling the factory by fuzzing the admin and nonce parameters.
     */
    function testFuzzCreateAccountWithNonceViaFactory(address _adminAddress, bytes32 _nonce) public {
        // Get the counterfactual address
        vm.prank(factoryAdmin);
        address account2 = managedOpenfortFactory.getAddressWithNonce(_adminAddress, _nonce);

        // Expect that we will see an event containing the account and admin
        vm.expectEmit(true, true, false, true);
        emit AccountCreated(account2, _adminAddress);

        // Deploy a managed account to the counterfactual address
        vm.prank(factoryAdmin);
        managedOpenfortFactory.createAccountWithNonce(_adminAddress, _nonce);

        // Calling it again should just return the address and not create another account
        vm.prank(factoryAdmin);
        managedOpenfortFactory.createAccountWithNonce(_adminAddress, _nonce);

        // Make sure the counterfactual address has not been altered
        vm.prank(factoryAdmin);
        assertEq(account2, managedOpenfortFactory.getAddressWithNonce(_adminAddress, _nonce));
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
        address account2 = managedOpenfortFactory.getAddressWithNonce(accountAdmin, bytes32("2"));
        assertEq(account2.code.length, 0);

        bytes memory initCallData =
            abi.encodeWithSignature("createAccountWithNonce(address,bytes32)", accountAdmin, bytes32("2"));
        bytes memory initCode = abi.encodePacked(abi.encodePacked(address(managedOpenfortFactory)), initCallData);

        UserOperation[] memory userOpCreateAccount =
            _setupUserOpExecute(account2, accountAdminPKey, initCode, address(0), 0, bytes(""));

        // vm.expectRevert();
        // entryPoint.simulateValidation(userOpCreateAccount[0]);

        // Expect that we will see an event containing the account and admin
        vm.expectEmit(true, true, false, true);
        emit AccountCreated(account2, accountAdmin);
        entryPoint.handleOps(userOpCreateAccount, beneficiary);

        // Make sure the smart account does have some code now
        assert(account2.code.length > 0);

        // Make sure the counterfactual address has not been altered
        assertEq(account2, managedOpenfortFactory.getAddressWithNonce(accountAdmin, bytes32("2")));
    }

    /*
     * Create an account using the factory and make it call count() directly.
     */
    function testIncrementCounterDirect() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(account), 0);

        // Make the admin of the managed account wallet (deployer) call "count"
        vm.prank(accountAdmin);
        ManagedOpenfortAccount(payable(account)).execute(address(testCounter), 0, abi.encodeWithSignature("count()"));

        // Verify that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Create an account by directly calling the factory and make it call count()
     * using the execute() function using the EntryPoint (userOp). Leveraging ERC-4337.
     */
    function testIncrementCounterViaEntrypoint() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(account), 0);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, accountAdminPKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Create an account by directly calling the factory and make it call count()
     * using the executeBatching() function using the EntryPoint (userOp). Leveraging ERC-4337.
     */
    function testIncrementCounterViaEntrypointBatching() public {
        // Verify that the counter is still set to 0
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

        // Verify that the counter has increased
        assertEq(testCounter.counters(account), 3);
    }

    /*
     *  Should fail, try to use a sessionKey that is not registered.
     */
    function testFailIncrementCounterViaSessionKeyNotregistered() public {
        // Verify that the counter is still set to 0
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

        // Verify that the counter has not increased
        assertEq(testCounter.counters(account), 0);
    }

    /*
     * Use a sessionKey that is registered.
     */
    function testIncrementCounterViaSessionKey() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");
        address[] memory emptyWhitelist;

        vm.prank(accountAdmin);
        ManagedOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1, 100, emptyWhitelist);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Register a sessionKey via userOp calling the execute() function
     * using the EntryPoint (userOp). Then use the sessionKey to count
     */
    function testRegisterSessionKeyViaEntrypoint() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");
        address[] memory emptyWhitelist;

        UserOperation[] memory userOp = _setupUserOp(
            account,
            accountAdminPKey,
            bytes(""),
            abi.encodeWithSignature(
                "registerSessionKey(address,uint48,uint48,uint48,address[])",
                sessionKey,
                0,
                2 ** 48 - 1,
                100,
                emptyWhitelist
            )
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has not increased
        assertEq(testCounter.counters(account), 0);

        userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Register a master sessionKey via userOp calling the execute() function
     * using the EntryPoint (userOp). Then use that sessionKey to register a second one
     * Should not be allowed: session keys cannot register new session keys!
     */
    function testFailRegisterSessionKeyViaEntrypoint2ndKey() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");
        address[] memory emptyWhitelist;

        UserOperation[] memory userOp = _setupUserOp(
            account,
            accountAdminPKey,
            bytes(""),
            abi.encodeWithSignature(
                "registerSessionKey(address,uint48,uint48,uint48,address[])",
                sessionKey,
                0,
                2 ** 48 - 1,
                2 ** 48 - 1,
                emptyWhitelist
            )
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has not increased
        assertEq(testCounter.counters(account), 0);

        userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has increased
        assertEq(testCounter.counters(account), 1);

        address sessionKeyAttack;
        uint256 sessionKeyPrivKeyAttack;
        (sessionKeyAttack, sessionKeyPrivKeyAttack) = makeAddrAndKey("sessionKeyAttack");

        userOp = _setupUserOp(
            account,
            sessionKeyPrivKey,
            bytes(""),
            abi.encodeWithSignature(
                "registerSessionKey(address,uint48,uint48,uint48,address[])",
                sessionKeyAttack,
                0,
                2 ** 48 - 1,
                2 ** 48 - 1,
                emptyWhitelist
            )
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
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");
        address[] memory emptyWhitelist;

        vm.warp(100);
        vm.prank(accountAdmin);
        ManagedOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 99, 100, emptyWhitelist);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        vm.expectRevert();
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has not increased
        assertEq(testCounter.counters(account), 0);
    }

    /*
     *  Should fail, try to use a sessionKey that is revoked.
     */
    function testFailIncrementCounterViaSessionKeyRevoked() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");
        address[] memory emptyWhitelist;

        vm.prank(accountAdmin);
        ManagedOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 0, 100, emptyWhitelist);
        ManagedOpenfortAccount(payable(account)).revokeSessionKey(sessionKey);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     *  Should fail, try to use a sessionKey that reached its limit.
     */
    function testFailIncrementCounterViaSessionKeyReachLimit() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");
        address[] memory emptyWhitelist;

        // We are now in block 100, but our session key is valid until block 150
        vm.warp(100);
        vm.prank(accountAdmin);
        ManagedOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 150, 1, emptyWhitelist);

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

        // Verify that the counter has only increased by one
        assertEq(testCounter.counters(account), 1);
    }

    /*
     *  Should fail, try to use a sessionKey that reached its limit.
     */
    function testFailIncrementCounterViaSessionKeyReachLimitBatching() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");
        address[] memory emptyWhitelist;

        // We are now in block 100, but our session key is valid until block 150
        vm.warp(100);
        vm.prank(accountAdmin);
        ManagedOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 150, 2, emptyWhitelist);

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

        // Verify that the counter has not increased
        assertEq(testCounter.counters(account), 0);
    }

    /*
     *  Should fail, try to revoke a sessionKey using a non-privileged user
     */
    function testFailRevokeSessionKeyInvalidUser() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");
        address[] memory emptyWhitelist;

        vm.prank(accountAdmin);
        ManagedOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 0, 100, emptyWhitelist);
        vm.prank(beneficiary);
        ManagedOpenfortAccount(payable(account)).revokeSessionKey(sessionKey);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Use a sessionKey with whitelisting to call Execute().
     */
    function testIncrementCounterViaSessionKeyWhitelisting() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        address[] memory whitelist = new address[](1);
        whitelist[0] = address(testCounter);
        vm.prank(accountAdmin);
        ManagedOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1, 1, whitelist);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Should fail, try to register a sessionKey with a large whitelist.
     */
    function testFailIncrementCounterViaSessionKeyWhitelistingTooBig() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        address[] memory whitelist = new address[](11);
        vm.prank(accountAdmin);
        ManagedOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1, 1, whitelist);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has not increased
        assertEq(testCounter.counters(account), 0);
    }

    /*
     * Use a sessionKey with whitelisting to call ExecuteBatch().
     */
    function testIncrementCounterViaSessionKeyWhitelistingBatch() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        address[] memory whitelist = new address[](1);
        whitelist[0] = address(testCounter);
        vm.prank(accountAdmin);
        ManagedOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1, 3, whitelist);

        // Verify that the registered key is not a MasterKey but has whitelisting
        bool isMasterKey;
        bool isWhitelisted;
        (,,, isMasterKey, isWhitelisted,) = ManagedOpenfortAccount(payable(account)).sessionKeys(sessionKey);
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

        // Verify that the counter has increased
        assertEq(testCounter.counters(account), 3);
    }

    /*
     * Use a sessionKey with whitelisting to call ExecuteBatch().
     */
    function testFailIncrementCounterViaSessionKeyWhitelistingBatch() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        address[] memory whitelist = new address[](1);
        whitelist[0] = address(testCounter);
        vm.prank(accountAdmin);
        ManagedOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1, 3, whitelist);

        // Verify that the registered key is not a MasterKey but has whitelisting
        bool isMasterKey;
        bool isWhitelisted;
        (,,, isMasterKey, isWhitelisted,) = ManagedOpenfortAccount(payable(account)).sessionKeys(sessionKey);
        assert(!isMasterKey);
        assert(isWhitelisted);

        uint256 count = 11;
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

        // Verify that the counter has not increased
        assertEq(testCounter.counters(account), 0);
    }

    /*
     * Should fail, try to use a sessionKey with invalid whitelisting to call Execute().
     */
    function testFailIncrementCounterViaSessionKeyWhitelistingWrongAddress() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        address[] memory whitelist = new address[](1);
        whitelist[0] = address(account);
        vm.prank(accountAdmin);
        ManagedOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1, 1, whitelist);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Should fail, try to use a sessionKey with invalid whitelisting to call ExecuteBatch().
     */
    function testFailIncrementCounterViaSessionKeyWhitelistingBatchWrongAddress() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        address[] memory whitelist = new address[](1);
        whitelist[0] = address(account);
        vm.prank(accountAdmin);
        ManagedOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1, 1, whitelist);

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

        // Verify that the counter has not increased
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

        assertEq(ManagedOpenfortAccount(payable(account)).owner(), accountAdmin);
        vm.expectRevert("Ownable: caller is not the owner");
        ManagedOpenfortAccount(payable(account)).transferOwnership(accountAdmin2);

        vm.prank(accountAdmin);
        ManagedOpenfortAccount(payable(account)).transferOwnership(accountAdmin2);
        vm.prank(accountAdmin2);
        ManagedOpenfortAccount(payable(account)).acceptOwnership();

        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(account), 0);

        // Make the admin of the managed account wallet (deployer) call "count"
        vm.prank(accountAdmin2);
        ManagedOpenfortAccount(payable(account)).execute(address(testCounter), 0, abi.encodeWithSignature("count()"));

        // Verify that the counter has increased
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
        ManagedOpenfortAccount(payable(account)).transferOwnership(accountAdmin2);
        vm.prank(accountAdmin2);
        ManagedOpenfortAccount(payable(account)).acceptOwnership();

        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(account), 0);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, accountAdmin2PKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Test an account with mockERC20 instead of TestCount.
     */
    function testMintTokenAccount() public {
        // Verify that the totalSupply is still 0
        assertEq(mockERC20.totalSupply(), 0);

        // Mint 1 to beneficiary
        mockERC20.mint(beneficiary, 1);
        assertEq(mockERC20.totalSupply(), 1);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account,
            accountAdminPKey,
            bytes(""),
            address(mockERC20),
            0,
            abi.encodeWithSignature("mint(address,uint256)", beneficiary, 1)
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the totalSupply has increased
        assertEq(mockERC20.totalSupply(), 2);
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
    // function testSimulateValidation() public {
    //     // Verify that the counter is still set to 0
    //     assertEq(testCounter.counters(account), 0);

    //     UserOperation[] memory userOp = _setupUserOpExecute(
    //         account, accountAdminPKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
    //     );

    //     entryPoint.depositTo{value: 1000000000000000000}(account);

    //     // Expect the simulateValidation() to always revert
    //     vm.expectRevert();
    //     entryPoint.simulateValidation(userOp[0]);

    //     // Test addStake. Make sure it checks for owner and alue passed.
    //     vm.expectRevert("Ownable: caller is not the owner");
    //     managedOpenfortFactory.addStake{value: 10000000000000000}(99);
    //     vm.prank(factoryAdmin);
    //     vm.expectRevert("no stake specified");
    //     managedOpenfortFactory.addStake(99);
    //     vm.prank(factoryAdmin);
    //     managedOpenfortFactory.addStake{value: 10000000000000000}(99);

    //     // expectRevert as simulateValidation() always reverts
    //     vm.expectRevert();
    //     entryPoint.simulateValidation(userOp[0]);

    //     // expectRevert as simulateHandleOp() always reverts
    //     vm.expectRevert();
    //     entryPoint.simulateHandleOp(userOp[0], address(0), "");

    //     // Verify that the counter has not increased
    //     assertEq(testCounter.counters(account), 0);
    // }

    /*
     * 1- Deploy a new account implementation with the new EntryPoint address and disabled 
     * 2- Upgrade the implementation address
     */
    function testUpgradeEntryPoint() public {
        address newEntryPoint = 0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF;

        // Check addressess
        assertEq(address(managedOpenfortAccount.entryPoint()), address(entryPoint));

        // Try to use the old and new implementation before upgrade (should always behave with current values)
        assertEq(MockV2ManagedOpenfortAccount(payable(account)).getLock(), 0);
        vm.expectRevert(MustBeGuardian.selector);
        MockV2ManagedOpenfortAccount(payable(account)).startRecovery(address(0));

        assertEq(ManagedOpenfortAccount(payable(account)).getDeposit(), 0);
        assertEq(MockV2ManagedOpenfortAccount(payable(account)).getDeposit(), 0);

        // Deploy the new account implementation
        MockV2ManagedOpenfortAccount mockV2ManagedOpenfortAccount =
            new MockV2ManagedOpenfortAccount{salt: versionSalt}();

        // Try to upgrade
        vm.expectRevert("Ownable: caller is not the owner");
        managedOpenfortFactory.upgradeTo(address(mockV2ManagedOpenfortAccount));

        // Finally upgrade
        vm.prank(factoryAdmin);
        managedOpenfortFactory.upgradeTo(address(mockV2ManagedOpenfortAccount));

        // Try to use the old and new implementation before upgrade (should always behave with current values)
        vm.expectRevert("disabled!");
        MockV2ManagedOpenfortAccount(payable(account)).getLock();
        vm.expectRevert("disabled!");
        ManagedOpenfortAccount(payable(account)).getLock();

        vm.expectRevert("disabled!");
        MockV2ManagedOpenfortAccount(payable(account)).startRecovery(address(0));
        vm.expectRevert("disabled!");
        ManagedOpenfortAccount(payable(account)).startRecovery(address(0));

        vm.expectRevert();
        ManagedOpenfortAccount(payable(account)).getDeposit();
        vm.expectRevert();
        MockV2ManagedOpenfortAccount(payable(account)).getDeposit();

        // Check that the EntryPoint is now upgraded too
        assertEq(address(MockV2ManagedOpenfortAccount(payable(address(account))).entryPoint()), newEntryPoint);
    }

    function testFailIsValidSignature() public {
        bytes32 hash = keccak256("Signed by Owner");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(accountAdminPKey, hash);
        address signer = ecrecover(hash, v, r, s);
        assertEq(accountAdmin, signer); // [PASS]

        bytes memory signature = abi.encodePacked(r, s, v);
        signer = ECDSA.recover(hash, signature);
        assertEq(accountAdmin, signer); // [PASS]

        bytes4 valid = ManagedOpenfortAccount(payable(account)).isValidSignature(hash, signature);
        assertEq(valid, bytes4(0xffffffff)); // SHOULD PASS!
        assertEq(valid, MAGICVALUE); // SHOULD FAIL! We do not accept straight signatures from owners anymore
    }

    function testFailIsValidSignatureMessage() public {
        bytes32 hash = keccak256("Signed by Owner");
        bytes32 hashMessage = hash.toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(accountAdminPKey, hashMessage);
        address signer = ecrecover(hashMessage, v, r, s);
        assertEq(accountAdmin, signer); // [PASS]

        bytes memory signature = abi.encodePacked(r, s, v);
        signer = ECDSA.recover(hashMessage, signature);
        assertEq(accountAdmin, signer); // [PASS]

        bytes4 valid = ManagedOpenfortAccount(payable(account)).isValidSignature(hash, signature);
        assertEq(valid, bytes4(0xffffffff)); // SHOULD PASS!
        assertEq(valid, MAGICVALUE); // SHOULD FAIL! We do not accept straight signatures from owners anymore
    }

    /*
     * Auxiliary function to get a valid EIP712 signature using _eip721contract's domains separator,
     * a valid hash of the message to sign (_structHash) and a private key (_pk)
     */
    function getEIP712SignatureFrom(address _eip721contract, bytes32 _structHash, uint256 _pk)
        internal
        returns (bytes memory signature721)
    {
        (, string memory name, string memory version, uint256 chainId, address verifyingContract,,) =
            IERC5267(_eip721contract).eip712Domain();
        bytes32 domainSeparator = keccak256(
            abi.encode(_TYPE_HASH, keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifyingContract)
        );
        bytes32 hash712 = domainSeparator.toTypedDataHash(_structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_pk, hash712);
        signature721 = abi.encodePacked(r, s, v);
        assertEq(ecrecover(hash712, v, r, s), vm.addr(_pk));
    }

    function testisValidSignatureTyped() public {
        string memory messageToSign = "Signed by Owner";
        bytes32 hash = keccak256(abi.encodePacked(messageToSign));

        bytes32 structHash = keccak256(abi.encode(OF_MSG_TYPEHASH, hash));

        (, string memory name, string memory version, uint256 chainId, address verifyingContract,,) =
            IERC5267(account).eip712Domain();

        bytes32 domainSeparator = keccak256(
            abi.encode(_TYPE_HASH, keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifyingContract)
        );

        bytes memory signature = getEIP712SignatureFrom(account, structHash, accountAdminPKey);
        bytes32 hash712 = domainSeparator.toTypedDataHash(structHash);
        address signer = hash712.recover(signature);

        assertEq(accountAdmin, signer); // [PASS]

        bytes4 valid = ManagedOpenfortAccount(payable(account)).isValidSignature(hash, signature);
        assertEq(valid, MAGICVALUE); // SHOULD PASS
    }

    /**
     * Lock tests *
     */

    /*
     * Test locking the Openfort account using the default guardian.
     */
    function testLockAccount() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

        assertEq(openfortAccount.isLocked(), false);
        assertEq(openfortAccount.getLock(), 0);

        vm.expectRevert(MustBeGuardian.selector);
        openfortAccount.lock();

        vm.prank(OPENFORT_GUARDIAN);
        openfortAccount.lock();

        assertEq(openfortAccount.isLocked(), true);
        assertEq(openfortAccount.getLock(), block.timestamp + LOCK_PERIOD);

        vm.expectRevert(AccountLocked.selector);
        vm.prank(OPENFORT_GUARDIAN);
        openfortAccount.lock();

        // Automatically unlock
        skip(LOCK_PERIOD + 1);
        assertEq(openfortAccount.isLocked(), false);
        assertEq(openfortAccount.getLock(), 0);
    }

    /*
     * Test unlocking the Openfort account using the default guardian.
     */
    function testUnlockAccount() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

        assertEq(openfortAccount.isLocked(), false);
        assertEq(openfortAccount.getLock(), 0);

        vm.expectRevert(MustBeGuardian.selector);
        openfortAccount.lock();

        vm.prank(OPENFORT_GUARDIAN);
        openfortAccount.lock();

        assertEq(openfortAccount.isLocked(), true);
        assertEq(openfortAccount.getLock(), block.timestamp + LOCK_PERIOD);

        skip(LOCK_PERIOD / 2);

        vm.expectRevert(MustBeGuardian.selector);
        openfortAccount.unlock();
        assertEq(openfortAccount.isLocked(), true);

        vm.prank(OPENFORT_GUARDIAN);
        openfortAccount.unlock();

        assertEq(openfortAccount.isLocked(), false);
        assertEq(openfortAccount.getLock(), 0);

        vm.expectRevert(AccountNotLocked.selector);
        vm.prank(OPENFORT_GUARDIAN);
        openfortAccount.unlock();
    }

    /**
     * Add guardians tests *
     */

    /*
     * Test proposing a guardian (by the owner) and accepting it (by the owner).
     * Successfully propose a guardian and confirm it after SECURITY_PERIOD
     */
    function testAddEOAGuardian() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

        openfortAccount.getGuardians();

        // Verify that the number of guardians is 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);

        // Create a friend EOA
        address friendAccount = makeAddr("friend");

        // Trying to propose a guardian not using the owner
        vm.expectRevert("Ownable: caller is not the owner");
        openfortAccount.proposeGuardian(friendAccount);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        openfortAccount.proposeGuardian(friendAccount);

        // Verify that the number of guardians is still 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);

        // Friend account should not be a guardian yet
        assertEq(openfortAccount.isGuardian(friendAccount), false);

        // Test if zero address is a guardian
        assertEq(openfortAccount.isGuardian(address(0)), false);

        skip(1);

        vm.expectRevert(PendingProposalNotOver.selector);
        openfortAccount.confirmGuardianProposal(friendAccount);

        skip(SECURITY_PERIOD);
        openfortAccount.confirmGuardianProposal(friendAccount);

        // Verify that the number of guardians is now 2
        assertEq(openfortAccount.guardianCount(), 2);

        // Friend account should be a guardian now
        assertEq(openfortAccount.isGuardian(friendAccount), true);
    }

    /*
     * Test proposing a guardian, but its proposal expires before accepting.
     * An expired proposal cannot be accepted. A proposal expires after SECURITY_PERIOD and SECURITY_WINDOW.
     */
    function testAddEOAGuardianExpired() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

        // Verify that the number of guardians is 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);

        // Create a friend EOA
        address friendAccount = makeAddr("friend");

        // Trying to propose a guardian not using the owner
        vm.expectRevert("Ownable: caller is not the owner");
        openfortAccount.proposeGuardian(friendAccount);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        openfortAccount.proposeGuardian(friendAccount);

        // Verify that the number of guardians is still 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);

        // Friend account should not be a guardian yet
        assertEq(openfortAccount.isGuardian(friendAccount), false);

        skip(1);

        vm.expectRevert(PendingProposalNotOver.selector);
        openfortAccount.confirmGuardianProposal(friendAccount);

        skip(SECURITY_PERIOD + SECURITY_WINDOW);
        vm.expectRevert(PendingProposalExpired.selector);
        openfortAccount.confirmGuardianProposal(friendAccount);

        // Verify that the number of guardians is still 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);

        // Friend account should not be a guardian yet
        assertEq(openfortAccount.isGuardian(friendAccount), false);
    }

    /*
     * Test proposing a guardian, but its proposal expires before accepting. Re-add again
     * An expired proposal cannot be accepted. A proposal expires after SECURITY_PERIOD and SECURITY_WINDOW.
     */
    function testAddEOAGuardianExpiredThenReAdd() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

        // Verify that the number of guardians is 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);

        // Create a friend EOA
        address friendAccount = makeAddr("friend");

        // Trying to propose a guardian not using the owner
        vm.expectRevert("Ownable: caller is not the owner");
        openfortAccount.proposeGuardian(friendAccount);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        openfortAccount.proposeGuardian(friendAccount);

        // Verify that the number of guardians is still 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);

        // Friend account should not be a guardian yet
        assertEq(openfortAccount.isGuardian(friendAccount), false);

        skip(1);

        vm.expectRevert(PendingProposalNotOver.selector);
        openfortAccount.confirmGuardianProposal(friendAccount);

        skip(SECURITY_PERIOD + SECURITY_WINDOW);
        vm.expectRevert(PendingProposalExpired.selector);
        openfortAccount.confirmGuardianProposal(friendAccount);

        // Verify that the number of guardians is still 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);

        // Friend account should not be a guardian yet
        assertEq(openfortAccount.isGuardian(friendAccount), false);

        /* Let's try it again (re-add) */
        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        openfortAccount.proposeGuardian(friendAccount);

        // Verify that the number of guardians is still 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);

        // Friend account should not be a guardian yet
        assertEq(openfortAccount.isGuardian(friendAccount), false);

        skip(1);
        skip(SECURITY_PERIOD);
        openfortAccount.confirmGuardianProposal(friendAccount);

        // Verify that the number of guardians is now 2
        assertEq(openfortAccount.guardianCount(), 2);

        // Friend account should not be a guardian yet
        assertEq(openfortAccount.isGuardian(friendAccount), true);
    }

    /*
     * Test proposing a guardian twice. Make sure a new proposal is not created and the original still works.
     * An expired proposal cannot be accepted. A proposal expires after SECURITY_PERIOD and SECURITY_WINDOW.
     */
    function testAddEOAGuardianDuplicatedPorposal() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

        // Verify that the number of guardians is 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);

        // Create a friend EOA
        address friendAccount = makeAddr("friend");

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        openfortAccount.proposeGuardian(friendAccount);

        // Verify that the number of guardians is still 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);

        // Friend account should not be a guardian yet
        assertEq(openfortAccount.isGuardian(friendAccount), false);

        skip(1);

        vm.expectRevert();
        vm.prank(accountAdmin);
        openfortAccount.proposeGuardian(friendAccount);

        // Now let's check that, even after the revert, it is possible to confirm the proposal (no DoS)
        skip(SECURITY_PERIOD);
        openfortAccount.confirmGuardianProposal(friendAccount);

        // Verify that the number of guardians is now 2
        assertEq(openfortAccount.guardianCount(), 2);

        // Friend account should not be a guardian yet
        assertEq(openfortAccount.isGuardian(friendAccount), true);
    }

    /*
     * Test proposing a guardian and cancel its proposal before accepting or expiring
     * Only the owner can cancel an ongoing proposal.
     */
    function testAddEOAGuardianCancel() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

        // Verify that the number of guardians is 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);

        // Create a friend EOA
        address friendAccount = makeAddr("friend");

        // Trying to propose a guardian not using the owner
        vm.expectRevert("Ownable: caller is not the owner");
        openfortAccount.proposeGuardian(friendAccount);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        openfortAccount.proposeGuardian(friendAccount);

        // Verify that the number of guardians is still 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);
        // Friend account should not be a guardian yet
        assertEq(openfortAccount.isGuardian(friendAccount), false);

        skip(1);
        vm.expectRevert(PendingProposalNotOver.selector);
        openfortAccount.confirmGuardianProposal(friendAccount);

        skip(SECURITY_PERIOD);
        vm.expectRevert("Ownable: caller is not the owner");
        openfortAccount.cancelGuardianProposal(friendAccount);

        vm.expectEmit(true, true, false, true);
        emit GuardianProposalCancelled(friendAccount);
        vm.prank(accountAdmin);
        openfortAccount.cancelGuardianProposal(friendAccount);

        // Verify that the number of guardians is still 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);
        // Friend account should not be a guardian yet
        assertEq(openfortAccount.isGuardian(friendAccount), false);

        vm.prank(accountAdmin);
        vm.expectRevert(UnknownProposal.selector);
        openfortAccount.confirmGuardianProposal(friendAccount);

        // Verify that the number of guardians is still 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);
        // Friend account should not be a guardian yet
        assertEq(openfortAccount.isGuardian(friendAccount), false);
    }

    /*
     * Test proposing owner as guardian. It should revert.
     * Successfully propose a guardian and confirm it after SECURITY_PERIOD
     */
    function testAddOwnerAsGuardianNotAllowed() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

        openfortAccount.getGuardians();

        // Verify that the number of guardians is 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);

        // Expect revert because the owner cannot be proposed as guardian
        vm.expectRevert();
        vm.prank(accountAdmin);
        openfortAccount.proposeGuardian(accountAdmin);

        // Verify that the number of guardians is still 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);

        // Owner account should not be a guardian yet
        assertEq(openfortAccount.isGuardian(accountAdmin), false);

        // Expect revert because the default guardian cannot be proposed again
        vm.expectRevert(DuplicatedGuardian.selector);
        vm.prank(accountAdmin);
        openfortAccount.proposeGuardian(OPENFORT_GUARDIAN);

        // Verify that the number of guardians is still 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);

        // OPENFORT_GUARDIAN account should still be a guardian
        assertEq(openfortAccount.isGuardian(OPENFORT_GUARDIAN), true);
    }

    /*
     * Test proposing multiple guardians (by the owner) and accepting them afterwards (by the owner).
     * Successfully propose guardians and confirm them after SECURITY_PERIOD
     */
    function testAddMultipleEOAGuardians() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

        openfortAccount.getGuardians();

        // Verify that the number of guardians is 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);

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
            openfortAccount.proposeGuardian(friends[index]);
        }

        // Verify that the number of guardians is still 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);
        // Friend account should not be a guardian yet
        assertEq(openfortAccount.isGuardian(friends[0]), false);

        skip(1);
        skip(SECURITY_PERIOD);

        for (uint256 index = 0; index < friends.length; index++) {
            openfortAccount.confirmGuardianProposal(friends[index]);
        }

        // Verify that the number of guardians is now 6
        assertEq(openfortAccount.guardianCount(), 6);

        // First friend account should be a guardian now
        assertEq(openfortAccount.isGuardian(friends[0]), true);
    }

    /**
     * Revoke guardians tests *
     */

    /*
     * Test revoking a guardian using owner.
     * Only the owner can revoke a guardian.
     */
    function testRevokeGuardian() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

        // Verify that the number of guardians is 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);

        // Create a friend EOA
        address friendAccount = makeAddr("friend");

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        openfortAccount.proposeGuardian(friendAccount);

        skip(1);
        skip(SECURITY_PERIOD);
        openfortAccount.confirmGuardianProposal(friendAccount);

        // Verify that the number of guardians is now 2
        assertEq(openfortAccount.guardianCount(), 2);

        // Friend account should be a guardian now
        assertEq(openfortAccount.isGuardian(friendAccount), true);

        // Trying to revoke a guardian not using the owner
        vm.expectRevert("Ownable: caller is not the owner");
        openfortAccount.revokeGuardian(friendAccount);

        // Trying to revoke a non-existent guardian (random beneficiary address)
        vm.expectRevert(MustBeGuardian.selector);
        vm.prank(accountAdmin);
        openfortAccount.revokeGuardian(beneficiary);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianRevocationRequested(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        openfortAccount.revokeGuardian(friendAccount);

        // Anyone can confirm a revocation. However, the security period has not passed yet
        skip(1);
        vm.expectRevert(PendingRevokeNotOver.selector);
        openfortAccount.confirmGuardianRevocation(friendAccount);

        // Anyone can confirm a revocation after security period
        skip(SECURITY_PERIOD);
        openfortAccount.confirmGuardianRevocation(friendAccount);

        // Friend account is not a guardian anymore
        assertEq(openfortAccount.isGuardian(friendAccount), false);
        // Verify that the number of guardians is 1 again
        assertEq(openfortAccount.guardianCount(), 1);
    }

    /*
     * Test revoking the default guardian when having registered another (custom) one.
     * Only the owner can revoke a guardian.
     */
    function testRevokeDefaultGuardian() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

        openfortAccount.getGuardians();

        // Verify that the number of guardians is 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);

        // Create a friend EOA
        address friendAccount = makeAddr("friend");

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        openfortAccount.proposeGuardian(friendAccount);

        skip(1);
        skip(SECURITY_PERIOD);
        openfortAccount.confirmGuardianProposal(friendAccount);

        // Verify that the number of guardians is now 2
        assertEq(openfortAccount.guardianCount(), 2);

        // Friend account should be a guardian now
        assertEq(openfortAccount.isGuardian(friendAccount), true);

        // Trying to revoke a guardian not using the owner
        vm.expectRevert("Ownable: caller is not the owner");
        openfortAccount.revokeGuardian(OPENFORT_GUARDIAN);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianRevocationRequested(OPENFORT_GUARDIAN, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        openfortAccount.revokeGuardian(OPENFORT_GUARDIAN);

        // Anyone can confirm a revocation. However, the security period has not passed yet
        skip(1);
        vm.expectRevert(PendingRevokeNotOver.selector);
        openfortAccount.confirmGuardianRevocation(OPENFORT_GUARDIAN);

        // Anyone can confirm a revocation after security period
        skip(SECURITY_PERIOD);
        openfortAccount.confirmGuardianRevocation(OPENFORT_GUARDIAN);

        // Default account is not a guardian anymore
        assertEq(openfortAccount.isGuardian(OPENFORT_GUARDIAN), false);
        // Verify that the number of guardians is 1 again
        assertEq(openfortAccount.guardianCount(), 1);
    }

    /*
     * Test revoking all guardians using owner.
     * Only the owner can revoke a guardian.
     */
    function testRevokeAllGuardians() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

        // Verify that the number of guardians is 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);

        // Create a friend EOA
        address friendAccount = makeAddr("friend");

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        openfortAccount.proposeGuardian(friendAccount);

        skip(1);
        skip(SECURITY_PERIOD);
        openfortAccount.confirmGuardianProposal(friendAccount);

        // Verify that the number of guardians is now 2
        assertEq(openfortAccount.guardianCount(), 2);

        // Friend account should be a guardian now
        assertEq(openfortAccount.isGuardian(friendAccount), true);

        // Trying to revoke a guardian not using the owner
        vm.expectRevert("Ownable: caller is not the owner");
        openfortAccount.revokeGuardian(friendAccount);

        // Trying to revoke a non-existent guardian (random beneficiary address)
        vm.expectRevert(MustBeGuardian.selector);
        vm.prank(accountAdmin);
        openfortAccount.revokeGuardian(beneficiary);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianRevocationRequested(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        openfortAccount.revokeGuardian(friendAccount);

        // Anyone can confirm a revocation. However, the security period has not passed yet
        skip(1);
        vm.expectRevert(PendingRevokeNotOver.selector);
        openfortAccount.confirmGuardianRevocation(friendAccount);

        // Anyone can confirm a revocation after security period
        skip(SECURITY_PERIOD);
        openfortAccount.confirmGuardianRevocation(friendAccount);

        // Friend account is not a guardian anymore
        assertEq(openfortAccount.isGuardian(friendAccount), false);
        // Verify that the number of guardians is 1 again
        assertEq(openfortAccount.guardianCount(), 1);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianRevocationRequested(OPENFORT_GUARDIAN, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        openfortAccount.revokeGuardian(OPENFORT_GUARDIAN);

        // Anyone can confirm a revocation. However, the security period has not passed yet
        skip(1);
        vm.expectRevert(PendingRevokeNotOver.selector);
        openfortAccount.confirmGuardianRevocation(OPENFORT_GUARDIAN);

        // Anyone can confirm a revocation after security period
        skip(SECURITY_PERIOD);
        openfortAccount.confirmGuardianRevocation(OPENFORT_GUARDIAN);

        // Default account is not a guardian anymore
        assertEq(openfortAccount.isGuardian(OPENFORT_GUARDIAN), false);
        // Verify that the number of guardians is 1 again
        assertEq(openfortAccount.guardianCount(), 0);
    }

    /*
     * Test revoking a guardian, but its revocation expired before confirming.
     * An expired revocation cannot be confirmed. A revocation expires after SECURITY_PERIOD + SECURITY_WINDOW.
     */
    function testRevokeEOAGuardianExpired() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

        // Verify that the number of guardians is 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);

        // Create a friend EOA
        address friendAccount = makeAddr("friend");

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        openfortAccount.proposeGuardian(friendAccount);

        skip(1);
        skip(SECURITY_PERIOD);
        openfortAccount.confirmGuardianProposal(friendAccount);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianRevocationRequested(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        openfortAccount.revokeGuardian(friendAccount);

        skip(1);
        skip(SECURITY_PERIOD + SECURITY_WINDOW);
        vm.expectRevert(PendingRevokeExpired.selector);
        openfortAccount.confirmGuardianRevocation(friendAccount);

        // Verify that the number of guardians is still 2. No revocation took place
        assertEq(openfortAccount.guardianCount(), 2);

        // Friend account should still be a guardian
        assertEq(openfortAccount.isGuardian(friendAccount), true);
    }

    /*
     * Test revoking a guardian twice. Make sure a new revocation is not created and the original still works.
     * An expired revocation cannot be confirmed. A revocation expires after SECURITY_PERIOD and SECURITY_WINDOW.
     */
    function testRevokeEOAGuardianDuplicatedPorposal() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

        // Verify that the number of guardians is 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);

        // Create a friend EOA
        address friendAccount = makeAddr("friend");

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        openfortAccount.proposeGuardian(friendAccount);

        skip(1);
        skip(SECURITY_PERIOD);
        openfortAccount.confirmGuardianProposal(friendAccount);

        // Verify that the number of guardians is now 2
        assertEq(openfortAccount.guardianCount(), 2);
        // Friend account should now be a guardian
        assertEq(openfortAccount.isGuardian(friendAccount), true);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianRevocationRequested(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        // Now let's check that, even after the revert, it is possible to confirm the proposal (no DoS)
        openfortAccount.revokeGuardian(friendAccount);

        vm.expectRevert(DuplicatedRevoke.selector);
        skip(1);
        vm.prank(accountAdmin);
        openfortAccount.revokeGuardian(friendAccount);

        skip(SECURITY_PERIOD);
        openfortAccount.confirmGuardianRevocation(friendAccount);

        // Verify that the number of guardians is now 1
        assertEq(openfortAccount.guardianCount(), 1);
        // Friend account should not be a guardian anymore
        assertEq(openfortAccount.isGuardian(friendAccount), false);
    }

    /*
     * Test revoking the default guardian and add it back.
     */
    function testRevokeDefaultGuardianAndAddBack() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

        // Verify that the number of guardians is 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianRevocationRequested(OPENFORT_GUARDIAN, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        // Now let's check that, even after the revert, it is possible to confirm the proposal (no DoS)
        openfortAccount.revokeGuardian(OPENFORT_GUARDIAN);

        skip(SECURITY_PERIOD + 1);
        openfortAccount.confirmGuardianRevocation(OPENFORT_GUARDIAN);

        // Verify that the number of guardians is now 0
        assertEq(openfortAccount.guardianCount(), 0);
        // default (openfort) account should not be a guardian anymore
        assertEq(openfortAccount.isGuardian(OPENFORT_GUARDIAN), false);

        // Expect that we will see an event containing the default (openfort) account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(OPENFORT_GUARDIAN, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        openfortAccount.proposeGuardian(OPENFORT_GUARDIAN);

        skip(SECURITY_PERIOD + 1);
        openfortAccount.confirmGuardianProposal(OPENFORT_GUARDIAN);

        // Verify that the number of guardians is now 1 again
        assertEq(openfortAccount.guardianCount(), 1);
        // default (openfort) account should be a guardian again
        assertEq(openfortAccount.isGuardian(OPENFORT_GUARDIAN), true);
    }

    /*
     * Test revoking a guardian using owner and cancel before confirming.
     * Only the owner can revoke a guardian and cancel its revocation before confirming.
     */
    function testCancelRevokeGuardian() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

        // Verify that the number of guardians is 1 (default)
        assertEq(openfortAccount.guardianCount(), 1);

        // Create a friend EOA
        address friendAccount = makeAddr("friend");

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        openfortAccount.proposeGuardian(friendAccount);

        skip(1);
        skip(SECURITY_PERIOD);
        openfortAccount.confirmGuardianProposal(friendAccount);

        // Verify that the number of guardians is now 2
        assertEq(openfortAccount.guardianCount(), 2);
        // Friend account should be a guardian now
        assertEq(openfortAccount.isGuardian(friendAccount), true);

        // Trying to revoke a guardian not using the owner
        vm.expectRevert("Ownable: caller is not the owner");
        openfortAccount.revokeGuardian(friendAccount);

        // Trying to revoke a non-existent guardian (random beneficiary address)
        vm.expectRevert(MustBeGuardian.selector);
        vm.prank(accountAdmin);
        openfortAccount.revokeGuardian(beneficiary);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianRevocationRequested(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        openfortAccount.revokeGuardian(friendAccount);

        // Anyone can confirm a revocation. However, the security period has not passed yet
        skip(1);
        vm.expectRevert(PendingRevokeNotOver.selector);
        openfortAccount.confirmGuardianRevocation(friendAccount);

        vm.expectRevert("Ownable: caller is not the owner");
        openfortAccount.cancelGuardianRevocation(friendAccount);

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianRevocationCancelled(friendAccount);
        vm.prank(accountAdmin);
        openfortAccount.cancelGuardianRevocation(friendAccount);

        // Friend account is not a guardian anymore
        assertEq(openfortAccount.isGuardian(friendAccount), true);
        // Verify that the number of guardians is 1 again
        assertEq(openfortAccount.guardianCount(), 2);

        // Cancelled revocation should not be able to be confirmed now
        skip(SECURITY_PERIOD);
        vm.expectRevert(UnknownRevoke.selector);
        openfortAccount.confirmGuardianRevocation(friendAccount);
    }

    /*
     * Random extra tests to mess up with the logic
     */
    function testMessingUpWithGuardianRegister() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

        // Create 4 friends
        address friendAccount;
        uint256 friendAccountPK;
        (friendAccount, friendAccountPK) = makeAddrAndKey("friend");

        address friendAccount2;
        uint256 friendAccount2PK;
        (friendAccount2, friendAccount2PK) = makeAddrAndKey("friend2");

        // Adding and removing guardians
        vm.startPrank(accountAdmin);
        openfortAccount.proposeGuardian(friendAccount);
        openfortAccount.proposeGuardian(friendAccount2);
        vm.stopPrank();

        skip(SECURITY_PERIOD + 1);
        openfortAccount.confirmGuardianProposal(friendAccount);

        // Try to confirm a non-existent revocation
        vm.expectRevert(MustBeGuardian.selector);
        openfortAccount.confirmGuardianRevocation(friendAccount2);
        // Try to confirm a non-existent revocation
        vm.expectRevert(UnknownRevoke.selector);
        openfortAccount.confirmGuardianRevocation(friendAccount);

        vm.prank(accountAdmin);
        vm.expectRevert(MustBeGuardian.selector);
        openfortAccount.revokeGuardian(friendAccount2); // Notice this tries to revoke a non-existent guardian!
        vm.expectRevert(DuplicatedGuardian.selector);
        vm.prank(accountAdmin);
        openfortAccount.proposeGuardian(friendAccount); // Notice this tries to register a guardian AGAIN!
        vm.prank(accountAdmin);
        openfortAccount.revokeGuardian(friendAccount); // Starting a valid revocation process
        skip(SECURITY_PERIOD + 1);
        // Try to confirm a guardian that is already valid and pending to revoke
        vm.expectRevert(DuplicatedGuardian.selector);
        openfortAccount.confirmGuardianProposal(friendAccount);
    }

    /**
     * Recovery tests *
     */

    /*
     * Check the correct functionality of startRecovery()
     */
    function testStartRecovery() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

        vm.expectRevert(MustBeGuardian.selector);
        openfortAccount.startRecovery(OPENFORT_GUARDIAN);

        vm.prank(OPENFORT_GUARDIAN);
        vm.expectRevert(GuardianCannotBeOwner.selector);
        openfortAccount.startRecovery(OPENFORT_GUARDIAN);

        vm.prank(OPENFORT_GUARDIAN);
        openfortAccount.startRecovery(address(beneficiary));

        assertEq(openfortAccount.isLocked(), true);
    }

    /*
     * Checks that incorrect parameters should always fail when trying to complete a recovery
     */
    function testBasicChecksCompleteRecovery() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

        vm.prank(OPENFORT_GUARDIAN);
        openfortAccount.startRecovery(address(beneficiary));

        assertEq(openfortAccount.isLocked(), true);

        // The recovery time period has not passed. The user should wait to recover.
        vm.expectRevert(OngoingRecovery.selector);
        bytes[] memory signatures = new bytes[](1);
        openfortAccount.completeRecovery(signatures);

        // Providing an empty array when it is expecting one guardian
        skip(RECOVERY_PERIOD + 1);
        vm.expectRevert(InvalidSignatureAmount.selector);
        bytes[] memory signatures_wrong_length = new bytes[](3);
        openfortAccount.completeRecovery(signatures_wrong_length);

        // Since signatures are empty, it should return an ECDSA error
        vm.expectRevert("ECDSA: invalid signature length");
        openfortAccount.completeRecovery(signatures);
    }

    /*
     * Most basic, yet complete, recovery flow
     * The default Openfort guardian is used to start and complete a recovery process.
     * Ownership is transferred to beneficiary
     */
    function testBasicCompleteRecovery() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

        // Default Openfort guardian starts a recovery process because the owner lost the PK
        vm.prank(OPENFORT_GUARDIAN);
        openfortAccount.startRecovery(address(beneficiary));
        assertEq(openfortAccount.isLocked(), true);

        bytes32 structHash = keccak256(
            abi.encode(RECOVER_TYPEHASH, address(beneficiary), uint64(block.timestamp + RECOVERY_PERIOD), uint32(1))
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = getEIP712SignatureFrom(account, structHash, OPENFORT_GUARDIAN_PKEY);

        skip(RECOVERY_PERIOD + 1);
        openfortAccount.completeRecovery(signatures);

        assertEq(openfortAccount.isLocked(), false);
        assertEq(openfortAccount.owner(), address(beneficiary));
    }

    /*
     * Case: User added 2 guardians and keeps the default (Openfort)
     * The 2 added guardians (friends) are used to recover the account and transfer
     * the ownership to beneficiary
     * @notice Remember that signatures need to be ordered by the guardian's address.
     */
    function test3GuardiansCompleteRecovery() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

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
            openfortAccount.proposeGuardian(friendAccount);
            vm.expectEmit(true, true, false, true);
            emit GuardianProposed(friendAccount2, block.timestamp + SECURITY_PERIOD);
            vm.prank(accountAdmin);
            openfortAccount.proposeGuardian(friendAccount2);

            skip(1);
            skip(SECURITY_PERIOD);
            openfortAccount.confirmGuardianProposal(friendAccount);
            openfortAccount.confirmGuardianProposal(friendAccount2);
        }

        {
            // Default Openfort guardian starts a recovery process because the owner lost the PK
            vm.prank(OPENFORT_GUARDIAN);
            openfortAccount.startRecovery(address(beneficiary));
            assertEq(openfortAccount.isLocked(), true);
        }

        bytes32 structHash = keccak256(
            abi.encode(RECOVER_TYPEHASH, address(beneficiary), uint64(block.timestamp + RECOVERY_PERIOD), uint32(2))
        );

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = getEIP712SignatureFrom(account, structHash, friendAccount2PK); // Using friendAccount2 first because it has a lower address
        signatures[1] = getEIP712SignatureFrom(account, structHash, friendAccountPK);

        skip(RECOVERY_PERIOD + 1);
        openfortAccount.completeRecovery(signatures);

        assertEq(openfortAccount.isLocked(), false);
        assertEq(openfortAccount.owner(), address(beneficiary));
    }

    /*
     * Case: User added 2 guardians and keeps the default (Openfort)
     * The 2 added guardians (friends) are used to recover the account and transfer
     * the ownership to beneficiary. Faild due to unsorted signatures
     * @notice Remember that signatures need to be ordered by the guardian's address.
     */
    function test3GuardiansUnorderedCompleteRecovery() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

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
            openfortAccount.proposeGuardian(friendAccount);
            vm.expectEmit(true, true, false, true);
            emit GuardianProposed(friendAccount2, block.timestamp + SECURITY_PERIOD);
            vm.prank(accountAdmin);
            openfortAccount.proposeGuardian(friendAccount2);

            skip(1);
            skip(SECURITY_PERIOD);
            openfortAccount.confirmGuardianProposal(friendAccount);
            openfortAccount.confirmGuardianProposal(friendAccount2);
        }

        {
            // Default Openfort guardian starts a recovery process because the owner lost the PK
            vm.prank(OPENFORT_GUARDIAN);
            openfortAccount.startRecovery(address(beneficiary));
            assertEq(openfortAccount.isLocked(), true);
        }

        bytes32 structHash = keccak256(
            abi.encode(RECOVER_TYPEHASH, address(beneficiary), uint64(block.timestamp + RECOVERY_PERIOD), uint32(2))
        );

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = getEIP712SignatureFrom(account, structHash, friendAccountPK); // Unsorted!
        signatures[1] = getEIP712SignatureFrom(account, structHash, friendAccount2PK);

        skip(RECOVERY_PERIOD + 1);
        vm.expectRevert(InvalidRecoverySignatures.selector);
        openfortAccount.completeRecovery(signatures);

        // it should still be locked and the admin still be the same
        assertEq(openfortAccount.isLocked(), true);
        assertEq(openfortAccount.owner(), accountAdmin);
    }

    /*
     * Case: User added 4 guardians and removes the default (Openfort)
     * One guardian (friend) is used to start a recovery process
     * The guardian that initiated the recovery + another one are used to complete the flow.
     * @notice Remember that signatures need to be ordered by the guardian's address.
     */
    function test4GuardiansNoDefaultCompleteRecovery() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

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
            openfortAccount.proposeGuardian(friendAccount);
            openfortAccount.proposeGuardian(friendAccount2);
            openfortAccount.proposeGuardian(friendAccount3);
            openfortAccount.proposeGuardian(friendAccount4);
            vm.stopPrank();

            skip(SECURITY_PERIOD + 1);
            openfortAccount.confirmGuardianProposal(friendAccount);
            openfortAccount.confirmGuardianProposal(friendAccount2);
            openfortAccount.confirmGuardianProposal(friendAccount3);
            openfortAccount.confirmGuardianProposal(friendAccount4);

            vm.prank(accountAdmin);
            openfortAccount.revokeGuardian(OPENFORT_GUARDIAN);
            vm.expectRevert(PendingRevokeNotOver.selector);
            openfortAccount.confirmGuardianRevocation(OPENFORT_GUARDIAN);
            skip(SECURITY_PERIOD + 1);
            openfortAccount.confirmGuardianRevocation(OPENFORT_GUARDIAN);
        }

        // Start the recovery process
        {
            // Default Openfort guardian tries starts a recovery process because the owner lost the PK
            // It should not work as it is not a guardian anymore
            vm.expectRevert(MustBeGuardian.selector);
            vm.prank(OPENFORT_GUARDIAN);
            openfortAccount.startRecovery(address(beneficiary));
            vm.prank(friendAccount2);
            openfortAccount.startRecovery(address(beneficiary));
            assertEq(openfortAccount.isLocked(), true);
        }

        bytes32 structHash = keccak256(
            abi.encode(RECOVER_TYPEHASH, address(beneficiary), uint64(block.timestamp + RECOVERY_PERIOD), uint32(2))
        );

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = getEIP712SignatureFrom(account, structHash, friendAccount2PK); // Using friendAccount2 first because it has a lower address
        signatures[1] = getEIP712SignatureFrom(account, structHash, friendAccountPK);

        skip(RECOVERY_PERIOD + 1);
        openfortAccount.completeRecovery(signatures);

        assertEq(openfortAccount.isLocked(), false);
        assertEq(openfortAccount.owner(), address(beneficiary));
    }

    /*
     * Case: User added 2 guardians and keeps the default (Openfort)
     * The 2 added guardians (friends) are used to recover the account and transfer
     * the ownership to beneficiary. Wrong signatures used
     * @notice Remember that signatures need to be ordered by the guardian's address.
     */
    function test3GuardiansFailCompleteRecovery() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

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
            openfortAccount.proposeGuardian(friendAccount);
            vm.expectEmit(true, true, false, true);
            emit GuardianProposed(friendAccount2, block.timestamp + SECURITY_PERIOD);
            vm.prank(accountAdmin);
            openfortAccount.proposeGuardian(friendAccount2);

            skip(1);
            skip(SECURITY_PERIOD);
            openfortAccount.confirmGuardianProposal(friendAccount);
            openfortAccount.confirmGuardianProposal(friendAccount2);
        }

        {
            // Default Openfort guardian starts a recovery process because the owner lost the PK
            vm.prank(OPENFORT_GUARDIAN);
            openfortAccount.startRecovery(address(beneficiary));
            assertEq(openfortAccount.isLocked(), true);
        }

        // notice: wrong new oner!!!
        bytes32 structHash =
            keccak256(abi.encode(RECOVER_TYPEHASH, factoryAdmin, uint64(block.timestamp + RECOVERY_PERIOD), uint32(2)));

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = getEIP712SignatureFrom(account, structHash, friendAccount2PK); // Using friendAccount2 first because it has a lower address
        signatures[1] = getEIP712SignatureFrom(account, structHash, friendAccountPK);

        skip(RECOVERY_PERIOD + 1);
        vm.expectRevert(InvalidRecoverySignatures.selector);
        openfortAccount.completeRecovery(signatures);

        // it should still be locked and the admin still be the same
        assertEq(openfortAccount.isLocked(), true);
        assertEq(openfortAccount.owner(), accountAdmin);
    }

    /*
     * Testing the functionality to cancel a recovery process
     */
    function testCancelRecovery() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

        // Default Openfort guardian starts a recovery process because the owner lost the PK
        vm.prank(OPENFORT_GUARDIAN);
        openfortAccount.startRecovery(address(beneficiary));
        assertEq(openfortAccount.isLocked(), true);

        vm.expectRevert("Ownable: caller is not the owner");
        openfortAccount.cancelRecovery();

        vm.prank(accountAdmin);
        openfortAccount.cancelRecovery();

        bytes32 structHash = keccak256(
            abi.encode(RECOVER_TYPEHASH, address(beneficiary), uint64(block.timestamp + RECOVERY_PERIOD), uint32(1))
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = getEIP712SignatureFrom(account, structHash, OPENFORT_GUARDIAN_PKEY);

        skip(RECOVERY_PERIOD + 1);
        vm.expectRevert(NoOngoingRecovery.selector);
        openfortAccount.completeRecovery(signatures);

        assertEq(openfortAccount.isLocked(), false);
        assertEq(openfortAccount.owner(), accountAdmin);
    }

    /*
     * Testing the startRecovery twice in a row
     */
    function testStartRecoveryTwice() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

        // Default Openfort guardian starts a recovery process because the owner lost the PK
        vm.prank(OPENFORT_GUARDIAN);
        openfortAccount.startRecovery(address(beneficiary));
        assertEq(openfortAccount.isLocked(), true);

        // Calling startRecovery() again should revert and have no effect
        vm.expectRevert(OngoingRecovery.selector);
        vm.prank(OPENFORT_GUARDIAN);
        openfortAccount.startRecovery(address(beneficiary));

        // The accounts should still be locked
        assertEq(openfortAccount.isLocked(), true);
        assertEq(openfortAccount.owner(), accountAdmin);
    }

    /**
     * Transfer ownership tests *
     */

    /*
     * Try to transfer ownership to a guardian.
     * Should not be allowed.
     */
    function testTransferOwnerNotGuardian() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

        // Create a friend EOA
        address friendAccount = makeAddr("friend");

        // Expect that we will see an event containing the friend account and security period
        vm.expectEmit(true, true, false, true);
        emit GuardianProposed(friendAccount, block.timestamp + SECURITY_PERIOD);
        vm.prank(accountAdmin);
        openfortAccount.proposeGuardian(friendAccount);

        skip(1);
        skip(SECURITY_PERIOD);
        openfortAccount.confirmGuardianProposal(friendAccount);

        // It should fail as friendAccount is a guardian
        vm.expectRevert(GuardianCannotBeOwner.selector);
        openfortAccount.transferOwnership(friendAccount);
    }

    /*
     * Try to transfer ownership to a valid account.
     * Should be allowed.
     */
    function testTransferOwner() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));

        // Create a new owner EOA
        address newOwner = makeAddr("newOwner");

        vm.expectRevert("Ownable: caller is not the owner");
        openfortAccount.transferOwnership(newOwner);

        vm.prank(accountAdmin);
        openfortAccount.transferOwnership(newOwner);

        vm.prank(newOwner);
        openfortAccount.acceptOwnership();

        // New owner should be now newOwner
        assertEq(openfortAccount.owner(), address(newOwner));
    }

    /*
     * Temporal test function for coverage purposes showing
     * that isGuardianOrGuardianSigner() always returns false.
     */
    function testStubFakeMockTempisGuardian() public {
        ManagedOpenfortAccount openfortAccount = ManagedOpenfortAccount(payable(account));
        assertEq(openfortAccount.isGuardianOrGuardianSigner(OPENFORT_GUARDIAN), false);
    }
}
