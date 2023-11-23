// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {console} from "lib/forge-std/src/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {EntryPoint, IEntryPoint, UserOperation} from "account-abstraction/core/EntryPoint.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";
import {MockERC20} from "contracts/mock/MockERC20.sol";
import {IBaseRecoverableAccount} from "contracts/interfaces/IBaseRecoverableAccount.sol";
import {IUpgradeableOpenfortAccount} from "contracts/interfaces/IUpgradeableOpenfortAccount.sol";
import {OpenfortErrorsAndEvents} from "contracts/interfaces/OpenfortErrorsAndEvents.sol";
import {UpgradeableOpenfortAccount} from "contracts/core/upgradeable/UpgradeableOpenfortAccount.sol";
import {UpgradeableOpenfortFactory} from "contracts/core/upgradeable/UpgradeableOpenfortFactory.sol";
import {UpgradeableOpenfortProxy} from "contracts/core/upgradeable/UpgradeableOpenfortProxy.sol";
import {MockV2UpgradeableOpenfortAccount} from "contracts/mock/MockV2UpgradeableOpenfortAccount.sol";
import {OpenfortBaseTest} from "../OpenfortBaseTest.t.sol";

contract UpgradeableOpenfortAccountTest is OpenfortBaseTest {
    using ECDSA for bytes32;

    UpgradeableOpenfortAccount public upgradeableOpenfortAccountImpl;
    UpgradeableOpenfortFactory public openfortFactory;

    /**
     * @notice Initialize the UpgradeableOpenfortAccount testing contract.
     * Scenario:
     * - factoryAdmin is the deployer (and owner) of the UpgradeableOpenfortFactory
     * - accountAdmin is the account used to deploy new upgradeable accounts
     * - entryPoint is the singleton EntryPoint
     * - testCounter is the counter used to test userOps
     */
    function setUp() public {
        versionSalt = bytes32(0x0);
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
            EntryPoint entryPointAux = new EntryPoint();
            bytes memory code = address(entryPointAux).code;
            address targetAddr = address(vm.envAddress("ENTRY_POINT_ADDRESS"));
            vm.etch(targetAddr, code);
            entryPoint = EntryPoint(payable(targetAddr));
        }
        // deploy upgradeable account implementation
        vm.expectEmit(true, true, false, true);
        emit AccountImplementationDeployed(factoryAdmin);
        upgradeableOpenfortAccountImpl = new UpgradeableOpenfortAccount{salt: versionSalt}();
        // deploy upgradeable account factory
        openfortFactory = new UpgradeableOpenfortFactory{salt: versionSalt}(
            factoryAdmin,
            address(entryPoint),
            address(upgradeableOpenfortAccountImpl),
            RECOVERY_PERIOD,
            SECURITY_PERIOD,
            SECURITY_WINDOW,
            LOCK_PERIOD,
            OPENFORT_GUARDIAN
        );

        // Create an upgradeable account wallet and get its address
        accountAddress = openfortFactory.createAccountWithNonce(accountAdmin, "1");

        // deploy a new TestCounter
        testCounter = new TestCounter();
        // deploy a new MockERC20 (ERC20)
        mockERC20 = new MockERC20();
        vm.stopPrank();
    }

    /*
     * Should be able to stake and unstake
     */
    function testStakeFactory() public {
        vm.expectRevert("Ownable: caller is not the owner");
        openfortFactory.addStake{value: 1 ether}(10);

        vm.expectRevert("no stake specified");
        vm.prank(factoryAdmin);
        openfortFactory.addStake(10);

        vm.prank(factoryAdmin);
        openfortFactory.addStake{value: 1 ether}(10);

        vm.expectRevert("Ownable: caller is not the owner");
        openfortFactory.unlockStake();

        vm.prank(factoryAdmin);
        openfortFactory.unlockStake();

        vm.expectRevert("Ownable: caller is not the owner");
        openfortFactory.withdrawStake(payable(factoryAdmin));

        vm.expectRevert("Stake withdrawal is not due");
        vm.prank(factoryAdmin);
        openfortFactory.withdrawStake(payable(factoryAdmin));

        skip(11);

        vm.prank(factoryAdmin);
        openfortFactory.withdrawStake(payable(factoryAdmin));
    }

    /*
     * Should not be able to initialize the implementation
     */
    function testInitializeImplementation() public {
        assertEq(openfortFactory.implementation(), address(upgradeableOpenfortAccountImpl));
        vm.expectRevert("Initializable: contract is already initialized");
        upgradeableOpenfortAccountImpl.initialize(
            accountAdmin,
            address(entryPoint),
            RECOVERY_PERIOD,
            SECURITY_PERIOD,
            SECURITY_WINDOW,
            LOCK_PERIOD,
            OPENFORT_GUARDIAN
        );
    }

    /*
     * Create an account by directly calling the factory.
     */
    function testCreateAccountWithNonceViaFactory() public {
        // Get the counterfactual address
        vm.prank(factoryAdmin);
        address accountAddress2 = openfortFactory.getAddressWithNonce(accountAdmin, "2");

        // Expect that we will see an event containing the account and admin
        vm.expectEmit(true, true, false, true);
        emit AccountCreated(accountAddress2, accountAdmin);

        // Deploy a upgradeable account to the counterfactual address
        vm.prank(factoryAdmin);
        openfortFactory.createAccountWithNonce(accountAdmin, "2");

        // Calling it again should just return the address and not create another account
        vm.prank(factoryAdmin);
        openfortFactory.createAccountWithNonce(accountAdmin, "2");

        // Make sure the counterfactual address has not been altered
        vm.prank(factoryAdmin);
        assertEq(accountAddress2, openfortFactory.getAddressWithNonce(accountAdmin, "2"));
    }

    /*
     * Create an account by directly calling the factory by fuzzing the admin and nonce parameters.
     */
    function testFuzzCreateAccountWithNonceViaFactory(address _adminAddress, bytes32 _nonce) public {
        // Get the counterfactual address
        vm.prank(factoryAdmin);
        address accountAddress2 = openfortFactory.getAddressWithNonce(_adminAddress, _nonce);

        // Expect that we will see an event containing the account and admin
        if (_adminAddress == address(0)) {
            vm.expectRevert();
        } else {
            vm.expectEmit(true, true, false, true);
            emit AccountCreated(accountAddress2, _adminAddress);

            // Deploy a upgradeable account to the counterfactual address
            vm.prank(factoryAdmin);
            openfortFactory.createAccountWithNonce(_adminAddress, _nonce);

            // Calling it again should just return the address and not create another account
            vm.prank(factoryAdmin);
            openfortFactory.createAccountWithNonce(_adminAddress, _nonce);
            // Make sure the counterfactual address has not been altered
            vm.prank(factoryAdmin);
            assertEq(accountAddress2, openfortFactory.getAddressWithNonce(_adminAddress, _nonce));
        }
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
        address account2 = openfortFactory.getAddressWithNonce(accountAdmin, bytes32("2"));
        assertEq(account2.code.length, 0);

        bytes memory initCallData =
            abi.encodeWithSignature("createAccountWithNonce(address,bytes32)", accountAdmin, bytes32("2"));
        bytes memory initCode = abi.encodePacked(abi.encodePacked(address(openfortFactory)), initCallData);

        UserOperation[] memory userOpCreateAccount =
            _setupUserOpExecute(account2, accountAdminPKey, initCode, address(0), 0, bytes(""));

        // Expect that we will see an event containing the account and admin
        vm.expectEmit(true, true, false, true);
        emit AccountCreated(account2, accountAdmin);

        entryPoint.handleOps(userOpCreateAccount, beneficiary);

        // Make sure the smart account does have some code now
        assert(account2.code.length > 0);

        // Make sure the counterfactual address has not been altered
        assertEq(account2, openfortFactory.getAddressWithNonce(accountAdmin, bytes32("2")));
    }

    /*
     * Create an account using the factory and make it call count() directly.
     */
    function testIncrementCounterDirect() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(accountAddress), 0);

        // Make the admin of the upgradeable account wallet (deployer) call "count"
        vm.prank(accountAdmin);
        IBaseRecoverableAccount(payable(accountAddress)).execute(
            address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        // Verify that the counter has increased
        assertEq(testCounter.counters(accountAddress), 1);
    }

    /*
     * Create an account by directly calling the factory and make it call count()
     * using the execute() function using the EntryPoint (userOp). Leveraging ERC-4337.
     */
    function testIncrementCounterViaEntrypoint() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(accountAddress), 0);

        UserOperation[] memory userOp = _setupUserOpExecute(
            accountAddress, accountAdminPKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has increased
        assertEq(testCounter.counters(accountAddress), 1);
    }

    /*
     * Create an account by directly calling the factory and make it call count()
     * using the executeBatching() function using the EntryPoint (userOp). Leveraging ERC-4337.
     */
    function testIncrementCounterViaEntrypointBatching() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(accountAddress), 0);

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
            _setupUserOpExecuteBatch(accountAddress, accountAdminPKey, bytes(""), targets, values, callData);

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has increased
        assertEq(testCounter.counters(accountAddress), count);
    }

    /*
     * Use the executeBatch() with a too big number
     */
    function testFailBatchingBig() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(accountAddress), 0);

        uint256 count = 10;
        address[] memory targets = new address[](count);
        uint256[] memory values = new uint256[](count);
        bytes[] memory callData = new bytes[](count);

        for (uint256 i = 0; i < count; i += 1) {
            targets[i] = address(testCounter);
            values[i] = 0;
            callData[i] = abi.encodeWithSignature("count()");
        }

        UserOperation[] memory userOp =
            _setupUserOpExecuteBatch(accountAddress, accountAdminPKey, bytes(""), targets, values, callData);

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has increased
        assertEq(testCounter.counters(accountAddress), count);
    }

    /*
     *  Should fail, try to use a sessionKey that is not registered.
     */
    function testFailIncrementCounterViaSessionKeyNotregistered() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(accountAddress), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        UserOperation[] memory userOp = _setupUserOpExecute(
            accountAddress, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has not increased
        assertEq(testCounter.counters(accountAddress), 0);
    }

    /*
     * Use a sessionKey that is registered.
     */
    function testIncrementCounterViaSessionKey() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(accountAddress), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");
        address[] memory emptyWhitelist;

        vm.prank(accountAdmin);
        IBaseRecoverableAccount(payable(accountAddress)).registerSessionKey(
            sessionKey, 0, 2 ** 48 - 1, 100, emptyWhitelist
        );

        UserOperation[] memory userOp = _setupUserOpExecute(
            accountAddress, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has increased
        assertEq(testCounter.counters(accountAddress), 1);
    }

    /*
     * Register a sessionKey via userOp calling the execute() function
     * using the EntryPoint (userOp). Then use the sessionKey to count
     */
    function testRegisterSessionKeyViaEntrypoint() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(accountAddress), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");
        address[] memory emptyWhitelist;

        UserOperation[] memory userOp = _setupUserOp(
            accountAddress,
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

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has not increased
        assertEq(testCounter.counters(accountAddress), 0);

        userOp = _setupUserOpExecute(
            accountAddress, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has increased
        assertEq(testCounter.counters(accountAddress), 1);
    }

    /*
     * Register a master sessionKey via userOp calling the execute() function
     * using the EntryPoint (userOp). Then use that sessionKey to register a second one
     * Should not be allowed: session keys cannot register new session keys!
     */
    function testFailRegisterSessionKeyViaEntrypoint2ndKey() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(accountAddress), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");
        address[] memory emptyWhitelist;

        UserOperation[] memory userOp = _setupUserOp(
            accountAddress,
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

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has not increased
        assertEq(testCounter.counters(accountAddress), 0);

        userOp = _setupUserOpExecute(
            accountAddress, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has increased
        assertEq(testCounter.counters(accountAddress), 1);

        address sessionKeyAttack;
        uint256 sessionKeyPrivKeyAttack;
        (sessionKeyAttack, sessionKeyPrivKeyAttack) = makeAddrAndKey("sessionKeyAttack");

        userOp = _setupUserOp(
            accountAddress,
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

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);
    }

    /*
     * Register a limited sessionKey via userOp calling the execute() function
     * using the EntryPoint (userOp). Then use that sessionKey to register a second one
     */
    function testFailAttackRegisterSessionKeyViaEntrypoint2ndKey() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(accountAddress), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        UserOperation[] memory userOp = _setupUserOpExecute(
            accountAddress,
            accountAdminPKey,
            bytes(""),
            accountAddress,
            0,
            abi.encodeWithSignature("registerSessionKey(address,uint48,uint48,uint48)", sessionKey, 0, 2 ** 48 - 1, 10)
        );

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has not increased
        assertEq(testCounter.counters(accountAddress), 0);

        userOp = _setupUserOpExecute(
            accountAddress, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has increased
        assertEq(testCounter.counters(accountAddress), 1);

        // Verify that the registered key is not a MasterKey nor has whitelisting
        bool isMasterKey;
        bool isWhitelisted;
        (,,, isMasterKey, isWhitelisted,) = IBaseRecoverableAccount(payable(accountAddress)).sessionKeys(sessionKey);
        assert(!isMasterKey);
        assert(!isWhitelisted);

        address sessionKeyAttack;
        uint256 sessionKeyPrivKeyAttack;
        (sessionKeyAttack, sessionKeyPrivKeyAttack) = makeAddrAndKey("sessionKeyAttack");

        userOp = _setupUserOpExecute(
            accountAddress,
            sessionKeyPrivKey,
            bytes(""),
            accountAddress,
            0,
            abi.encodeWithSignature("registerSessionKey(address,uint48,uint48)", sessionKeyAttack, 0, 2 ** 48 - 1)
        );

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);
    }

    /*
     *  Should fail, try to use a sessionKey that is expired.
     */
    function testIncrementCounterViaSessionKeyExpired() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(accountAddress), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");
        address[] memory emptyWhitelist;

        vm.warp(100);
        vm.prank(accountAdmin);
        IBaseRecoverableAccount(payable(accountAddress)).registerSessionKey(sessionKey, 0, 99, 100, emptyWhitelist);

        UserOperation[] memory userOp = _setupUserOpExecute(
            accountAddress, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        vm.expectRevert();
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has not increased
        assertEq(testCounter.counters(accountAddress), 0);
    }

    /*
     *  Should fail, try to use a sessionKey that is revoked.
     */
    function testFailIncrementCounterViaSessionKeyRevoked() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(accountAddress), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");
        address[] memory emptyWhitelist;

        vm.prank(accountAdmin);
        IBaseRecoverableAccount(payable(accountAddress)).registerSessionKey(sessionKey, 0, 0, 100, emptyWhitelist);
        IBaseRecoverableAccount(payable(accountAddress)).revokeSessionKey(sessionKey);

        UserOperation[] memory userOp = _setupUserOpExecute(
            accountAddress, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has increased
        assertEq(testCounter.counters(accountAddress), 1);
    }

    /*
     *  Should fail, try to use a sessionKey that reached its limit.
     */
    function testFailIncrementCounterViaSessionKeyReachLimit() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(accountAddress), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");
        address[] memory emptyWhitelist;

        // We are now in block 100, but our session key is valid until block 150
        vm.warp(100);
        vm.prank(accountAdmin);
        IBaseRecoverableAccount(payable(accountAddress)).registerSessionKey(sessionKey, 0, 150, 1, emptyWhitelist);

        UserOperation[] memory userOp = _setupUserOpExecute(
            accountAddress, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        userOp = _setupUserOpExecute(
            accountAddress, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has only increased by one
        assertEq(testCounter.counters(accountAddress), 1);
    }

    /*
     *  Should fail, try to use a sessionKey that reached its limit.
     */
    function testFailIncrementCounterViaSessionKeyReachLimitBatching() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(accountAddress), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");
        address[] memory emptyWhitelist;

        // We are now in block 100, but our session key is valid until block 150
        vm.warp(100);
        vm.prank(accountAdmin);
        IBaseRecoverableAccount(payable(accountAddress)).registerSessionKey(sessionKey, 0, 150, 2, emptyWhitelist);

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
            _setupUserOpExecuteBatch(accountAddress, sessionKeyPrivKey, bytes(""), targets, values, callData);

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has not increased
        assertEq(testCounter.counters(accountAddress), 0);
    }

    /*
     *  Should fail, try to revoke a sessionKey using a non-privileged user
     */
    function testFailRevokeSessionKeyInvalidUser() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(accountAddress), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");
        address[] memory emptyWhitelist;

        vm.prank(accountAdmin);
        IBaseRecoverableAccount(payable(accountAddress)).registerSessionKey(sessionKey, 0, 0, 100, emptyWhitelist);
        vm.prank(beneficiary);
        IBaseRecoverableAccount(payable(accountAddress)).revokeSessionKey(sessionKey);

        UserOperation[] memory userOp = _setupUserOpExecute(
            accountAddress, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has increased
        assertEq(testCounter.counters(accountAddress), 1);
    }

    /*
     * Use a sessionKey with whitelisting to call Execute().
     */
    function testIncrementCounterViaSessionKeyWhitelisting() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(accountAddress), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        address[] memory whitelist = new address[](1);
        whitelist[0] = address(testCounter);
        vm.prank(accountAdmin);
        IBaseRecoverableAccount(payable(accountAddress)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1, 1, whitelist);

        UserOperation[] memory userOp = _setupUserOpExecute(
            accountAddress, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has increased
        assertEq(testCounter.counters(accountAddress), 1);
    }

    /*
     * Should fail, try to register a sessionKey with a large whitelist.
     */
    function testFailIncrementCounterViaSessionKeyWhitelistingTooBig() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(accountAddress), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        address[] memory whitelist = new address[](11);
        vm.prank(accountAdmin);
        IBaseRecoverableAccount(payable(accountAddress)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1, 1, whitelist);

        UserOperation[] memory userOp = _setupUserOpExecute(
            accountAddress, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has not increased
        assertEq(testCounter.counters(accountAddress), 0);
    }

    /*
     * Use a sessionKey with whitelisting to call ExecuteBatch().
     */
    function testIncrementCounterViaSessionKeyWhitelistingBatch() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(accountAddress), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        address[] memory whitelist = new address[](1);
        whitelist[0] = address(testCounter);
        vm.prank(accountAdmin);
        IBaseRecoverableAccount(payable(accountAddress)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1, 3, whitelist);

        // Verify that the registered key is not a MasterKey but has whitelisting
        bool isMasterKey;
        bool isWhitelisted;
        (,,, isMasterKey, isWhitelisted,) = IBaseRecoverableAccount(payable(accountAddress)).sessionKeys(sessionKey);
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
            _setupUserOpExecuteBatch(accountAddress, sessionKeyPrivKey, bytes(""), targets, values, callData);

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has increased
        assertEq(testCounter.counters(accountAddress), 3);
    }

    /*
     * Should fail, try to use a sessionKey with invalid whitelisting to call Execute().
     */
    function testFailIncrementCounterViaSessionKeyWhitelistingWrongAddress() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(accountAddress), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        address[] memory whitelist = new address[](1);
        whitelist[0] = address(accountAddress);
        vm.prank(accountAdmin);
        IBaseRecoverableAccount(payable(accountAddress)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1, 1, whitelist);

        UserOperation[] memory userOp = _setupUserOpExecute(
            accountAddress, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has increased
        assertEq(testCounter.counters(accountAddress), 1);
    }

    /*
     * Should fail, try to use a sessionKey with invalid whitelisting to call ExecuteBatch().
     */
    function testFailIncrementCounterViaSessionKeyWhitelistingBatchWrongAddress() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(accountAddress), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        address[] memory whitelist = new address[](1);
        whitelist[0] = address(accountAddress);
        vm.prank(accountAdmin);
        IBaseRecoverableAccount(payable(accountAddress)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1, 1, whitelist);

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
            accountAddress,
            sessionKeyPrivKey, //Sign the userOp using the sessionKey's private key
            bytes(""),
            targets,
            values,
            callData
        );

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has not increased
        assertEq(testCounter.counters(accountAddress), 0);
    }

    /*
     * Use a sessionKey with whitelisting to call ExecuteBatch() with 11 whitelisted addresses.
     * Fail due to too much whitelisted addresses.
     */
    function testTooManyWhitelist() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(accountAddress), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        address[] memory whitelist = new address[](11);
        for (uint256 i = 0; i < whitelist.length; i++) {
            whitelist[i] = address(testCounter);
        }
        vm.expectRevert("Whitelist too big");
        vm.prank(accountAdmin);
        UpgradeableOpenfortAccount(payable(accountAddress)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1, 3, whitelist);
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

        vm.expectRevert("Ownable: caller is not the owner");
        IBaseRecoverableAccount(payable(accountAddress)).transferOwnership(accountAdmin2);

        vm.prank(accountAdmin);
        IBaseRecoverableAccount(payable(accountAddress)).transferOwnership(accountAdmin2);
        vm.prank(accountAdmin2);
        IBaseRecoverableAccount(payable(accountAddress)).acceptOwnership();

        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(accountAddress), 0);

        // Make the admin of the upgradeable account wallet (deployer) call "count"
        vm.prank(accountAdmin2);
        IBaseRecoverableAccount(payable(accountAddress)).execute(
            address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        // Verify that the counter has increased
        assertEq(testCounter.counters(accountAddress), 1);
    }

    /*
     * Change the owner of an account and call TestCounter though the Entrypoint
     */
    function testChangeOwnershipAndCountEntryPoint() public {
        address accountAdmin2;
        uint256 accountAdmin2PKey;
        (accountAdmin2, accountAdmin2PKey) = makeAddrAndKey("accountAdmin2");

        vm.prank(accountAdmin);
        IBaseRecoverableAccount(payable(accountAddress)).transferOwnership(accountAdmin2);
        vm.prank(accountAdmin2);
        IBaseRecoverableAccount(payable(accountAddress)).acceptOwnership();

        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(accountAddress), 0);

        UserOperation[] memory userOp = _setupUserOpExecute(
            accountAddress, accountAdmin2PKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has increased
        assertEq(testCounter.counters(accountAddress), 1);
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
            accountAddress,
            accountAdminPKey,
            bytes(""),
            address(mockERC20),
            0,
            abi.encodeWithSignature("mint(address,uint256)", beneficiary, 1)
        );

        entryPoint.depositTo{value: 1 ether}(accountAddress);
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
        assertEq(address(accountAddress).balance, 0);

        vm.prank(accountAdmin);
        (bool success,) = payable(accountAddress).call{value: 1000}("");
        assert(success);
        assertEq(address(accountAddress).balance, 1000);
    }

    /*
     * Transfer native tokens out of an account.
     */
    function testTransferOutNativeToken() public {
        uint256 value = 1000;

        assertEq(address(accountAddress).balance, 0);
        vm.prank(accountAdmin);
        (bool success,) = payable(accountAddress).call{value: value}("");
        assertEq(address(accountAddress).balance, value);
        assert(success);
        assertEq(beneficiary.balance, 0);

        UserOperation[] memory userOp =
            _setupUserOpExecute(accountAddress, accountAdminPKey, bytes(""), address(beneficiary), value, bytes(""));

        EntryPoint(entryPoint).handleOps(userOp, beneficiary);
        assertEq(beneficiary.balance, value);
    }

    /*
     * Basic test of simulateValidation() to check that it always reverts.
     */
    function testSimulateValidation() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(accountAddress), 0);

        UserOperation[] memory userOp = _setupUserOpExecute(
            accountAddress, accountAdminPKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        // Expect the simulateValidation() to always revert
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);

        // Verify that the counter has not increased
        assertEq(testCounter.counters(accountAddress), 0);
    }

    /*
     * Create an account and upgrade its implementation
     */
    function testUpgradeAccount() public {
        assertEq(IBaseRecoverableAccount(payable(accountAddress)).owner(), address(accountAdmin));
        assertEq(address(IBaseRecoverableAccount(payable(accountAddress)).entryPoint()), address(entryPoint));
        MockV2UpgradeableOpenfortAccount newAccountImplementation = new MockV2UpgradeableOpenfortAccount();
        UpgradeableOpenfortProxy p = UpgradeableOpenfortProxy(payable(accountAddress));
        // Printing account address and the implementation address
        console.log("Account address (proxy): ", accountAddress);
        console.log("Implementation address (old): ", p.implementation());

        vm.expectRevert("Ownable: caller is not the owner");
        UpgradeableOpenfortAccount(payable(accountAddress)).upgradeTo(address(newAccountImplementation));

        vm.expectRevert();
        MockV2UpgradeableOpenfortAccount(payable(accountAddress)).easterEgg();

        vm.prank(accountAdmin);
        UpgradeableOpenfortAccount(payable(accountAddress)).upgradeTo(address(newAccountImplementation));

        // Notice that, even though we bind the address to the old implementation, entryPoint() is now changed
        assertEq(
            address(IBaseRecoverableAccount(payable(accountAddress)).entryPoint()),
            address(0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF)
        );

        assertEq(MockV2UpgradeableOpenfortAccount(payable(accountAddress)).easterEgg(), 42);

        vm.expectRevert("Ownable: caller is not the owner");
        IUpgradeableOpenfortAccount(payable(accountAddress)).updateEntryPoint(beneficiary);

        vm.expectRevert("disabled!");
        vm.prank(accountAdmin);
        IUpgradeableOpenfortAccount(payable(accountAddress)).updateEntryPoint(beneficiary);

        // Printing account address and the implementation address. Impl address should have changed
        console.log("Account address (proxy): ", accountAddress);
        console.log("Implementation address (new): ", p.implementation());
    }

    /*
     * 1- Deploy a factory using the old EntryPoint to create an account.
     * 2- Inform the account of the new EntryPoint by calling updateEntryPoint()
     */
    function testUpdateEntryPoint() public {
        bytes memory code = address(entryPoint).code;
        address oldEntryPoint = address(0x0576a174D229E3cFA37253523E645A78A0C91B57);
        vm.etch(oldEntryPoint, code); // Simulate there's code here
        address newEntryPoint = vm.envAddress("ENTRY_POINT_ADDRESS");
        UpgradeableOpenfortFactory openfortFactoryOld = new UpgradeableOpenfortFactory{salt: versionSalt}(
            factoryAdmin,
            oldEntryPoint,
            address(upgradeableOpenfortAccountImpl),
            RECOVERY_PERIOD,
            SECURITY_PERIOD,
            SECURITY_WINDOW,
            LOCK_PERIOD,
            OPENFORT_GUARDIAN
        );

        // Create an upgradeable account wallet using the old EntryPoint and get its address
        address payable oldAccountAddress = payable(openfortFactoryOld.createAccountWithNonce(accountAdmin, "999"));
        IUpgradeableOpenfortAccount upgradeableAccount = IUpgradeableOpenfortAccount(oldAccountAddress);
        assertEq(address(upgradeableAccount.entryPoint()), oldEntryPoint);

        vm.expectRevert("Ownable: caller is not the owner");
        upgradeableAccount.updateEntryPoint(newEntryPoint);

        vm.prank(accountAdmin);
        vm.expectRevert(OpenfortErrorsAndEvents.NotAContract.selector);
        upgradeableAccount.updateEntryPoint(address(0));

        vm.prank(accountAdmin);
        upgradeableAccount.updateEntryPoint(newEntryPoint);

        assertEq(address(upgradeableAccount.entryPoint()), newEntryPoint);
    }

    function testFailIsValidSignature() public {
        bytes32 hash = keccak256("Signed by Owner");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(accountAdminPKey, hash);
        address signer = ecrecover(hash, v, r, s);
        assertEq(accountAdmin, signer); // [PASS]

        bytes memory signature = abi.encodePacked(r, s, v);
        signer = ECDSA.recover(hash, signature);
        assertEq(accountAdmin, signer); // [PASS]

        bytes4 valid = IBaseRecoverableAccount(payable(accountAddress)).isValidSignature(hash, signature);
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

        bytes4 valid = IBaseRecoverableAccount(payable(accountAddress)).isValidSignature(hash, signature);
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
            IERC5267(accountAddress).eip712Domain();

        bytes32 domainSeparator = keccak256(
            abi.encode(_TYPE_HASH, keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifyingContract)
        );

        bytes memory signature = getEIP712SignatureFrom(accountAddress, structHash, accountAdminPKey);
        bytes32 hash712 = domainSeparator.toTypedDataHash(structHash);
        address signer = hash712.recover(signature);

        assertEq(accountAdmin, signer); // [PASS]

        bytes4 valid = IBaseRecoverableAccount(payable(accountAddress)).isValidSignature(hash, signature);
        assertEq(valid, MAGICVALUE); // SHOULD PASS
    }

    function testAddDeposit() public {
        IBaseRecoverableAccount account = IBaseRecoverableAccount(payable(accountAddress));
        assertEq(0, account.getDeposit());
        // The commented code below is because addDeposit() was removed
        // vm.expectEmit(true, true, false, true);
        // emit Deposited(accountAddress, 1 ether);
        // account.addDeposit{value: 1 ether}();
        // assertEq(1 ether, account.getDeposit());

        // Make the admin of the upgradeable account wallet (deployer) call "depositTo()"
        vm.expectEmit(true, true, false, true);
        emit Deposited(accountAddress, 1 ether); // Notice 2 ether is the current deposit, not the deposited
        vm.prank(accountAdmin);
        account.execute{value: 1 ether}(
            address(entryPoint), 1 ether, abi.encodeWithSignature("depositTo(address)", accountAddress)
        );
        assertEq(1 ether, account.getDeposit());
    }

    function testWithdrawDeposit() public {
        IBaseRecoverableAccount account = IBaseRecoverableAccount(payable(accountAddress));
        assertEq(0, account.getDeposit());
        vm.expectEmit(true, true, false, true);
        emit Deposited(accountAddress, 1 ether);
        // Make the admin of the upgradeable account wallet (deployer) call "depositTo()"
        vm.prank(accountAdmin);
        account.execute{value: 1 ether}(
            address(entryPoint), 1 ether, abi.encodeWithSignature("depositTo(address)", accountAddress)
        );
        assertEq(1 ether, account.getDeposit());

        vm.prank(accountAdmin);
        account.execute{value: 1 ether}(
            address(entryPoint),
            0,
            abi.encodeWithSignature("withdrawTo(address,uint256)", payable(accountAddress), 1 ether)
        );
        assertEq(0 ether, account.getDeposit());
        assertEq(2 ether, accountAddress.balance); // Notice the Ether went to the account, not the EOA
    }

    /**
     * Lock tests *
     */

    /*
     * Test locking the Openfort account using the default guardian.
     */
    function testLockAccount() public {
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

        // Default Openfort guardian starts a recovery process because the owner lost the PK
        vm.prank(OPENFORT_GUARDIAN);
        openfortAccount.startRecovery(address(beneficiary));
        assertEq(openfortAccount.isLocked(), true);

        bytes32 structHash = keccak256(
            abi.encode(RECOVER_TYPEHASH, address(beneficiary), uint64(block.timestamp + RECOVERY_PERIOD), uint32(1))
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = getEIP712SignatureFrom(accountAddress, structHash, OPENFORT_GUARDIAN_PKEY);

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        // Using friendAccount2 first because it has a lower address
        signatures[0] = getEIP712SignatureFrom(accountAddress, structHash, friendAccount2PK);
        signatures[1] = getEIP712SignatureFrom(accountAddress, structHash, friendAccountPK);

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        signatures[0] = getEIP712SignatureFrom(accountAddress, structHash, friendAccountPK); // Unsorted!
        signatures[1] = getEIP712SignatureFrom(accountAddress, structHash, friendAccount2PK);

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        signatures[0] = getEIP712SignatureFrom(accountAddress, structHash, friendAccount2PK); // Using friendAccount2 first because it has a lower address
        signatures[1] = getEIP712SignatureFrom(accountAddress, structHash, friendAccountPK);

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        signatures[0] = getEIP712SignatureFrom(accountAddress, structHash, friendAccount2PK); // Using friendAccount2 first because it has a lower address
        signatures[1] = getEIP712SignatureFrom(accountAddress, structHash, friendAccountPK);

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        signatures[0] = getEIP712SignatureFrom(accountAddress, structHash, OPENFORT_GUARDIAN_PKEY);

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));

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
        IBaseRecoverableAccount openfortAccount = IBaseRecoverableAccount(payable(accountAddress));
        assertEq(openfortAccount.isGuardianOrGuardianSigner(OPENFORT_GUARDIAN), false);
    }
}
