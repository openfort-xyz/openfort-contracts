// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import {Test, console} from "lib/forge-std/src/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint, UserOperation} from "account-abstraction/core/EntryPoint.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";
import {TestToken} from "account-abstraction/test/TestToken.sol";
import {UpgradeableOpenfortFactory} from "contracts/core/upgradeable/UpgradeableOpenfortFactory.sol";
import {UpgradeableOpenfortAccount} from "contracts/core/upgradeable/UpgradeableOpenfortAccount.sol";

contract UpgradeableOpenfortAccountTest is Test {
    using ECDSA for bytes32;

    uint256 public mumbaiFork;

    EntryPoint public entryPoint;
    UpgradeableOpenfortFactory public upgradeableOpenfortFactory;
    TestCounter public testCounter;
    TestToken public testToken;

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
     * @notice Initialize the UpgradeableOpenfortAccount testing contract.
     * Scenario:
     * - factoryAdmin is the deployer (and owner) of the UpgradeableOpenfortFactory
     * - accountAdmin is the account used to deploy new static accounts
     * - entryPoint is the singleton EntryPoint
     * - testCounter is the counter used to test userOps
     */
    function setUp() public {
        mumbaiFork = vm.createFork(vm.envString("POLYGON_MUMBAI_RPC"));
        vm.selectFork(mumbaiFork);
        // Setup and fund signers
        (factoryAdmin, factoryAdminPKey) = makeAddrAndKey("factoryAdmin");
        vm.deal(factoryAdmin, 100 ether);
        (accountAdmin, accountAdminPKey) = makeAddrAndKey("accountAdmin");
        vm.deal(accountAdmin, 100 ether);

        // deploy entryPoint
        entryPoint = EntryPoint(payable(vm.envAddress("ENTRY_POINT_ADDRESS")));
        // deploy account factory
        vm.prank(factoryAdmin);
        upgradeableOpenfortFactory = new UpgradeableOpenfortFactory((payable(vm.envAddress("ENTRY_POINT_ADDRESS"))));
        // deploy a new TestCounter
        testCounter = new TestCounter();
        // deploy a new TestToken (ERC20)
        testToken = new TestToken();
    }

    /*
     * Create an account by directly calling the factory.
     */
    function testCreateAccountViaFactory() public {
        // Get the counterfactual address
        address account = upgradeableOpenfortFactory.getAddress(accountAdmin);

        // Expect that we will see an event containing the account and admin
        vm.expectEmit(true, true, false, true);
        emit AccountCreated(account, accountAdmin);

        // Deploy a static account to the counterfactual address
        upgradeableOpenfortFactory.createAccount(accountAdmin, bytes(""));

        // Make sure the counterfactual address has not been altered
        assertEq(account, upgradeableOpenfortFactory.getAddress(accountAdmin));
    }

    /*
     * Test account creation using nonces using the factory.
     */
    function testCreateAccountViaFactoryWithNonce() public {
        // Create an static account wallet and get its address
        address account = upgradeableOpenfortFactory.createAccount(accountAdmin, "");
        address account2 = upgradeableOpenfortFactory.createAccount(accountAdmin, "");

        // Verifiy that createAccount() always generate the same address when used with the same admin
        assertEq(account, account2);

        // Create a new account with accountAdmin using a nonce
        account2 = upgradeableOpenfortFactory.createAccountWithNonce(accountAdmin, "", 0);

        // Verifiy that the new account is indeed different now
        assertNotEq(account, account2);
    }

    /*
     * Create an account calling the factory via EntryPoint.
     * Use initCode
     */
    function testCreateAccountViaEntryPoint() public {
        // Get the counterfactual address
        address account = upgradeableOpenfortFactory.getAddress(accountAdmin);

        // Make sure the smart account does not have any code yet
        assertEq(account.code.length, 0);

        bytes memory initCallData = abi.encodeWithSignature("createAccount(address,bytes)", accountAdmin, bytes(""));
        bytes memory initCode = abi.encodePacked(abi.encodePacked(address(upgradeableOpenfortFactory)), initCallData);

        UserOperation[] memory userOpCreateAccount =
            _setupUserOpExecute(account, accountAdminPKey, initCode, address(0), 0, bytes(""));

        // Expect that we will see an event containing the account and admin
        vm.expectEmit(true, true, false, true);
        emit AccountCreated(account, accountAdmin);

        entryPoint.handleOps(userOpCreateAccount, beneficiary);

        // Make sure the smart account does have some code now
        assert(account.code.length > 0);

        // Make sure the counterfactual address has not been altered
        assertEq(account, upgradeableOpenfortFactory.getAddress(accountAdmin));
    }

    /*
     * Create an account using the factory and make it call count() directly.
     */
    function testTestCounterDirect() public {
        // Create an static account wallet and get its address
        address account = upgradeableOpenfortFactory.createAccount(accountAdmin, "");

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        // Make the admin of the static account wallet (deployer) call "count"
        vm.prank(accountAdmin);
        UpgradeableOpenfortAccount(payable(account)).execute(
            address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Create an account by directly calling the factory and make it call count()
     * using the execute() function using the EntryPoint (userOp). Leaveraging ERC-4337.
     */
    function testTestCounterViaEntrypoint() public {
        // Create an static account wallet and get its address
        address account = upgradeableOpenfortFactory.createAccount(accountAdmin, "");

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, accountAdminPKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
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
    function testTestCounterViaEntrypointBatching() public {
        // Create an static account wallet and get its address
        address account = upgradeableOpenfortFactory.createAccount(accountAdmin, "");

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
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 3);
    }

    /*
     *  Should fail, try to use a sessionKey that is not registered.
     */
    function testFailTestCounterViaSessionKeyNotregistered() public {
        // Create an static account wallet and get its address
        address account = upgradeableOpenfortFactory.createAccount(accountAdmin, "");

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has not increased
        assertEq(testCounter.counters(account), 0);
    }

    /*
     * Use a sessionKey that is registered.
     */
    function testTestCounterViaSessionKey() public {
        // Create an static account wallet and get its address
        address account = upgradeableOpenfortFactory.createAccount(accountAdmin, "");

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        vm.prank(accountAdmin);
        UpgradeableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Register a sessionKey via userOp calling the execute() function
     * using the EntryPoint (userOp). Then use the sessionKey to count
     */
    function testRegisterSessionKeyViaEntrypoint() public {
        // Create an static account wallet and get its address
        address account = upgradeableOpenfortFactory.createAccount(accountAdmin, "");

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
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has not increased
        assertEq(testCounter.counters(account), 0);

        userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Register a master sessionKey via userOp calling the execute() function
     * using the EntryPoint (userOp). Then use that sessionKey to register a second one
     */
    function testRegisterSessionKeyViaEntrypoint2ndKey() public {
        // Create an static account wallet and get its address
        address account = upgradeableOpenfortFactory.createAccount(accountAdmin, "");

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
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has not increased
        assertEq(testCounter.counters(account), 0);

        userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
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
        entryPoint.handleOps(userOp, beneficiary);
    }

    /*
     * Register a limited sessionKey via userOp calling the execute() function
     * using the EntryPoint (userOp). Then use that sessionKey to register a second one
     */
    function testFailAttackRegisterSessionKeyViaEntrypoint2ndKey() public {
        // Create an static account wallet and get its address
        address account = upgradeableOpenfortFactory.createAccount(accountAdmin, "");

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
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has not increased
        assertEq(testCounter.counters(account), 0);

        userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);

        // Verify that the registered key is not a MasterKey nor has whitelisting
        bool isMasterKey;
        bool isWhitelisted;
        (,,, isMasterKey, isWhitelisted) = UpgradeableOpenfortAccount(payable(account)).sessionKeys(sessionKey);
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
        entryPoint.handleOps(userOp, beneficiary);
    }

    /*
     *  Should fail, try to use a sessionKey that is expired.
     */
    function testFailTestCounterViaSessionKeyExpired() public {
        // Create an static account wallet and get its address
        address account = upgradeableOpenfortFactory.createAccount(accountAdmin, "");

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        vm.warp(100);
        vm.prank(accountAdmin);
        UpgradeableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 99);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has not increased
        assertEq(testCounter.counters(account), 0);
    }

    /*
     *  Should fail, try to use a sessionKey that is revoked.
     */
    function testFailTestCounterViaSessionKeyRevoked() public {
        // Create an static account wallet and get its address
        address account = upgradeableOpenfortFactory.createAccount(accountAdmin, "");

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        vm.prank(accountAdmin);
        UpgradeableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 0);
        UpgradeableOpenfortAccount(payable(account)).revokeSessionKey(sessionKey);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     *  Should fail, try to use a sessionKey that reached its limit.
     */
    function testFailTestCounterViaSessionKeyReachLimit() public {
        // Create an static account wallet and get its address
        address account = upgradeableOpenfortFactory.createAccount(accountAdmin, "");

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        // We are now in block 100, but our session key is valid until block 150
        vm.warp(100);
        vm.prank(accountAdmin);
        UpgradeableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 150, 1);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        entryPoint.handleOps(userOp, beneficiary);

        userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has only increased by one
        assertEq(testCounter.counters(account), 1);
    }

    /*
     *  Should fail, try to use a sessionKey that reached its limit.
     */
    function testFailTestCounterViaSessionKeyReachLimitBatching() public {
        // Create an static account wallet and get its address
        address account = upgradeableOpenfortFactory.createAccount(accountAdmin, "");

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        // We are now in block 100, but our session key is valid until block 150
        vm.warp(100);
        vm.prank(accountAdmin);
        UpgradeableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 150, 2);

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
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has not increased
        assertEq(testCounter.counters(account), 0);
    }

    /*
     *  Should fail, try to revoke a sessionKey using a non-privileged user
     */
    function testFailRevokeSessionKeyInvalidUser() public {
        // Create an static account wallet and get its address
        address account = upgradeableOpenfortFactory.createAccount(accountAdmin, "");

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        vm.prank(accountAdmin);
        UpgradeableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 0);
        vm.prank(beneficiary);
        UpgradeableOpenfortAccount(payable(account)).revokeSessionKey(sessionKey);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Use a sessionKey with whitelisting to call Execute().
     */
    function testTestCounterViaSessionKeyWhitelisting() public {
        // Create an static account wallet and get its address
        address account = upgradeableOpenfortFactory.createAccount(accountAdmin, "");

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        address[] memory whitelist = new address[](1);
        whitelist[0] = address(testCounter);
        vm.prank(accountAdmin);
        UpgradeableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1, 1, whitelist);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Should fail, try to register a sessionKey with a large whitelist.
     */
    function testFailTestCounterViaSessionKeyWhitelistingTooBig() public {
        // Create an static account wallet and get its address
        address account = upgradeableOpenfortFactory.createAccount(accountAdmin, "");

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        address[] memory whitelist = new address[](11);
        vm.prank(accountAdmin);
        UpgradeableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1, 1, whitelist);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has not increased
        assertEq(testCounter.counters(account), 0);
    }

    /*
     * Use a sessionKey with whitelisting to call ExecuteBatch().
     */
    function testTestCounterViaSessionKeyWhitelistingBatch() public {
        // Create an static account wallet and get its address
        address account = upgradeableOpenfortFactory.createAccount(accountAdmin, "");

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        address[] memory whitelist = new address[](1);
        whitelist[0] = address(testCounter);
        vm.prank(accountAdmin);
        UpgradeableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1, 3, whitelist);

        // Verify that the registered key is not a MasterKey but has whitelisting
        bool isMasterKey;
        bool isWhitelisted;
        (,,, isMasterKey, isWhitelisted) = UpgradeableOpenfortAccount(payable(account)).sessionKeys(sessionKey);
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
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 3);
    }

    /*
     * Should fail, try to use a sessionKey with invalid whitelisting to call Execute().
     */
    function testFailTestCounterViaSessionKeyWhitelistingWrongAddress() public {
        // Create an static account wallet and get its address
        address account = upgradeableOpenfortFactory.createAccount(accountAdmin, "");

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        address[] memory whitelist = new address[](1);
        whitelist[0] = address(account);
        vm.prank(accountAdmin);
        UpgradeableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1, 1, whitelist);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Should fail, try to use a sessionKey with invalid whitelisting to call ExecuteBatch().
     */
    function testFailTestCounterViaSessionKeyWhitelistingBatchWrongAddress() public {
        // Create an static account wallet and get its address
        address account = upgradeableOpenfortFactory.createAccount(accountAdmin, "");

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

        address[] memory whitelist = new address[](1);
        whitelist[0] = address(account);
        vm.prank(accountAdmin);
        UpgradeableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1, 1, whitelist);

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
        // Create an static account wallet and get its address
        address account = upgradeableOpenfortFactory.createAccount(accountAdmin, "");

        address accountAdmin2;
        uint256 accountAdmin2PKey;
        (accountAdmin2, accountAdmin2PKey) = makeAddrAndKey("accountAdmin2");

        vm.prank(accountAdmin);
        UpgradeableOpenfortAccount(payable(account)).transferOwnership(accountAdmin2);
        vm.prank(accountAdmin2);
        UpgradeableOpenfortAccount(payable(account)).acceptOwnership();

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        // Make the admin of the static account wallet (deployer) call "count"
        vm.prank(accountAdmin2);
        UpgradeableOpenfortAccount(payable(account)).execute(
            address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Change the owner of an account and call TestCounter though the Entrypoint
     */
    function testChangeOwnershipAndCountEntryPoint() public {
        // Create an static account wallet and get its address
        address account = upgradeableOpenfortFactory.createAccount(accountAdmin, "");

        address accountAdmin2;
        uint256 accountAdmin2PKey;
        (accountAdmin2, accountAdmin2PKey) = makeAddrAndKey("accountAdmin2");

        vm.prank(accountAdmin);
        UpgradeableOpenfortAccount(payable(account)).transferOwnership(accountAdmin2);
        vm.prank(accountAdmin2);
        UpgradeableOpenfortAccount(payable(account)).acceptOwnership();

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, accountAdmin2PKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Test an account with testToken instead of TestCount.
     */
    function testTokenAccount() public {
        // Create an static account wallet and get its address
        address account = upgradeableOpenfortFactory.createAccount(accountAdmin, "");

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
        entryPoint.handleOps(userOp, beneficiary);

        // Verifiy that the totalSupply has increased
        assertEq(testToken.totalSupply(), 2);
    }

    /*
     * Test receive native tokens.
     */
    function testReceiveNativeToken() public {
        // Create an static account wallet and get its address
        address account = upgradeableOpenfortFactory.createAccount(accountAdmin, "");

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
        // Create an static account wallet and get its address
        address account = upgradeableOpenfortFactory.createAccount(accountAdmin, "");

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
        // Create an static account wallet and get its address
        address account = upgradeableOpenfortFactory.createAccount(accountAdmin, "");

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
}