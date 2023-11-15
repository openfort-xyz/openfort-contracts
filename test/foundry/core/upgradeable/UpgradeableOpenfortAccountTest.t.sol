// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Test, console} from "lib/forge-std/src/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {EntryPoint, UserOperation} from "account-abstraction/core/EntryPoint.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";
import {TestToken} from "account-abstraction/test/TestToken.sol";
import {UpgradeableOpenfortAccount} from "contracts/core/upgradeable/UpgradeableOpenfortAccount.sol";
import {UpgradeableOpenfortFactory} from "contracts/core/upgradeable/UpgradeableOpenfortFactory.sol";
import {OpenfortUpgradeableProxy} from "contracts/core/upgradeable/OpenfortUpgradeableProxy.sol";
import {MockedV2UpgradeableOpenfortAccount} from "contracts/mock/MockedV2UpgradeableOpenfortAccount.sol";

contract UpgradeableOpenfortAccountTest is Test {
    using ECDSA for bytes32;

    EntryPoint public entryPoint;
    UpgradeableOpenfortAccount public upgradeableOpenfortAccount;
    UpgradeableOpenfortFactory public upgradeableOpenfortFactory;
    address public account;
    TestCounter public testCounter;
    TestToken public testToken;

    // Testing addresses
    address private factoryAdmin;
    uint256 private factoryAdminPKey;

    address private accountAdmin;
    uint256 private accountAdminPKey;

    address payable private beneficiary = payable(makeAddr("beneficiary"));

    // bytes4(keccak256("isValidSignature(bytes32,bytes)")
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;
    // keccak256("OpenfortMessage(bytes32 hashedMessage)");
    bytes32 private constant OF_MSG_TYPEHASH = 0x57159f03b9efda178eab2037b2ec0b51ce11be0051b8a2a9992c29dc260e4a30;
    bytes32 private constant _TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

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
        // deploy upgradeable account implementation
        upgradeableOpenfortAccount = new UpgradeableOpenfortAccount();
        // deploy upgradeable account factory
        upgradeableOpenfortFactory =
            new UpgradeableOpenfortFactory(payable(address(entryPoint)), address(upgradeableOpenfortAccount));

        // Create an upgradeable account wallet and get its address
        account = upgradeableOpenfortFactory.createAccountWithNonce(accountAdmin, "1");

        // deploy a new TestCounter
        testCounter = new TestCounter();
        // deploy a new TestToken (ERC20)
        testToken = new TestToken();
        vm.stopPrank();
    }

    /*
     * Create an account by directly calling the factory.
     */
    function testCreateAccountWithNonceViaFactory() public {
        // Get the counterfactual address
        vm.prank(factoryAdmin);
        address accountAddress2 = upgradeableOpenfortFactory.getAddressWithNonce(accountAdmin, "2");

        // Expect that we will see an event containing the account and admin
        vm.expectEmit(true, true, false, true);
        emit AccountCreated(accountAddress2, accountAdmin);

        // Deploy a upgradeable account to the counterfactual address
        vm.prank(factoryAdmin);
        upgradeableOpenfortFactory.createAccountWithNonce(accountAdmin, "2");

        // Calling it again should just return the address and not create another account
        vm.prank(factoryAdmin);
        upgradeableOpenfortFactory.createAccountWithNonce(accountAdmin, "2");

        // Make sure the counterfactual address has not been altered
        vm.prank(factoryAdmin);
        assertEq(accountAddress2, upgradeableOpenfortFactory.getAddressWithNonce(accountAdmin, "2"));
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
        address account2 = upgradeableOpenfortFactory.getAddressWithNonce(accountAdmin, bytes32("2"));
        assertEq(account2.code.length, 0);

        bytes memory initCallData =
            abi.encodeWithSignature("createAccountWithNonce(address,bytes32)", accountAdmin, bytes32("2"));
        bytes memory initCode = abi.encodePacked(abi.encodePacked(address(upgradeableOpenfortFactory)), initCallData);

        UserOperation[] memory userOpCreateAccount =
            _setupUserOpExecute(account2, accountAdminPKey, initCode, address(0), 0, bytes(""));

        // Expect that we will see an event containing the account and admin
        vm.expectEmit(true, true, false, true);
        emit AccountCreated(account2, accountAdmin);

        entryPoint.handleOps(userOpCreateAccount, beneficiary);

        // Make sure the smart account does have some code now
        assert(account2.code.length > 0);

        // Make sure the counterfactual address has not been altered
        assertEq(account2, upgradeableOpenfortFactory.getAddressWithNonce(accountAdmin, bytes32("2")));
    }

    /*
     * Create an account using the factory and make it call count() directly.
     */
    function testIncrementCounterDirect() public {
        // Verify that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        // Make the admin of the upgradeable account wallet (deployer) call "count"
        vm.prank(accountAdmin);
        UpgradeableOpenfortAccount(payable(account)).execute(
            address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        // Verify that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Create an account by directly calling the factory and make it call count()
     * using the execute() function using the EntryPoint (userOp). Leaveraging ERC-4337.
     */
    function testIncrementCounterViaEntrypoint() public {
        // Verify that the counter is stil set to 0
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
     * using the executeBatching() function using the EntryPoint (userOp). Leaveraging ERC-4337.
     */
    function testIncrementCounterViaEntrypointBatching() public {
        // Verify that the counter is stil set to 0
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
        // Verify that the counter is stil set to 0
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
        // Verify that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");
        address[] memory emptyWhitelist;

        vm.prank(accountAdmin);
        UpgradeableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 2 ** 48 - 1, 100, emptyWhitelist);

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
        // Verify that the counter is stil set to 0
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
        // Verify that the counter is stil set to 0
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
     * Register a limited sessionKey via userOp calling the execute() function
     * using the EntryPoint (userOp). Then use that sessionKey to register a second one
     */
    function testFailAttackRegisterSessionKeyViaEntrypoint2ndKey() public {
        // Verify that the counter is stil set to 0
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
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);
    }

    /*
     *  Should fail, try to use a sessionKey that is expired.
     */
    function testIncrementCounterViaSessionKeyExpired() public {
        // Verify that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");
        address[] memory emptyWhitelist;

        vm.warp(100);
        vm.prank(accountAdmin);
        UpgradeableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 99, 100, emptyWhitelist);

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
        // Verify that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");
        address[] memory emptyWhitelist;

        vm.prank(accountAdmin);
        UpgradeableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 0, 100, emptyWhitelist);
        UpgradeableOpenfortAccount(payable(account)).revokeSessionKey(sessionKey);

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
        // Verify that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");
        address[] memory emptyWhitelist;

        // We are now in block 100, but our session key is valid until block 150
        vm.warp(100);
        vm.prank(accountAdmin);
        UpgradeableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 150, 1, emptyWhitelist);

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
        // Verify that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");
        address[] memory emptyWhitelist;

        // We are now in block 100, but our session key is valid until block 150
        vm.warp(100);
        vm.prank(accountAdmin);
        UpgradeableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 150, 2, emptyWhitelist);

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
        // Verify that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        address sessionKey;
        uint256 sessionKeyPrivKey;
        (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");
        address[] memory emptyWhitelist;

        vm.prank(accountAdmin);
        UpgradeableOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, 0, 100, emptyWhitelist);
        vm.prank(beneficiary);
        UpgradeableOpenfortAccount(payable(account)).revokeSessionKey(sessionKey);

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
        // Verify that the counter is stil set to 0
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
        // Verify that the counter is stil set to 0
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
        // Verify that the counter is stil set to 0
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
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has increased
        assertEq(testCounter.counters(account), 3);
    }

    /*
     * Should fail, try to use a sessionKey with invalid whitelisting to call Execute().
     */
    function testFailIncrementCounterViaSessionKeyWhitelistingWrongAddress() public {
        // Verify that the counter is stil set to 0
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
        // Verify that the counter is stil set to 0
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

        vm.expectRevert("Ownable: caller is not the owner");
        UpgradeableOpenfortAccount(payable(account)).transferOwnership(accountAdmin2);

        vm.prank(accountAdmin);
        UpgradeableOpenfortAccount(payable(account)).transferOwnership(accountAdmin2);
        vm.prank(accountAdmin2);
        UpgradeableOpenfortAccount(payable(account)).acceptOwnership();

        // Verify that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        // Make the admin of the upgradeable account wallet (deployer) call "count"
        vm.prank(accountAdmin2);
        UpgradeableOpenfortAccount(payable(account)).execute(
            address(testCounter), 0, abi.encodeWithSignature("count()")
        );

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
        UpgradeableOpenfortAccount(payable(account)).transferOwnership(accountAdmin2);
        vm.prank(accountAdmin2);
        UpgradeableOpenfortAccount(payable(account)).acceptOwnership();

        // Verify that the counter is stil set to 0
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
     * Test an account with testToken instead of TestCount.
     */
    function testMintTokenAccount() public {
        // Verify that the totalSupply is stil 0
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

        // Verify that the totalSupply has increased
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
        // Verify that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        UserOperation[] memory userOp = _setupUserOpExecute(
            account, accountAdminPKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1000000000000000000}(account);
        // Expect the simulateValidation() to always revert
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);

        // Verify that the counter has not increased
        assertEq(testCounter.counters(account), 0);
    }

    /*
     * Create an account and upgrade its implementation
     */
    function testUpgradeAccount() public {
        assertEq(UpgradeableOpenfortAccount(payable(account)).version(), 1);
        MockedV2UpgradeableOpenfortAccount newAccountImplementation = new MockedV2UpgradeableOpenfortAccount();
        OpenfortUpgradeableProxy p = OpenfortUpgradeableProxy(payable(account));
        // Printing account address and the implementation address
        console.log(account);
        console.log(p.implementation());

        vm.expectRevert("Ownable: caller is not the owner");
        UpgradeableOpenfortAccount(payable(account)).upgradeTo(address(newAccountImplementation));

        vm.prank(accountAdmin);
        UpgradeableOpenfortAccount(payable(account)).upgradeTo(address(newAccountImplementation));

        // Notice that, even though we bind the address to the old implementation, version() now returns 2
        assertEq(UpgradeableOpenfortAccount(payable(account)).version(), 2);

        // Printing account address and the implementation address. Impl address should have changed
        console.log(account);
        console.log(p.implementation());
    }

    /*
     * 1- Deploy a factory using the old EntryPoint to create an account.
     * 2- Inform the account of the new EntryPoint by calling updateEntryPoint()
     */
    function testUpdateEntryPoint() public {
        address oldEntryPoint = address(0x0576a174D229E3cFA37253523E645A78A0C91B57);
        address newEntryPoint = vm.envAddress("ENTRY_POINT_ADDRESS");
        UpgradeableOpenfortFactory upgradeableOpenfortFactoryOld =
            new UpgradeableOpenfortFactory(payable(oldEntryPoint), address(upgradeableOpenfortAccount));

        // Create an upgradeable account wallet using the old EntryPoint and get its address
        address payable accountOld = payable(upgradeableOpenfortFactoryOld.createAccountWithNonce(accountAdmin, "999"));
        UpgradeableOpenfortAccount upgradeableAccount = UpgradeableOpenfortAccount(accountOld);
        assertEq(address(upgradeableAccount.entryPoint()), oldEntryPoint);

        vm.expectRevert("Ownable: caller is not the owner");
        upgradeableAccount.updateEntryPoint(newEntryPoint);

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

        bytes4 valid = UpgradeableOpenfortAccount(payable(account)).isValidSignature(hash, signature);
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

        bytes4 valid = UpgradeableOpenfortAccount(payable(account)).isValidSignature(hash, signature);
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

        bytes4 valid = UpgradeableOpenfortAccount(payable(account)).isValidSignature(hash, signature);
        assertEq(valid, MAGICVALUE); // SHOULD PASS
    }
}
