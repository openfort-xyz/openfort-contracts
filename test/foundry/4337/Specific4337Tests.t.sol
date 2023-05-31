// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import {Test, console} from "lib/forge-std/src/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint, UserOperation} from "account-abstraction/core/EntryPoint.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";
import {TestToken} from "account-abstraction/test/TestToken.sol";
import {StaticOpenfortFactory} from "contracts/core/static/StaticOpenfortFactory.sol";
import {StaticOpenfortAccount} from "contracts/core/static/StaticOpenfortAccount.sol";
import "account-abstraction/core/Helpers.sol" as Helpers;

contract Specific4337Tests is Test {
    using ECDSA for bytes32;

    uint48 constant MAX_TIME = 2 ** 48 - 1;

    uint256 public mumbaiFork;

    EntryPoint public entryPoint;
    StaticOpenfortFactory public staticOpenfortFactory;
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

    function _getValidationData(
        address sender,
        uint256 _signerPKey,
        bytes memory _initCode,
        address _target,
        uint256 _value,
        bytes memory _callData
    ) internal returns (uint256 validationData) {
        UserOperation[] memory userOp = _setupUserOpExecute(sender, _signerPKey, _initCode, _target, _value, _callData);

        bytes32 opHash = EntryPoint(entryPoint).getUserOpHash(userOp[0]);

        vm.prank(address(entryPoint));
        return StaticOpenfortAccount(payable(sender)).validateUserOp(userOp[0], opHash, 0);
    }

    /**
     * @notice Initialize the StaticOpenfortAccount testing contract.
     * Scenario:
     * - factoryAdmin is the deployer (and owner) of the StaticOpenfortFactory
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

        // deploy a new TestCounter
        testCounter = new TestCounter();
        // deploy a new TestToken (ERC20)
        testToken = new TestToken();
    }

    // /*
    //  * Should succeed. Return 0 as it is the owner calling
    //  * 
    //  */
    // function testValidateUserOp() public {
    //     // Create an static account wallet and get its address
    //     address account = staticOpenfortFactory.createAccount(accountAdmin, "");

    //     uint256 validationData = _getValidationData(
    //         account, accountAdminPKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
    //     );
    //     assertEq(validationData, 0);
    // }

    // /*
    //  * Should return 1, therefore fail
    //  * Use an incorrect private key
    //  */
    // function testWrongValidateUserOp() public {
    //     // Create an static account wallet and get its address
    //     address account = staticOpenfortFactory.createAccount(accountAdmin, "");

    //     // Using an invalid private key
    //     uint256 validationData = _getValidationData(
    //         account, factoryAdminPKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
    //     );

    //     assertEq(validationData, 1);
    // }

    // /*
    //  * Should succeed. Return (false, ValidAfter, ValidUntil) // false, MAX, 0
    //  * Use a sessionKey that is registered.
    //  */
    // function testValidateUserOpSessionKey() public {
    //     // Create an static account wallet and get its address
    //     address account = staticOpenfortFactory.createAccount(accountAdmin, "");

    //     address sessionKey;
    //     uint256 sessionKeyPrivKey;
    //     (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

    //     vm.prank(accountAdmin);
    //     StaticOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, MAX_TIME);

    //     uint256 validationData = _getValidationData(
    //         account, sessionKeyPrivKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
    //     );

    //     uint256 expectedValidationData = Helpers._packValidationData(false, MAX_TIME, 0);
    //     assertEq(validationData, expectedValidationData);
    // }

    // /*
    //  * Use a sessionKey that is NOT registered.
    //  * Should return 1; wrong!
    //  */
    // function testWrongValidateUserOpSessionKey() public {
    //     // Create an static account wallet and get its address
    //     address account = staticOpenfortFactory.createAccount(accountAdmin, "");

    //     address sessionKey;
    //     uint256 sessionKeyPrivKey;
    //     (sessionKey, sessionKeyPrivKey) = makeAddrAndKey("sessionKey");

    //     address sessionKey2;
    //     uint256 sessionKeyPrivKey2;
    //     (sessionKey2, sessionKeyPrivKey2) = makeAddrAndKey("sessionKey2");

    //     vm.prank(accountAdmin);
    //     StaticOpenfortAccount(payable(account)).registerSessionKey(sessionKey, 0, MAX_TIME);

    //     uint256 validationData = _getValidationData(
    //         account, sessionKeyPrivKey2, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
    //     );
    //     assertEq(validationData, 1);
    // }
}
