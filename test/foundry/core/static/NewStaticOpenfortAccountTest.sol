// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import {Test, console} from "lib/forge-std/src/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint, UserOperation, IEntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";
import {TestToken} from "account-abstraction/test/TestToken.sol";
import {NewStaticOpenfortFactory} from "contracts/core/static/NewStaticOpenfortFactory.sol";
import {NewStaticOpenfortAccount} from "contracts/core/static/NewStaticOpenfortAccount.sol";

contract NewStaticOpenfortAccountTest is Test {
    using ECDSA for bytes32;

    uint256 public mumbaiFork;

    EntryPoint public entryPoint;
    NewStaticOpenfortFactory public newStaticOpenfortFactory;
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
     * @notice Initialize the StaticOpenfortAccount testing contract.
     * Scenario:
     * - factoryAdmin is the deployer (and owner) of the StaticOpenfortAccountFactory
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
        newStaticOpenfortFactory = new NewStaticOpenfortFactory(vm.envAddress("ENTRY_POINT_ADDRESS"));
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
        address account = newStaticOpenfortFactory.getAddress(accountAdmin);

        // Expect that we will see an event containing the account and admin
        vm.expectEmit(true, true, false, true);
        emit AccountCreated(account, accountAdmin);

        // Deploy a static account to the counterfactual address
        newStaticOpenfortFactory.createAccount(accountAdmin, bytes(""));

        // Make sure the counterfactual address has not been altered
        assertEq(account, newStaticOpenfortFactory.getAddress(accountAdmin));
    }

    /*
     * Test account creation using nonces using the factory.
     */
    function testCreateAccountViaFactoryWithNonce() public {
        // Create an static account wallet and get its address
        address account = newStaticOpenfortFactory.createAccount(accountAdmin, "");
        address account2 = newStaticOpenfortFactory.createAccount(accountAdmin, "");

        // Verifiy that createAccount() always generate the same address when used with the same admin
        assertEq(account, account2);

        // Create a new account with accountAdmin using a nonce
        account2 = newStaticOpenfortFactory.createAccountWithNonce(accountAdmin, "", 0);

        // Verifiy that the new account is indeed different now
        assertNotEq(account, account2);
    }

}
