// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import {Test, console} from "lib/forge-std/src/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint, UserOperation, IEntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";
import {StaticAccountFactory} from "contracts/core/StaticAccountFactory.sol";
import {StaticAccount} from "contracts/core/StaticAccount.sol";

contract StaticAccountTest is Test {
    using ECDSA for bytes32;

    EntryPoint public entryPoint;
    StaticAccountFactory public staticAccountFactory;
    TestCounter public testCounter;
    
    // Test params
    uint256 private accountAdminPKey = 100;
    address private accountAdmin;

    uint256 private accountSignerPKey = 200;
    address private accountSigner;

    uint256 private nonSignerPKey = 300;
    address private nonSigner;

    event AccountCreated(address indexed account, address indexed accountAdmin);
/*
    function _setupUserOp(
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
        bytes32 opHash = EntryPoint(entrypoint).getUserOpHash(op);
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
*/
    /**
     * @notice Initialize the StaticAccount testing contract.
     * Scenario:
     * - user1 is the deployer (and owner) of the OpenfortSimpleAccount
     * 
     * - testCounter is the counter used to test userOps
     */
    function setUp() public {
        // Setup signers.
        accountAdmin = vm.addr(accountAdminPKey); // Generate addr from priv key
        vm.deal(accountAdmin, 100 ether);

        accountSigner = vm.addr(accountSignerPKey);
        nonSigner = vm.addr(nonSignerPKey);

        // deploy entryPoint
        entryPoint = new EntryPoint();
        // deploy account factory
        staticAccountFactory = new StaticAccountFactory(IEntryPoint(payable(address(entryPoint))));

        testCounter = new TestCounter();
    }

    /// Create an account by directly calling the factory.
    function testCreateAccountViaFactory() public {
        // Get the counterfactual address
        address account = staticAccountFactory.getAddress(accountAdmin);
        console.log(account);

        // Deploy a static account to the counterfactual address
        staticAccountFactory.createAccount(accountAdmin, bytes(""));

        // Make sure the counterfactual address has not been altered
        account = staticAccountFactory.getAddress(accountAdmin);
        console.log(account);
    }

    /// Create an account by directly calling the factory and make it call count()
    function testCreateAccountTestCounter() public {
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

    /**
     * Auxiliary function to sign user ops
     */
    function signUserOp(UserOperation memory op, address addr, uint256 key)
        public
        view
        returns (bytes memory signature)
    {
        bytes32 hash = entryPoint.getUserOpHash(op);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, hash.toEthSignedMessageHash());
        // Check that the address can be retrieved from the signature values (v,r,s)
        require(addr == ECDSA.recover(hash.toEthSignedMessageHash(), v, r, s), "Invalid signature");
        signature = abi.encodePacked(r, s, v);
        // Check that the address can be retrieved from the signature as it will be received by the user (one string value)
        require(addr == ECDSA.recover(hash.toEthSignedMessageHash(), signature), "Invalid signature");
    }

    /**
     * Send a userOp to the deployed 
     * deployer/owner, user1.
     */
    function testStaticAccountCounter() public {

    }
}