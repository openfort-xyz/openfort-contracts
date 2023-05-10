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

    address payable public bundler;
    address public user1;
    uint256 public user1PrivKey;

    event AccountCreated(address indexed account, address indexed accountAdmin);

    /**
     * @notice Initialize the StaticAccount testing contract.
     * Scenario:
     * - user1 is the deployer (and owner) of the OpenfortSimpleAccount
     * 
     * - testCounter is the counter used to test userOps
     */
    function setUp() public {
        entryPoint = new EntryPoint();
        // deploy account factory
        staticAccountFactory = new StaticAccountFactory(IEntryPoint(payable(address(entryPoint))));
        
        (user1, user1PrivKey) = makeAddrAndKey("user1");
        bundler = payable(makeAddr("bundler"));
        testCounter = new TestCounter();
    }

    /// @dev Create an account by directly calling the factory.
    function testStateCreateAccountViaFactory() public {
        staticAccountFactory.createAccount(user1, bytes(""));
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