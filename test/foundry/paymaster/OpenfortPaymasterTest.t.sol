// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import {Test, console} from "lib/forge-std/src/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint, UserOperation, IEntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";
import {TestToken} from "account-abstraction/test/TestToken.sol";
import {StaticOpenfortAccountFactory} from "contracts/core/static/StaticOpenfortAccountFactory.sol";
import {StaticOpenfortAccount} from "contracts/core/static/StaticOpenfortAccount.sol";
import {OpenfortPaymaster} from "contracts/paymaster/OpenfortPaymaster.sol";

contract OpenfortPaymasterTest is Test {
    using ECDSA for bytes32;

    uint256 public mumbaiFork;

    EntryPoint public entryPoint;
    StaticOpenfortAccountFactory public staticOpenfortAccountFactory;
    OpenfortPaymaster public openfortPaymaster;
    TestCounter public testCounter;
    TestToken public testToken;
    
    // Testing addresses
    address private factoryAdmin;
    uint256 private factoryAdminPKey;

    address private accountAdmin;
    uint256 private accountAdminPKey;
    
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
        openfortPaymaster = new OpenfortPaymaster(IEntryPoint(payable(address(entryPoint))), factoryAdmin);
        // deploy account factory
        vm.prank(factoryAdmin);
        staticOpenfortAccountFactory = new StaticOpenfortAccountFactory(IEntryPoint(payable(address(entryPoint))));
        // deploy a new TestCounter
        testCounter = new TestCounter();
        // deploy a new TestToken (ERC20)
        testToken = new TestToken();
    }
}
