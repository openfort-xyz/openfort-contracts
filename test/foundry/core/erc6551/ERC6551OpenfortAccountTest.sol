// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {console} from "lib/forge-std/src/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ERC6551Registry, IERC6551Registry} from "erc6551/src/ERC6551Registry.sol";
import {EntryPoint, IEntryPoint, UserOperation} from "account-abstraction/core/EntryPoint.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";
import {MockERC721} from "contracts/mock/MockERC721.sol";
import {ERC6551OpenfortAccount} from "contracts/core/erc6551/ERC6551OpenfortAccount.sol";
import {OpenfortErrorsAndEvents} from "contracts/interfaces/OpenfortErrorsAndEvents.sol";
import {OpenfortBaseTest} from "../OpenfortBaseTest.t.sol";

contract ERC6551OpenfortAccountTest is OpenfortBaseTest {
    using ECDSA for bytes32;

    ERC6551Registry public erc6551Registry;
    ERC6551OpenfortAccount public erc6551OpenfortAccountImpl;
    ERC6551OpenfortAccount public erc6551OpenfortAccount;

    /**
     * @notice Initialize the StaticOpenfortAccount testing contract.
     * Scenario:
     * - factoryAdmin is the deployer (and owner) of the mockNFT
     * - accountAdmin is the account used to deploy new static accounts
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

        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        console.log("ChainId:", chainId);

        vm.startPrank(factoryAdmin);

        // If we are in a fork
        if (vm.envAddress("ENTRY_POINT_ADDRESS").code.length > 0) {
            entryPoint = EntryPoint(payable(vm.envAddress("ENTRY_POINT_ADDRESS")));
        }
        // If not a fork, deploy entryPoint (at the correct address)
        else {
            EntryPoint entryPoint_aux = new EntryPoint();
            bytes memory code = address(entryPoint_aux).code;
            address targetAddr = address(vm.envAddress("ENTRY_POINT_ADDRESS"));
            vm.etch(targetAddr, code);
            entryPoint = EntryPoint(payable(targetAddr));
        }

        // If we are in a fork
        if (vm.envAddress("ERC6551_REGISTRY_ADDRESS").code.length > 0) {
            erc6551Registry = ERC6551Registry(payable(vm.envAddress("ERC6551_REGISTRY_ADDRESS")));
            console.log("Using ERC6551 registry from a fork");
        }
        // If not a fork, deploy ERC6551 registry (at the correct address)
        else {
            ERC6551Registry ERC6551Registry_aux = new ERC6551Registry();
            bytes memory code = address(ERC6551Registry_aux).code;
            address targetAddr = address(vm.envAddress("ERC6551_REGISTRY_ADDRESS"));
            vm.etch(targetAddr, code);
            erc6551Registry = ERC6551Registry(payable(targetAddr));
        }

        // deploy a new MockERC721 collection
        mockERC721 = new MockERC721{salt: versionSalt}();

        erc6551OpenfortAccountImpl = new ERC6551OpenfortAccount{salt: versionSalt}();

        accountAddress = erc6551Registry.createAccount(
            address(erc6551OpenfortAccountImpl), versionSalt, chainId, address(mockERC721), 1
        );

        mockERC721.mint(accountAdmin, 1);

        // deploy a new TestCounter
        testCounter = new TestCounter{salt: versionSalt}();

        vm.stopPrank();

        erc6551OpenfortAccount = ERC6551OpenfortAccount(payable(accountAddress));
    }

    /*
     * Test deploy. Regular, no userOps.
     */
    function testERC6551Deploy() public {
        address deployedAccount =
            erc6551Registry.createAccount(address(erc6551OpenfortAccountImpl), 0, block.chainid, address(0), 0);

        assertTrue(deployedAccount != address(0));

        address predictedAccount =
            erc6551Registry.account(address(erc6551OpenfortAccountImpl), 0, block.chainid, address(0), 0);

        assertEq(predictedAccount, deployedAccount);
    }

    /*
     * Check implementation has not been initialized.
     * EntryPoint address should be 0 always in the implementation address. Should pass.
     */
    function testImplementationNoEntryPointAddr() public {
        assertEq(address(erc6551OpenfortAccountImpl.entryPoint()), address(0));
        vm.expectRevert("Initializable: contract is already initialized");
        erc6551OpenfortAccountImpl.initialize();
        assertEq(address(erc6551OpenfortAccountImpl.entryPoint()), address(0));
    }

    /*
     * Create a 2nd account using the same technique than in setup with a new salt (2).
     */
    function testCreate2ndAcc() public {
        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        address accountAddress2 = erc6551Registry.createAccount(
            address(erc6551OpenfortAccountImpl), bytes32(0), chainId, address(mockERC721), 1
        );

        ERC6551OpenfortAccount erc6551OpenfortAccount2 = ERC6551OpenfortAccount(payable(accountAddress2));
        erc6551OpenfortAccount2.initialize();
        IEntryPoint e = erc6551OpenfortAccount2.entryPoint();
        assertEq(address(e), address(entryPoint));
        assertNotEq(address(e), accountAddress2);
    }

    /*
     * Create a new account using createAccount() and the initializer.
     */
    function testCreateAccInitializer() public {
        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        address accountAddress2 = erc6551Registry.createAccount(
            address(erc6551OpenfortAccountImpl), versionSalt, chainId, address(mockERC721), 1
        );
        ERC6551OpenfortAccount erc6551OpenfortAccount2 = ERC6551OpenfortAccount(payable(accountAddress2));
        assertEq(address(erc6551OpenfortAccount2.entryPoint()), address(0));
        erc6551OpenfortAccount2.initialize();
        assertEq(address(erc6551OpenfortAccount2.entryPoint()), address(entryPoint));
    }

    /*
     * Create a new account using createAccount() and the initializer.
     * Test initialize again should fail.
     */
    function testFailCreateAccInitializerNoReinit() public {
        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        address accountAddress2 = erc6551Registry.createAccount(
            address(erc6551OpenfortAccountImpl), versionSalt, chainId, address(mockERC721), 1
        );

        ERC6551OpenfortAccount erc6551OpenfortAccount2 = ERC6551OpenfortAccount(payable(accountAddress2));
        erc6551OpenfortAccount2.initialize();
        erc6551OpenfortAccount2.initialize();
    }

    /*
     * Test getDeposit() function.
     * First ERC4337 function called by this ERC6551-compatible account.
     */
    function testGetDeposit() public {
        erc6551OpenfortAccount.initialize();
        uint256 deposit = erc6551OpenfortAccount.getDeposit();
        assertEq(deposit, 0);

        // We can add deposit by directly calling the EntryPoint
        entryPoint.depositTo{value: 1 ether}(address(erc6551OpenfortAccount));
        deposit = erc6551OpenfortAccount.getDeposit();
        assertEq(deposit, 1 ether);

        // We can ALSO add deposit by calling the EntryPoint depositTo() function
        vm.prank(accountAdmin);
        erc6551OpenfortAccount.execute{value: 1 ether}(
            address(entryPoint), 1 ether, abi.encodeWithSignature("depositTo(address)", accountAddress)
        );
        deposit = erc6551OpenfortAccount.getDeposit();
        assertEq(deposit, 2 ether);
    }

    /*
     * Test owner() function.
     * Check that the owner of the erc6551 account is the owner of the NFT
     * Notice, no need to initialize yet. 
     */
    function testOwner() public {
        assertEq(erc6551OpenfortAccount.owner(), mockERC721.ownerOf(1));
        assertEq(erc6551OpenfortAccount.owner(), accountAdmin);
    }

    /*
     * Test owner() function.
     * Check that the owner of the erc6551 account is the owner of the NFT
     */
    function testNotOwner() public {
        // Burning the NFT
        vm.prank(accountAdmin);
        mockERC721.transferFrom(accountAdmin, address(1), 1);

        assertEq(erc6551OpenfortAccount.owner(), mockERC721.ownerOf(1));
        assertNotEq(erc6551OpenfortAccount.owner(), accountAdmin);
        assertEq(erc6551OpenfortAccount.owner(), address(1));
    }

    function testERC6551ExecuteTransferEth() public {
        erc6551OpenfortAccount.initialize();
        vm.deal(accountAddress, 1 ether);

        vm.prank(accountAdmin);
        erc6551OpenfortAccount.execute(payable(vm.addr(2)), 0.5 ether, "", 0);

        assertEq(accountAddress.balance, 0.5 ether);
        assertEq(vm.addr(2).balance, 0.5 ether);
        assertEq(erc6551OpenfortAccount.state(), 2);

        vm.prank(accountAdmin);
        erc6551OpenfortAccount.execute(payable(vm.addr(2)), 0.5 ether, "");

        assertEq(accountAddress.balance, 0 ether);
        assertEq(vm.addr(2).balance, 1 ether);
        assertEq(erc6551OpenfortAccount.state(), 3);
    }

    /*
     * Create an account using the factory and make it call count() directly.
     */
    function testIncrementCounterDirect() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(accountAddress), 0);

        // Make the admin of the upgradeable account wallet (deployer) call "count"
        vm.prank(accountAdmin);
        erc6551OpenfortAccount.execute(address(testCounter), 0, abi.encodeWithSignature("count()"));

        // Verify that the counter has increased
        assertEq(testCounter.counters(accountAddress), 1);
    }

    /*
     * Create an account by directly calling the factory and make it call count()
     * using the execute() function using the EntryPoint (userOp). Leveraging ERC-4337.
     */
    function testIncrementCounterViaEntrypoint() public {
        // If we want to use userOps, we need to initialize
        erc6551OpenfortAccount.initialize();
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
}
