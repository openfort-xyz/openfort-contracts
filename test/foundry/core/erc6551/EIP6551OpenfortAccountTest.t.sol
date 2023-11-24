// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {console} from "lib/forge-std/src/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ERC6551Registry, IERC6551Registry} from "erc6551/src/ERC6551Registry.sol";
import {EntryPoint, IEntryPoint, UserOperation} from "account-abstraction/core/EntryPoint.sol";
import {MockERC721} from "contracts/mock/MockERC721.sol";
import {ERC6551OpenfortAccount} from "contracts/core/erc6551/ERC6551OpenfortAccount.sol";
import {ERC6551OpenfortProxy} from "contracts/core/erc6551/ERC6551OpenfortProxy.sol";
import {OpenfortErrorsAndEvents} from "contracts/interfaces/OpenfortErrorsAndEvents.sol";
import {OpenfortBaseTest} from "../OpenfortBaseTest.t.sol";

contract ERC6551OpenfortAccountTest is OpenfortBaseTest {
    using ECDSA for bytes32;

    ERC6551Registry public erc6551Registry;
    ERC6551OpenfortAccount public erc6551OpenfortAccount;
    ERC6551OpenfortAccount public erc6551OpenfortAccountImpl;
    ERC6551OpenfortProxy public erc6551OpenfortAccountProxy;
    MockERC721 public mockERC721;

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

        erc6551OpenfortAccountProxy =
            new ERC6551OpenfortProxy{salt: versionSalt}(address(erc6551OpenfortAccountImpl), "");
        
        erc6551OpenfortAccountProxy.implementation();
        erc6551OpenfortAccountProxy.implementation();
        erc6551OpenfortAccountProxy.implementation();
        erc6551OpenfortAccountProxy.implementation();

        accountAddress = erc6551Registry.createAccount(
            address(erc6551OpenfortAccountProxy), versionSalt, chainId, address(mockERC721), 1
        );

        vm.stopPrank();

        erc6551OpenfortAccount = ERC6551OpenfortAccount(payable(accountAddress));
        vm.expectRevert();
        erc6551OpenfortAccount.initialize(address(entryPoint));
        console.log("State: ", erc6551OpenfortAccount.state());

        vm.expectRevert(OpenfortErrorsAndEvents.NotOwner.selector);
        erc6551OpenfortAccount.initialize(address(entryPoint));

        vm.prank(factoryAdmin);
        mockERC721.mint(accountAdmin, 1);

        vm.prank(accountAdmin);
        erc6551OpenfortAccount.initialize(address(entryPoint));
    }

    /*
     * Test get implementation from proxy.
     */
    function testGetImplementation() public view {
        ERC6551OpenfortProxy p = ERC6551OpenfortProxy(payable(accountAddress));
        p.implementation();
    }

    /*
     * Test reinitialize. It should fail.
     */
    function testFailReinitialize() public {
        vm.prank(accountAdmin);
        erc6551OpenfortAccount.initialize(address(entryPoint));
    }

    /*
     * Test initialize implementation. It should fail.
     */
    function testFailInitializeImplementation() public {
        erc6551OpenfortAccountImpl.initialize(address(entryPoint));
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
     * EntryPoint address should be 0. Should pass.
     */
    function testImplementationNoEntryPointAddr() public {
        IEntryPoint e = erc6551OpenfortAccountImpl.entryPoint();
        assertEq(address(e), address(0));
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
        IEntryPoint e = erc6551OpenfortAccount2.entryPoint();
        assertEq(address(e), address(entryPoint));
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
        erc6551OpenfortAccount2.initialize(address(entryPoint));
    }

    /*
     * Test getDeposit() function.
     * First ERC4337 function called by this ERC6551-compatible account.
     */
    function testGetDeposit() public {
        uint256 deposit;
        deposit = erc6551OpenfortAccount.getDeposit();
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

    /*
     * Create an account by directly calling the registry.
     */
    function testCreateAccountWithNonceViaRegistry() public {
        uint256 chainId;
        assembly {
            chainId := chainid()
        }

        // Get the counterfactual address
        vm.prank(factoryAdmin);
        address accountAddress2 =
            erc6551Registry.account(address(erc6551OpenfortAccount), versionSalt, chainId, address(mockERC721), 1);

        // Expect that we will see an event containing the account and admin
        // vm.expectEmit(true, true, false, true);
        // emit IERC6551Registry.ERC6551AccountCreated(
        //     accountAddress2, address(erc6551OpenfortAccount), chainId, address(mockERC721), 1, 2
        // );

        // Deploy a static account to the counterfactual address
        vm.prank(factoryAdmin);
        erc6551Registry.createAccount(address(erc6551OpenfortAccount), versionSalt, chainId, address(mockERC721), 1);

        // Make sure the counterfactual address has not been altered
        vm.prank(factoryAdmin);
        assertEq(
            accountAddress2,
            erc6551Registry.account(address(erc6551OpenfortAccount), versionSalt, chainId, address(mockERC721), 1)
        );
        // assertNotEq(
        //     accountAddress2,
        //     erc6551Registry.account(address(erc6551OpenfortAccount), versionSalt, chainId, address(mockERC721), 1)
        // );
        assertNotEq(
            accountAddress2,
            erc6551Registry.account(address(erc6551OpenfortAccount), versionSalt, chainId + 1, address(mockERC721), 1)
        );
        assertNotEq(
            accountAddress2,
            erc6551Registry.account(address(erc6551OpenfortAccount), versionSalt, chainId, address(0), 1)
        );
    }
}
