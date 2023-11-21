// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {console} from "lib/forge-std/src/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ERC6551Registry, IERC6551Registry} from "erc6551/src/ERC6551Registry.sol";
import {EntryPoint, IEntryPoint, UserOperation} from "account-abstraction/core/EntryPoint.sol";
import {MockERC721} from "contracts/mock/MockERC721.sol";
import {EIP6551OpenfortAccount} from "contracts/core/eip6551/EIP6551OpenfortAccount.sol";
import {OpenfortBaseTest} from "../OpenfortBaseTest.t.sol";

contract EIP6551OpenfortAccountTest is OpenfortBaseTest {
    using ECDSA for bytes32;

    ERC6551Registry public erc6551Registry;
    EIP6551OpenfortAccount public eip6551OpenfortAccount;
    EIP6551OpenfortAccount public implEIP6551OpenfortAccount;
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

        implEIP6551OpenfortAccount = new EIP6551OpenfortAccount{salt: versionSalt}();

        address eip6551OpenfortAccountAddress = erc6551Registry.createAccount(
            address(implEIP6551OpenfortAccount), versionSalt, chainId, address(mockERC721), 1
        );

        eip6551OpenfortAccount = EIP6551OpenfortAccount(payable(eip6551OpenfortAccountAddress));
        eip6551OpenfortAccount.initialize(address(entryPoint));

        mockERC721.mint(eip6551OpenfortAccountAddress, 1);

        vm.stopPrank();
    }

    /*
     * Test reinitialize. It should fail.
     */
    function testFailReinitialize() public {
        eip6551OpenfortAccount.initialize(address(entryPoint));
    }

    /*
     * Test deploy. Regular, no userOps.
     */
    function testERC6551Deploy() public {
        address deployedAccount =
            erc6551Registry.createAccount(address(implEIP6551OpenfortAccount), 0, block.chainid, address(0), 0);

        assertTrue(deployedAccount != address(0));

        address predictedAccount =
            erc6551Registry.account(address(implEIP6551OpenfortAccount), 0, block.chainid, address(0), 0);

        assertEq(predictedAccount, deployedAccount);
    }

    /*
     * Test initialize implementation. It should fail.
     */
    function testFailInitializeImplementation() public {
        implEIP6551OpenfortAccount.initialize(address(entryPoint));
    }

    /*
     * Check implementation has not been initialized.
     * EntryPoint address should be 0. Should pass.
     */
    function testImplementationNoEntryPointAddr() public {
        IEntryPoint e = implEIP6551OpenfortAccount.entryPoint();
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
        address eip6551OpenfortAccountAddress2 = erc6551Registry.createAccount(
            address(implEIP6551OpenfortAccount), bytes32(0), chainId, address(mockERC721), 1
        );

        EIP6551OpenfortAccount eip6551OpenfortAccount2 = EIP6551OpenfortAccount(payable(eip6551OpenfortAccountAddress2));
        IEntryPoint e = eip6551OpenfortAccount2.entryPoint();
        assertEq(address(e), address(entryPoint));
        assertNotEq(address(e), eip6551OpenfortAccountAddress2);
    }

    /*
     * Create a new account using createAccount() and the initializer.
     */
    function testCreateAccInitializer() public {
        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        address eip6551OpenfortAccountAddress2 = erc6551Registry.createAccount(
            address(implEIP6551OpenfortAccount), versionSalt, chainId, address(mockERC721), 1
        );
        EIP6551OpenfortAccount eip6551OpenfortAccount2 = EIP6551OpenfortAccount(payable(eip6551OpenfortAccountAddress2));
        IEntryPoint e = eip6551OpenfortAccount2.entryPoint();
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
        address eip6551OpenfortAccountAddress2 = erc6551Registry.createAccount(
            address(implEIP6551OpenfortAccount), versionSalt, chainId, address(mockERC721), 1
        );

        EIP6551OpenfortAccount eip6551OpenfortAccount2 = EIP6551OpenfortAccount(payable(eip6551OpenfortAccountAddress2));
        eip6551OpenfortAccount2.initialize(address(entryPoint));
    }

    /*
     * Test getDeposit() function.
     * First ERC4337 function called by this EIP6551-compatible account.
     */
    function testGetDeposit() public {
        uint256 deposit;
        deposit = eip6551OpenfortAccount.getDeposit();
        assertEq(deposit, 0);

        // We can add deposit by directly calling the EntryPoint
        entryPoint.depositTo{value: 1}(address(eip6551OpenfortAccount));
        deposit = eip6551OpenfortAccount.getDeposit();
        assertEq(deposit, 1);

        // We can ALSO add deposit by calling the EntryPoint addDeposit() function of the account
        eip6551OpenfortAccount.addDeposit{value: 1}();
        deposit = eip6551OpenfortAccount.getDeposit();
        assertEq(deposit, 2);
    }

    /*
     * Test owner() function.
     * Check that the owner of the eip6551 account is the owner of the NFT
     */
    function testOwner() public {
        assertEq(eip6551OpenfortAccount.owner(), mockERC721.ownerOf(1));
        assertEq(eip6551OpenfortAccount.owner(), address(eip6551OpenfortAccount));
    }

    /*
     * Test owner() function.
     * Check that the owner of the eip6551 account is the owner of the NFT
     */
    function testNotOwner() public {
        // Burning the NFT
        vm.prank(address(eip6551OpenfortAccount));
        mockERC721.transferFrom(address(eip6551OpenfortAccount), address(1), 1);

        assertEq(eip6551OpenfortAccount.owner(), mockERC721.ownerOf(1));
        assertNotEq(eip6551OpenfortAccount.owner(), address(eip6551OpenfortAccount));
        assertEq(eip6551OpenfortAccount.owner(), address(1));
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
        address eip6551OpenfortAccountAddress2 =
            erc6551Registry.account(address(eip6551OpenfortAccount), versionSalt, chainId, address(mockERC721), 1);

        // Expect that we will see an event containing the account and admin
        // vm.expectEmit(true, true, false, true);
        // emit IERC6551Registry.ERC6551AccountCreated(
        //     eip6551OpenfortAccountAddress2, address(eip6551OpenfortAccount), chainId, address(mockERC721), 1, 2
        // );

        // Deploy a static account to the counterfactual address
        vm.prank(factoryAdmin);
        erc6551Registry.createAccount(address(eip6551OpenfortAccount), versionSalt, chainId, address(mockERC721), 1);

        // Make sure the counterfactual address has not been altered
        vm.prank(factoryAdmin);
        assertEq(
            eip6551OpenfortAccountAddress2,
            erc6551Registry.account(address(eip6551OpenfortAccount), versionSalt, chainId, address(mockERC721), 1)
        );
        // assertNotEq(
        //     eip6551OpenfortAccountAddress2,
        //     erc6551Registry.account(address(eip6551OpenfortAccount), versionSalt, chainId, address(mockERC721), 1)
        // );
        assertNotEq(
            eip6551OpenfortAccountAddress2,
            erc6551Registry.account(address(eip6551OpenfortAccount), versionSalt, chainId + 1, address(mockERC721), 1)
        );
        assertNotEq(
            eip6551OpenfortAccountAddress2,
            erc6551Registry.account(address(eip6551OpenfortAccount), versionSalt, chainId, address(0), 1)
        );
    }
}
