// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {console} from "lib/forge-std/src/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {ERC6551Registry, IERC6551Registry} from "erc6551/src/ERC6551Registry.sol";
import {IEntryPoint, UserOperation} from "account-abstraction/core/EntryPoint.sol";
import {IERC6551Account} from "erc6551/src/interfaces/IERC6551Account.sol";
import {IERC6551Executable} from "erc6551/src/interfaces/IERC6551Executable.sol";
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
     * - openfortAdmin is the deployer (and owner) of the mock tokens
     * - openfortAdmin is the account used to deploy new static accounts
     * - entryPoint is the singleton EntryPoint
     * - testCounter is the counter used to test userOps
     */
    function setUp() public override {
        super.setUp();

        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        console.log("ChainId:", chainId);

        vm.startPrank(openfortAdmin);

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

        erc6551OpenfortAccountImpl = new ERC6551OpenfortAccount{salt: versionSalt}();

        accountAddress = erc6551Registry.createAccount(
            address(erc6551OpenfortAccountImpl), versionSalt, chainId, address(mockERC721), 1
        );

        mockERC721.mint(openfortAdmin, 1);

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
        vm.prank(openfortAdmin);
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
        assertEq(erc6551OpenfortAccount.owner(), openfortAdmin);

        vm.chainId(9999999);
        assertEq(erc6551OpenfortAccount.owner(), address(0));
    }

    /*
     * Test token() function.
     * Notice, no need to initialize yet.
     */
    function testToken() public {
        uint256 _chainId;
        assembly {
            _chainId := chainid()
        }
        (uint256 chainId, address tokenContract, uint256 tokenId) = erc6551OpenfortAccount.token();
        assertEq(chainId, _chainId);
        assertEq(tokenContract, address(mockERC721));
        assertEq(tokenId, 1);

        erc6551OpenfortAccount.initialize();

        (uint256 chainId2, address tokenContract2, uint256 tokenId2) = erc6551OpenfortAccount.token();
        assertEq(chainId2, _chainId);
        assertEq(tokenContract2, address(mockERC721));
        assertEq(tokenId2, 1);
    }

    /*
     * Test isValidSigner() function.
     * Notice, no need to initialize yet.
     */
    function testIsValidSigner() public {
        bytes4 isValid = erc6551OpenfortAccount.isValidSigner(vm.addr(2), "");
        assertEq(isValid, 0);

        isValid = erc6551OpenfortAccount.isValidSigner(openfortAdmin, "");
        assertEq(isValid, erc6551OpenfortAccount.isValidSigner.selector);

        erc6551OpenfortAccount.initialize();

        isValid = erc6551OpenfortAccount.isValidSigner(openfortAdmin, "");
        assertEq(isValid, erc6551OpenfortAccount.isValidSigner.selector);
    }

    /*
     * Test owner() function.
     * Check that the owner of the erc6551 account is the owner of the NFT
     */
    function testNotOwner() public {
        // Burning the NFT
        vm.prank(openfortAdmin);
        mockERC721.transferFrom(openfortAdmin, address(1), 1);

        assertEq(erc6551OpenfortAccount.owner(), mockERC721.ownerOf(1));
        assertNotEq(erc6551OpenfortAccount.owner(), openfortAdmin);
        assertEq(erc6551OpenfortAccount.owner(), address(1));
    }

    function testERC6551ExecuteTransferEth() public {
        erc6551OpenfortAccount.initialize();
        vm.deal(accountAddress, 1 ether);

        vm.prank(openfortAdmin);
        vm.expectRevert(ERC6551OpenfortAccount.OperationNotAllowed.selector);
        erc6551OpenfortAccount.execute(payable(vm.addr(2)), 0.5 ether, "", 1);

        vm.prank(openfortAdmin);
        erc6551OpenfortAccount.execute(payable(vm.addr(2)), 0.5 ether, "", 0);

        assertEq(accountAddress.balance, 0.5 ether);
        assertEq(vm.addr(2).balance, 0.5 ether);
        assertEq(erc6551OpenfortAccount.state(), 2);

        vm.prank(openfortAdmin);
        erc6551OpenfortAccount.execute(payable(vm.addr(2)), 0.5 ether, "");

        assertEq(accountAddress.balance, 0 ether);
        assertEq(vm.addr(2).balance, 1 ether);
        assertEq(erc6551OpenfortAccount.state(), 3);
    }

    function testERC6551ExecuteTransferEthBatch() public {
        erc6551OpenfortAccount.initialize();
        vm.deal(accountAddress, 1 ether);

        uint256 count = 2;
        address[] memory targets = new address[](count);
        uint256[] memory values = new uint256[](count);
        bytes[] memory callData = new bytes[](count);

        targets[0] = payable(vm.addr(2));
        targets[1] = payable(vm.addr(3));
        values[0] = 0.25 ether;
        values[1] = 0.25 ether;
        callData[0] = "";
        callData[1] = "";

        vm.prank(openfortAdmin);
        erc6551OpenfortAccount.executeBatch(targets, values, callData);

        assertEq(accountAddress.balance, 0.5 ether);
        assertEq(vm.addr(2).balance, 0.25 ether);
        assertEq(vm.addr(3).balance, 0.25 ether);
        assertEq(erc6551OpenfortAccount.state(), 3);
    }

    /*
     * Create an account using the factory and make it call count() directly.
     */
    function testIncrementCounterDirect() public {
        // Verify that the counter is still set to 0
        assertEq(testCounter.counters(accountAddress), 0);

        // Make the admin of the upgradeable account wallet (deployer) call "count"
        vm.prank(openfortAdmin);
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
            accountAddress, openfortAdminPKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()")
        );

        entryPoint.depositTo{value: 1 ether}(accountAddress);
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);
        entryPoint.handleOps(userOp, beneficiary);

        // Verify that the counter has increased
        assertEq(testCounter.counters(accountAddress), 1);
    }

    function testSupportsInterface() public {
        assertTrue(erc6551OpenfortAccount.supportsInterface(type(IERC6551Account).interfaceId));
        assertTrue(erc6551OpenfortAccount.supportsInterface(type(IERC6551Executable).interfaceId));
        assertTrue(erc6551OpenfortAccount.supportsInterface(type(IERC721Receiver).interfaceId));
        assertTrue(erc6551OpenfortAccount.supportsInterface(type(IERC1155Receiver).interfaceId));
        assertTrue(erc6551OpenfortAccount.supportsInterface(type(IERC165).interfaceId));
        assertFalse(erc6551OpenfortAccount.supportsInterface(bytes4(0x0000)));
        assertEq(erc6551OpenfortAccount.onERC1155Received(address(0), address(0), 0, 0, ""), bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)")));
        uint256[] memory ids = new uint256[](1);
        ids[0] = 1;
        uint256[] memory values = new uint256[](1);
        values[0] = 1;
        assertEq(erc6551OpenfortAccount.onERC1155BatchReceived(address(0), address(0), ids, values, ""), bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)")));
    }

    function testUpdateEntryPoint() public {
        vm.expectRevert(OpenfortErrorsAndEvents.NotOwner.selector);
        erc6551OpenfortAccount.updateEntryPoint(vm.addr(2));

        vm.prank(openfortAdmin);
        vm.expectRevert(OpenfortErrorsAndEvents.ZeroAddressNotAllowed.selector);
        erc6551OpenfortAccount.updateEntryPoint(address(0));

        vm.prank(openfortAdmin);
        erc6551OpenfortAccount.updateEntryPoint(vm.addr(2));

        // Weird behaviour, but not necessarily bad; if the user changes the EntryPoint address
        // before initializing, the EntryPoint is set to the default
        vm.prank(openfortAdmin);
        erc6551OpenfortAccount.initialize();

        vm.prank(openfortAdmin);
        erc6551OpenfortAccount.updateEntryPoint(vm.addr(2));
    }

    /*
     * Test onERC721Received()
     */
    function testSafeTransferFrom() public {
        vm.prank(openfortAdmin);
        vm.expectRevert("Cannot own yourself");
        mockERC721.safeTransferFrom(openfortAdmin, address(erc6551OpenfortAccount), 1);

        uint256 _chainId;
        assembly {
            _chainId := chainid()
        }
        address accountAddress2 = erc6551Registry.createAccount(
            address(erc6551OpenfortAccountImpl), versionSalt, _chainId, address(mockERC721), 2
        );

        // Try with token ID 2 not minted yet
        vm.prank(openfortAdmin);
        vm.expectRevert("ERC721: invalid token ID");
        mockERC721.safeTransferFrom(openfortAdmin, accountAddress2, 1);

        mockERC721.mint(openfortAdmin, 2);
        vm.prank(openfortAdmin);
        mockERC721.safeTransferFrom(openfortAdmin, accountAddress2, 1);
    }

    /*
     * Test onERC721Received()
     */
    function testSafeTransferFrom1155() public {
        mockERC1155.mint(openfortAdmin, 7, 7);

        assertEq(mockERC1155.balanceOf(openfortAdmin, 7), 7);
        assertEq(mockERC1155.balanceOf(address(erc6551OpenfortAccount), 7), 0);

        vm.prank(openfortAdmin);
        mockERC1155.safeTransferFrom(openfortAdmin, address(erc6551OpenfortAccount), 7, 7, "");

        assertEq(mockERC1155.balanceOf(openfortAdmin, 7), 0);
        assertEq(mockERC1155.balanceOf(address(erc6551OpenfortAccount), 7), 7);

        vm.prank(openfortAdmin);
        erc6551OpenfortAccount.execute{value: 1 ether}(
            address(mockERC1155),
            0,
            abi.encodeWithSignature(
                "safeTransferFrom(address,address,uint256,uint256,bytes)",
                address(erc6551OpenfortAccount),
                openfortAdmin,
                7,
                7,
                ""
            )
        );

        assertEq(mockERC1155.balanceOf(openfortAdmin, 7), 7);
        assertEq(mockERC1155.balanceOf(address(erc6551OpenfortAccount), 7), 0);
    }
}
