// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Test, console} from "lib/forge-std/src/Test.sol";
import {SigUtils} from "../../utils/SigUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint, IEntryPoint, UserOperation} from "account-abstraction/core/EntryPoint.sol";
import {VIPNFT} from "contracts/mock/VipNFT.sol";
import {USDC} from "contracts/mock/USDC.sol";

import {UpgradeableOpenfortAccount} from "contracts/core/upgradeable/UpgradeableOpenfortAccount.sol";
import {UpgradeableOpenfortFactory} from "contracts/core/upgradeable/UpgradeableOpenfortFactory.sol";

import {ERC6551Registry} from "lib/erc6551/src/ERC6551Registry.sol";
import {EIP6551OpenfortAccount} from "contracts/core/eip6551/EIP6551OpenfortAccount.sol";

// contract EIP6551OpenfortBenchmark is Test {
//     using ECDSA for bytes32;

//     EntryPoint public entryPoint;

//     UpgradeableOpenfortAccount public implUpgradeableOpenfortAccount;
//     UpgradeableOpenfortFactory public upgradeableOpenfortFactory;
//     UpgradeableOpenfortAccount public upgradeableOpenfortAccount;

//     ERC6551Registry public erc6551Registry;
//     EIP6551OpenfortAccount public eip6551OpenfortAccount;
//     EIP6551OpenfortAccount implEIP6551OpenfortAccount;

//     uint256 public chainId;

//     VIPNFT testToken;
//     USDC testUSDC;

//     // Testing addresses
//     address private factoryAdmin;
//     uint256 private factoryAdminPKey;

//     address private accountAdmin;
//     uint256 private accountAdminPKey;

//     address public upgradeableOpenfortAddressComplex;
//     UpgradeableOpenfortAccount public upgradeableOpenfortAccountComplex;

//     address public eip6551OpenfortAddressComplex;
//     EIP6551OpenfortAccount public eip6551OpenfortAccountComplex;

//     address payable private beneficiary = payable(makeAddr("beneficiary"));

//     event AccountCreated(
//         address account, address implementation, uint256 chainId, address tokenContract, uint256 tokenId, uint256 salt
//     );

//     /*
//      * Auxiliary function to generate a userOP
//      */
//     function _setupUserOp(
//         address sender,
//         uint256 _signerPKey,
//         bytes memory _initCode,
//         bytes memory _callDataForEntrypoint
//     ) internal returns (UserOperation[] memory ops) {
//         uint256 nonce = entryPoint.getNonce(sender, 0);

//         // Get user op fields
//         UserOperation memory op = UserOperation({
//             sender: sender,
//             nonce: nonce,
//             initCode: _initCode,
//             callData: _callDataForEntrypoint,
//             callGasLimit: 500_000,
//             verificationGasLimit: 500_000,
//             preVerificationGas: 500_000,
//             maxFeePerGas: 0,
//             maxPriorityFeePerGas: 0,
//             paymasterAndData: bytes(""),
//             signature: bytes("")
//         });

//         // Sign UserOp
//         bytes32 opHash = EntryPoint(entryPoint).getUserOpHash(op);
//         bytes32 msgHash = ECDSA.toEthSignedMessageHash(opHash);

//         (uint8 v, bytes32 r, bytes32 s) = vm.sign(_signerPKey, msgHash);
//         bytes memory userOpSignature = abi.encodePacked(r, s, v);

//         address recoveredSigner = ECDSA.recover(msgHash, v, r, s);
//         address expectedSigner = vm.addr(_signerPKey);
//         assertEq(recoveredSigner, expectedSigner);

//         op.signature = userOpSignature;

//         // Store UserOp
//         ops = new UserOperation[](1);
//         ops[0] = op;
//     }

//     /*
//      * Auxiliary function to generate a userOP using the execute()
//      * from the account
//      */
//     function _setupUserOpExecute(
//         address sender,
//         uint256 _signerPKey,
//         bytes memory _initCode,
//         address _target,
//         uint256 _value,
//         bytes memory _callData
//     ) internal returns (UserOperation[] memory) {
//         bytes memory callDataForEntrypoint =
//             abi.encodeWithSignature("execute(address,uint256,bytes)", _target, _value, _callData);

//         return _setupUserOp(sender, _signerPKey, _initCode, callDataForEntrypoint);
//     }

//     /*
//      * Auxiliary function to generate a userOP using the executeBatch()
//      * from the account
//      */
//     function _setupUserOpExecuteBatch(
//         address sender,
//         uint256 _signerPKey,
//         bytes memory _initCode,
//         address[] memory _target,
//         uint256[] memory _value,
//         bytes[] memory _callData
//     ) internal returns (UserOperation[] memory) {
//         bytes memory callDataForEntrypoint =
//             abi.encodeWithSignature("executeBatch(address[],uint256[],bytes[])", _target, _value, _callData);

//         return _setupUserOp(sender, _signerPKey, _initCode, callDataForEntrypoint);
//     }

//     /**
//      * @notice Initialize the UpgradeableOpenfortAccount testing contract.
//      * Scenario:
//      * - factoryAdmin is the deployer (and owner) of the UpgradeableOpenfortFactory
//      * - accountAdmin is the account used to deploy new static accounts
//      * - entryPoint is the singleton EntryPoint
//      * - testCounter is the counter used to test userOps
//      */
//     function setUp() public {
//         // Setup and fund signers
//         (factoryAdmin, factoryAdminPKey) = makeAddrAndKey("factoryAdmin");
//         vm.deal(factoryAdmin, 100 ether);
//         (accountAdmin, accountAdminPKey) = makeAddrAndKey("accountAdmin");
//         vm.deal(accountAdmin, 100 ether);

//         uint256 auxChainId;
//         assembly {
//             auxChainId := chainid()
//         }

//         chainId = auxChainId;

//         vm.startPrank(factoryAdmin);

//         // If we are in a fork
//         if (vm.envAddress("ENTRY_POINT_ADDRESS").code.length > 0) {
//             entryPoint = EntryPoint(payable(vm.envAddress("ENTRY_POINT_ADDRESS")));
//         }
//         // If not a fork, deploy entryPoint (at correct address)
//         else {
//             EntryPoint entryPoint_aux = new EntryPoint();
//             bytes memory code = address(entryPoint_aux).code;
//             address targetAddr = address(vm.envAddress("ENTRY_POINT_ADDRESS"));
//             vm.etch(targetAddr, code);
//             entryPoint = EntryPoint(payable(targetAddr));
//         }

//         // deploy upgradeable account implementation
//         implUpgradeableOpenfortAccount = new UpgradeableOpenfortAccount();
//         // deploy upgradeable account factory
//         upgradeableOpenfortFactory = new UpgradeableOpenfortFactory(
//             payable(address(entryPoint)),
//             address(implUpgradeableOpenfortAccount)
//         );

//         // Create an upgradeable account wallet and get its address
//         address upgradeableOpenfortAddress = upgradeableOpenfortFactory.createAccountWithNonce(accountAdmin, "1");

//         upgradeableOpenfortAccount = UpgradeableOpenfortAccount(payable(upgradeableOpenfortAddress));

//         // deploy a new VIPNFT collection
//         testToken = new VIPNFT();

//         implEIP6551OpenfortAccount = new EIP6551OpenfortAccount();

//         erc6551Registry = new ERC6551Registry();

//         address eip6551OpenfortAccountAddress =
//             erc6551Registry.createAccount(address(implEIP6551OpenfortAccount), chainId, address(testToken), 1, 1, "");

//         eip6551OpenfortAccount = EIP6551OpenfortAccount(payable(eip6551OpenfortAccountAddress));
//         eip6551OpenfortAccount.initialize(address(entryPoint));

//         testToken.mint(accountAdmin, 1);

//         testUSDC = new USDC();
//         testUSDC.mint(accountAdmin, 100 ether);

//         // Declarations for complex tests

//         upgradeableOpenfortAddressComplex = upgradeableOpenfortFactory.createAccountWithNonce(accountAdmin, "complex");
//         upgradeableOpenfortAccountComplex = UpgradeableOpenfortAccount(payable(upgradeableOpenfortAddressComplex));

//         testToken.mint(upgradeableOpenfortAddressComplex, 2);

//         eip6551OpenfortAddressComplex =
//             erc6551Registry.createAccount(address(implEIP6551OpenfortAccount), chainId, address(testToken), 2, 2, "");
//         eip6551OpenfortAccountComplex = EIP6551OpenfortAccount(payable(eip6551OpenfortAddressComplex));

//         vm.stopPrank();
//     }

//     /*
//      * Create a 2nd Upgradeable account with accountAdmin as the owner
//      */
//     function test1CreateUpgradeableAccount() public {
//         address upgradeableOpenfortAccountAddress2 =
//             upgradeableOpenfortFactory.createAccountWithNonce(accountAdmin, "2");
//         UpgradeableOpenfortAccount upgradeableOpenfortAccountAccount2 =
//             UpgradeableOpenfortAccount(payable(upgradeableOpenfortAccountAddress2));
//         IEntryPoint e = upgradeableOpenfortAccountAccount2.entryPoint();
//         assertEq(address(e), address(entryPoint));
//     }

//     /*
//      * Create a 2nd EIP6551 account with testToken as the owner and initialize later
//      */
//     function test1CreateEIP6551AccountInitAfter() public {
//         address eip6551OpenfortAccountAddress2 =
//             erc6551Registry.createAccount(address(implEIP6551OpenfortAccount), chainId, address(testToken), 1, 2, "");

//         EIP6551OpenfortAccount eip6551OpenfortAccount2 = EIP6551OpenfortAccount(payable(eip6551OpenfortAccountAddress2));
//         eip6551OpenfortAccount2.initialize(address(entryPoint));
//         IEntryPoint e = eip6551OpenfortAccount2.entryPoint();
//         assertEq(address(e), address(entryPoint));
//     }

//     /*
//      * Create a 2nd EIP6551 account with testToken as the owner and initialize during creation
//      */
//     function test1CreateEIP6551AccountInitDuringCreation() public {
//         address eip6551OpenfortAccountAddress2 = erc6551Registry.createAccount(
//             address(implEIP6551OpenfortAccount),
//             chainId,
//             address(testToken),
//             3,
//             1,
//             abi.encodeWithSignature("initialize(address)", address(entryPoint))
//         );
//         EIP6551OpenfortAccount eip6551OpenfortAccount2 = EIP6551OpenfortAccount(payable(eip6551OpenfortAccountAddress2));
//         IEntryPoint e = eip6551OpenfortAccount2.entryPoint();
//         assertEq(address(e), address(entryPoint));
//     }

//     /*
//      * Test owner() function.
//      * Check that the owner of the upgradeable account is accountAdmin
//      */
//     function test2OwnerUpgradeable() public {
//         assertEq(upgradeableOpenfortAccount.owner(), accountAdmin);
//     }

//     /*
//      * Test owner() function.
//      * Check that the owner of the eip6551 account is the owner of the NFT
//      */
//     function test2OwnerEIP6551() public {
//         assertEq(eip6551OpenfortAccount.owner(), testToken.ownerOf(1));
//     }

//     /*
//      * Test transferOwnership() function using upgradeable accounts.
//      */
//     function test3TransferOwnerUpgradeable() public {
//         assertEq(upgradeableOpenfortAccount.owner(), accountAdmin);

//         vm.prank(accountAdmin);
//         upgradeableOpenfortAccount.transferOwnership(factoryAdmin);

//         assertEq(upgradeableOpenfortAccount.owner(), accountAdmin);
//         assertEq(upgradeableOpenfortAccount.pendingOwner(), factoryAdmin);

//         vm.prank(factoryAdmin);
//         upgradeableOpenfortAccount.acceptOwnership();

//         assertEq(upgradeableOpenfortAccount.owner(), factoryAdmin);
//     }

//     /*
//      * Test transferOwnership() function using EIP6551 accounts.
//      */
//     function test3TransferOwnerEIP6551() public {
//         assertEq(eip6551OpenfortAccount.owner(), accountAdmin);

//         vm.prank(accountAdmin);
//         testToken.safeTransferFrom(accountAdmin, factoryAdmin, 1);

//         assertEq(eip6551OpenfortAccount.owner(), factoryAdmin);
//     }

//     /*
//      * Test transferOwnership() function using EIP6551 account with a userOp
//      * It will fail because the msg.sender doing the transferFrom() is the EntryPoint
//      * the user should do it with a regular TX or approving the EntryPoint to spend
//      */
//     function testFailTransferOwnerEIP6551UserOp() public {
//         assertEq(eip6551OpenfortAccount.owner(), accountAdmin);

//         address _target = address(testToken);
//         bytes memory _callData =
//             abi.encodeWithSignature("transferFrom(address,address,uint256)", accountAdmin, factoryAdmin, 1);

//         UserOperation[] memory userOp = _setupUserOpExecute(
//             address(eip6551OpenfortAccount),
//             accountAdminPKey,
//             bytes(""),
//             address(testToken),
//             0,
//             abi.encodeWithSignature("execute(address,uint256,bytes)", _target, 0, _callData)
//         );

//         entryPoint.depositTo{value: 1000000000000000000}(address(eip6551OpenfortAccount));

//         vm.expectRevert();
//         entryPoint.simulateValidation(userOp[0]);
//         entryPoint.handleOps(userOp, beneficiary);

//         assertEq(eip6551OpenfortAccount.owner(), factoryAdmin);
//     }

//     /*
//      * Test transfer funds using upgradeable accounts.
//      */
//     function test4TransferFundsUpgradeable() public {
//         address upgradeableOpenfortAddress = payable(address((upgradeableOpenfortAccount)));
//         console.log("Admin balance: ", accountAdmin.balance);
//         console.log("Upgradeable Openfort Account balance: ", upgradeableOpenfortAddress.balance);

//         vm.prank(accountAdmin);
//         (bool ok,) = upgradeableOpenfortAddress.call{value: 50 ether}("");
//         assert(ok);
//         console.log("Admin balance: ", accountAdmin.balance);
//         console.log("Upgradeable Openfort Account balance: ", upgradeableOpenfortAddress.balance);

//         vm.prank(accountAdmin);
//         upgradeableOpenfortAccount.execute(accountAdmin, 40 ether, "");

//         console.log("Admin balance: ", accountAdmin.balance);
//         console.log("Upgradeable Openfort Account balance: ", upgradeableOpenfortAddress.balance);
//     }

//     /*
//      * Test transfer funds function using EIP6551 accounts.
//      */
//     function test4TransferFundsEIP6551() public {
//         address eip6551OpenfortAddress = payable(address((eip6551OpenfortAccount)));
//         console.log("Admin balance: ", accountAdmin.balance);
//         console.log("EIP6551 Openfort Account balance: ", eip6551OpenfortAddress.balance);

//         vm.prank(accountAdmin);
//         (bool ok,) = eip6551OpenfortAddress.call{value: 50 ether}("");
//         assert(ok);
//         console.log("Admin balance: ", accountAdmin.balance);
//         console.log("EIP6551 Openfort Account balance: ", eip6551OpenfortAddress.balance);

//         vm.prank(accountAdmin);
//         eip6551OpenfortAccount.execute(accountAdmin, 40 ether, "");

//         console.log("Admin balance: ", accountAdmin.balance);
//         console.log("EIP6551 Openfort Account balance: ", eip6551OpenfortAddress.balance);
//     }

//     /*
//      * Test transfer ERC20 using upgradeable accounts.
//      */
//     function test5TransferERC20Upgradeable() public {
//         address upgradeableOpenfortAddress = payable(address((upgradeableOpenfortAccount)));
//         console.log("Admin balance: ", testUSDC.balanceOf(accountAdmin));
//         console.log("Upgradeable Openfort Account balance: ", testUSDC.balanceOf(upgradeableOpenfortAddress));

//         vm.prank(accountAdmin);
//         testUSDC.transfer(upgradeableOpenfortAddress, 50 ether);
//         console.log("Admin balance: ", testUSDC.balanceOf(accountAdmin));
//         console.log("Upgradeable Openfort Account balance: ", testUSDC.balanceOf(upgradeableOpenfortAddress));

//         vm.prank(accountAdmin);
//         upgradeableOpenfortAccount.execute(
//             address(testUSDC), 0, abi.encodeWithSignature("transfer(address,uint256)", accountAdmin, 50 ether)
//         );
//         console.log("Admin balance: ", testUSDC.balanceOf(accountAdmin));
//         console.log("Upgradeable Openfort Account balance: ", testUSDC.balanceOf(upgradeableOpenfortAddress));
//     }

//     /*
//      * Test transfer ERC20 function using EIP6551 accounts.
//      */
//     function test5TransferERC20EIP6551() public {
//         address eip6551OpenfortAddress = payable(address((eip6551OpenfortAccount)));
//         console.log("Admin balance: ", testUSDC.balanceOf(accountAdmin));
//         console.log("Upgradeable Openfort Account balance: ", testUSDC.balanceOf(eip6551OpenfortAddress));

//         vm.prank(accountAdmin);
//         testUSDC.transfer(eip6551OpenfortAddress, 50 ether);
//         console.log("Admin balance: ", testUSDC.balanceOf(accountAdmin));
//         console.log("EIP6551 Openfort Account balance: ", testUSDC.balanceOf(eip6551OpenfortAddress));

//         vm.prank(accountAdmin);
//         eip6551OpenfortAccount.execute(
//             address(testUSDC), 0, abi.encodeWithSignature("transfer(address,uint256)", accountAdmin, 50 ether)
//         );
//         console.log("Admin balance: ", testUSDC.balanceOf(accountAdmin));
//         console.log("EIP6551 Openfort Account balance: ", testUSDC.balanceOf(eip6551OpenfortAddress));
//     }

//     /*
//      * Test multiple transfers ERC20 using upgradeable accounts.
//      */
//     function test6TransferMultipleERC20Upgradeable() public {
//         address upgradeableOpenfortAddress = payable(address((upgradeableOpenfortAccount)));
//         console.log("Admin balance: ", testUSDC.balanceOf(accountAdmin));
//         console.log("Upgradeable Openfort Account balance: ", testUSDC.balanceOf(upgradeableOpenfortAddress));

//         vm.prank(accountAdmin);
//         testUSDC.transfer(upgradeableOpenfortAddress, 50 ether);
//         console.log("Admin balance: ", testUSDC.balanceOf(accountAdmin));
//         console.log("Upgradeable Openfort Account balance: ", testUSDC.balanceOf(upgradeableOpenfortAddress));

//         vm.startPrank(accountAdmin);
//         upgradeableOpenfortAccount.execute(
//             address(testUSDC), 0, abi.encodeWithSignature("transfer(address,uint256)", accountAdmin, 5 ether)
//         );
//         upgradeableOpenfortAccount.execute(
//             address(testUSDC), 0, abi.encodeWithSignature("transfer(address,uint256)", accountAdmin, 5 ether)
//         );
//         upgradeableOpenfortAccount.execute(
//             address(testUSDC), 0, abi.encodeWithSignature("transfer(address,uint256)", accountAdmin, 5 ether)
//         );
//         upgradeableOpenfortAccount.execute(
//             address(testUSDC), 0, abi.encodeWithSignature("transfer(address,uint256)", accountAdmin, 5 ether)
//         );
//         upgradeableOpenfortAccount.execute(
//             address(testUSDC), 0, abi.encodeWithSignature("transfer(address,uint256)", accountAdmin, 5 ether)
//         );
//         upgradeableOpenfortAccount.execute(
//             address(testUSDC), 0, abi.encodeWithSignature("transfer(address,uint256)", accountAdmin, 5 ether)
//         );
//         upgradeableOpenfortAccount.execute(
//             address(testUSDC), 0, abi.encodeWithSignature("transfer(address,uint256)", accountAdmin, 5 ether)
//         );
//         upgradeableOpenfortAccount.execute(
//             address(testUSDC), 0, abi.encodeWithSignature("transfer(address,uint256)", accountAdmin, 5 ether)
//         );
//         upgradeableOpenfortAccount.execute(
//             address(testUSDC), 0, abi.encodeWithSignature("transfer(address,uint256)", accountAdmin, 5 ether)
//         );
//         upgradeableOpenfortAccount.execute(
//             address(testUSDC), 0, abi.encodeWithSignature("transfer(address,uint256)", accountAdmin, 5 ether)
//         );
//         vm.stopPrank();

//         console.log("Admin balance: ", testUSDC.balanceOf(accountAdmin));
//         console.log("Upgradeable Openfort Account balance: ", testUSDC.balanceOf(upgradeableOpenfortAddress));
//     }

//     /*
//      * Test multiple transfers ERC20 function using EIP6551 accounts.
//      */
//     function test6TransferMultipleERC20EIP6551() public {
//         address eip6551OpenfortAddress = payable(address((eip6551OpenfortAccount)));
//         console.log("Admin balance: ", testUSDC.balanceOf(accountAdmin));
//         console.log("Upgradeable Openfort Account balance: ", testUSDC.balanceOf(eip6551OpenfortAddress));

//         vm.prank(accountAdmin);
//         testUSDC.transfer(eip6551OpenfortAddress, 50 ether);
//         console.log("Admin balance: ", testUSDC.balanceOf(accountAdmin));
//         console.log("EIP6551 Openfort Account balance: ", testUSDC.balanceOf(eip6551OpenfortAddress));

//         vm.startPrank(accountAdmin);
//         eip6551OpenfortAccount.execute(
//             address(testUSDC), 0, abi.encodeWithSignature("transfer(address,uint256)", accountAdmin, 5 ether)
//         );
//         eip6551OpenfortAccount.execute(
//             address(testUSDC), 0, abi.encodeWithSignature("transfer(address,uint256)", accountAdmin, 5 ether)
//         );
//         eip6551OpenfortAccount.execute(
//             address(testUSDC), 0, abi.encodeWithSignature("transfer(address,uint256)", accountAdmin, 5 ether)
//         );
//         eip6551OpenfortAccount.execute(
//             address(testUSDC), 0, abi.encodeWithSignature("transfer(address,uint256)", accountAdmin, 5 ether)
//         );
//         eip6551OpenfortAccount.execute(
//             address(testUSDC), 0, abi.encodeWithSignature("transfer(address,uint256)", accountAdmin, 5 ether)
//         );
//         eip6551OpenfortAccount.execute(
//             address(testUSDC), 0, abi.encodeWithSignature("transfer(address,uint256)", accountAdmin, 5 ether)
//         );
//         eip6551OpenfortAccount.execute(
//             address(testUSDC), 0, abi.encodeWithSignature("transfer(address,uint256)", accountAdmin, 5 ether)
//         );
//         eip6551OpenfortAccount.execute(
//             address(testUSDC), 0, abi.encodeWithSignature("transfer(address,uint256)", accountAdmin, 5 ether)
//         );
//         eip6551OpenfortAccount.execute(
//             address(testUSDC), 0, abi.encodeWithSignature("transfer(address,uint256)", accountAdmin, 5 ether)
//         );
//         eip6551OpenfortAccount.execute(
//             address(testUSDC), 0, abi.encodeWithSignature("transfer(address,uint256)", accountAdmin, 5 ether)
//         );
//         vm.stopPrank();
//         console.log("Admin balance: ", testUSDC.balanceOf(accountAdmin));
//         console.log("EIP6551 Openfort Account balance: ", testUSDC.balanceOf(eip6551OpenfortAddress));
//     }

//     /*
//      * Test owner() function.
//      * Check that the owner of the eip6551 account is the owner of the NFT
//      */
//     function test7ComplexOwner() public {
//         assertEq(eip6551OpenfortAccountComplex.owner(), upgradeableOpenfortAddressComplex);
//     }

//     /*
//      * Test transferOwnership() function using upgradeable account that have EIP6551 accounts.
//      * Scenario: a complex account changes the ownership; all NFTs are manageable by the new owner
//      */
//     function test8TransferOwner4337Complex() public {
//         // The EOA is the owner of the Upgradeable account
//         assertEq(upgradeableOpenfortAccountComplex.owner(), accountAdmin);

//         // The upgradeable account is the owner of the EIP6551 accounts because it holds the NFT
//         assertEq(eip6551OpenfortAccountComplex.owner(), upgradeableOpenfortAddressComplex);
//         assertEq(testToken.ownerOf(2), upgradeableOpenfortAddressComplex);

//         vm.prank(accountAdmin);
//         upgradeableOpenfortAccountComplex.transferOwnership(factoryAdmin);

//         assertEq(upgradeableOpenfortAccountComplex.owner(), accountAdmin);
//         assertEq(upgradeableOpenfortAccountComplex.pendingOwner(), factoryAdmin);

//         vm.prank(factoryAdmin);
//         upgradeableOpenfortAccountComplex.acceptOwnership();

//         assertEq(upgradeableOpenfortAccountComplex.owner(), factoryAdmin);
//         assertEq(eip6551OpenfortAccountComplex.owner(), upgradeableOpenfortAddressComplex);
//         assertEq(testToken.ownerOf(2), upgradeableOpenfortAddressComplex);
//     }

//     /*
//      * Test transferOwnership() function using upgradeable account that have EIP6551 accounts.
//      * Scenario: a complex account transfer an NFT to send an EIP6551 account to another user
//      */
//     function test9TransferOwnerEIP6551Complex() public {
//         // The EOA is the owner of the Upgradeable account
//         assertEq(upgradeableOpenfortAccountComplex.owner(), accountAdmin);
//         // The upgradeable account is the owner of the EIP6551 accounts because it holds the NFT
//         assertEq(eip6551OpenfortAccountComplex.owner(), upgradeableOpenfortAddressComplex);
//         assertEq(testToken.ownerOf(2), upgradeableOpenfortAddressComplex);

//         vm.prank(accountAdmin);
//         upgradeableOpenfortAccountComplex.execute(
//             address(testToken),
//             0,
//             abi.encodeWithSignature(
//                 "transferFrom(address,address,uint256)", upgradeableOpenfortAddressComplex, factoryAdmin, 2
//             )
//         );
//         assertEq(testToken.ownerOf(2), factoryAdmin);
//         assertEq(eip6551OpenfortAccountComplex.owner(), factoryAdmin);
//     }

//     /*
//      * Test transferOwnership() function using upgradeable account that have EIP6551 accounts.
//      */
//     function test9TransferOwnerEIP6551ComplexUserOp() public {
//         // The EOA is the owner of the Upgradeable account
//         assertEq(upgradeableOpenfortAccountComplex.owner(), accountAdmin);
//         // The upgradeable account is the owner of the EIP6551 accounts because it holds the NFT
//         assertEq(eip6551OpenfortAccountComplex.owner(), upgradeableOpenfortAddressComplex);
//         assertEq(testToken.ownerOf(2), upgradeableOpenfortAddressComplex);

//         UserOperation[] memory userOp = _setupUserOpExecute(
//             upgradeableOpenfortAddressComplex,
//             accountAdminPKey,
//             bytes(""),
//             address(testToken),
//             0,
//             abi.encodeWithSignature(
//                 "safeTransferFrom(address,address,uint256)", upgradeableOpenfortAddressComplex, factoryAdmin, 2
//             )
//         );

//         entryPoint.depositTo{value: 1000000000000000000}(upgradeableOpenfortAddressComplex);
//         vm.expectRevert();
//         entryPoint.simulateValidation(userOp[0]);
//         entryPoint.handleOps(userOp, beneficiary);

//         assertEq(testToken.ownerOf(2), factoryAdmin);
//         assertEq(eip6551OpenfortAccountComplex.owner(), factoryAdmin);
//     }
// }
