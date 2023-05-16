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

        // retrieve the entryPoint and deploy openfortPaymaster
        entryPoint = EntryPoint(payable(vm.envAddress("ENTRY_POINT_ADDRESS")));
        openfortPaymaster = new OpenfortPaymaster(IEntryPoint(payable(address(entryPoint))), factoryAdmin);

        // deploy account factory
        vm.prank(factoryAdmin);
        staticOpenfortAccountFactory = new StaticOpenfortAccountFactory(IEntryPoint(payable(address(entryPoint))));
        // deploy a new TestCounter
        testCounter = new TestCounter();
        // deploy a new TestToken (ERC20) and mint 100
        testToken = new TestToken();
        testToken.mint(address(this), 100);
    }

    /*
     * Test initial parameters
     * 
     */
    function testInitialParameters() public {
        assertEq(address(openfortPaymaster.entryPoint()), vm.envAddress("ENTRY_POINT_ADDRESS"));
        assertEq(address(openfortPaymaster.owner()), factoryAdmin);
    }

    /*
     * Test parsePaymasterAndData
     * 
     */
    function testParsePaymasterData() public {
        uint48 validUntil = 2 ** 48 - 1;
        uint48 validAfter = 0;
        address erc20Token = address(testToken);
        uint256 exchangeRate = 1000;
        bytes memory signature;

        bytes32 hash = keccak256(
                abi.encodePacked(
                    validUntil, validAfter, erc20Token, exchangeRate));
        { // Using scoping to avoid the "Stack too deep" error
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(factoryAdminPKey, hash);
            signature = abi.encodePacked(r, s, v);
        }
        bytes memory dataEncoded = abi.encode(validUntil, validAfter, erc20Token, exchangeRate); // Looking at the source code, I've found this part was not Packed (filled with 0s)

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, signature); // This part was packed (filled with 0s)

        uint48 returnedValidUntil;
        uint48 returnedValidAfter;
        address returnedVErc20Token;
        uint256 returnedVExchangeRate;
        bytes memory returnedSignature;

        (returnedValidUntil, returnedValidAfter, returnedVErc20Token, returnedVExchangeRate, returnedSignature) = openfortPaymaster.parsePaymasterAndData(paymasterAndData);
        assertEq(validUntil, returnedValidUntil);
        assertEq(validAfter, returnedValidAfter);
        assertEq(erc20Token, returnedVErc20Token);
        assertEq(exchangeRate, returnedVExchangeRate);
        assertEq(signature, returnedSignature);
    }

    /*
     * The owner (factoryAdmin) can add stake
     * Others cannot
     */
    function testPaymasterAddStake() public {
        // The owner can add stake
        vm.prank(factoryAdmin);
        openfortPaymaster.addStake{value: 2}(1);

        // Others cannot add stake
        vm.expectRevert("Ownable: caller is not the owner");
        openfortPaymaster.addStake{value: 2}(1);
    }

    /*
     * Deposit 1 ETH to the EntryPoint on Paymaster's behalf
     * 
     */
    function testEntryPointDepositToPaymaster() public {
        entryPoint.depositTo{ value: 1 }(address(openfortPaymaster));
    }

    function testDepositAndReadBalance() public {
        // Create an static account wallet and get its address
        address account = staticOpenfortAccountFactory.createAccount(accountAdmin, "");
        // openfortPaymaster.addDepositFor(address(testToken), account, 100);
        // uint depositInfo = openfortPaymaster.depositInfo(address(testToken), account);
        // assertEq(depositInfo, 100);
    }
}
