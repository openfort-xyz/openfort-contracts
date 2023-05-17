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

    uint48 internal constant VALIDUNTIL = 2 ** 48 - 1;
    uint48 internal constant VALIDAFTER = 0;
    uint256 internal constant EXCHANGERATE = 10_000_000;
    uint256 internal constant MOCKSIG = 2 ** 256 - 1;

    /*
     * Auxiliary function to generate a userOP
     */
    function _setupUserOp(
        address sender,
        uint256 _signerPKey,
        bytes memory _initCode,
        bytes memory _callDataForEntrypoint,
        bytes memory paymasterAndData
    ) internal returns (UserOperation[] memory ops) {
        // Get user op fields
        UserOperation memory op = UserOperation({
            sender: sender,
            nonce: entryPoint.getNonce(sender, 0),
            initCode: _initCode,
            callData: _callDataForEntrypoint,
            callGasLimit: 500_000,
            verificationGasLimit: 500_000,
            preVerificationGas: 500_000,
            maxFeePerGas: 1500000000,
            maxPriorityFeePerGas: 1500000000,
            paymasterAndData: paymasterAndData,
            signature: bytes("")
        });

        // Sign UserOp
        bytes32 opHash = EntryPoint(entryPoint).getUserOpHash(op);
        bytes32 msgHash = ECDSA.toEthSignedMessageHash(opHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_signerPKey, msgHash);
        bytes memory userOpSignature = abi.encodePacked(r, s, v);

        // Verifications below commented to avoid "Stack too deep" error
        // address recoveredSigner = ECDSA.recover(msgHash, v, r, s);
        // address expectedSigner = vm.addr(_signerPKey);
        assertEq(ECDSA.recover(msgHash, v, r, s), vm.addr(_signerPKey));

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
        bytes memory _callData,
        bytes memory paymasterAndData
    ) internal returns (UserOperation[] memory) {
        bytes memory callDataForEntrypoint =
            abi.encodeWithSignature("execute(address,uint256,bytes)", _target, _value, _callData);

        return _setupUserOp(sender, _signerPKey, _initCode, callDataForEntrypoint, paymasterAndData);
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
        bytes[] memory _callData,
        bytes memory paymasterAndData
    ) internal returns (UserOperation[] memory) {
        bytes memory callDataForEntrypoint =
            abi.encodeWithSignature("executeBatch(address[],uint256[],bytes[])", _target, _value, _callData);

        return _setupUserOp(sender, _signerPKey, _initCode, callDataForEntrypoint, paymasterAndData);
    }

    function mockedPaymasterDataNative() internal pure returns (bytes memory dataEncoded) {
        // Looking at the source code, I've found this part was not Packed (filled with 0s)
        dataEncoded = abi.encode(VALIDUNTIL, VALIDAFTER, address(0), EXCHANGERATE);
    }

    function mockedPaymasterDataERC20() internal view returns (bytes memory dataEncoded) {
        // Looking at the source code, I've found this part was not Packed (filled with 0s)
        dataEncoded = abi.encode(VALIDUNTIL, VALIDAFTER, address(testToken), EXCHANGERATE);
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
        // Fund the paymaster with 100 ETH
        vm.deal(address(openfortPaymaster), 100 ether);
        // Paymaster deposits 50 ETH to EntryPoint
        openfortPaymaster.deposit{value: 50 ether}();
        // Paymaster stakes 25 ETH
        vm.prank(factoryAdmin);
        openfortPaymaster.addStake{value: 25 ether}(1);

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
     * Test parsePaymasterAndData() when using the native token
     * 
     */
    function testParsePaymasterDataNative() public {
        // Encode the paymaster data
        bytes memory dataEncoded = mockedPaymasterDataNative();
        
        // Get the related paymaster data signature
        bytes32 hash = keccak256(dataEncoded);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(factoryAdminPKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Create the paymasterAndData info
        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, signature); // This part was packed (not filled with 0s)

        (
            uint48 returnedValidUntil,
            uint48 returnedValidAfter,
            address returnedVErc20Token,
            uint256 returnedVExchangeRate,
            bytes memory returnedSignature
        ) = openfortPaymaster.parsePaymasterAndData(paymasterAndData);
        assertEq(returnedValidUntil, VALIDUNTIL);
        assertEq(returnedValidAfter, VALIDAFTER);
        assertEq(returnedVErc20Token, address(0));
        assertEq(returnedVExchangeRate, EXCHANGERATE);
        assertEq(signature, returnedSignature);
    }

    /*
     * Test parsePaymasterAndData() with an ERC20
     * 
     */
    function testParsePaymasterDataERC20() public {
        // Encode the paymaster data
        bytes memory dataEncoded = mockedPaymasterDataERC20();

        // Get the related paymaster data signature
        bytes32 hash = keccak256(dataEncoded);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(factoryAdminPKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Create the paymasterAndData info
        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, signature); // This part was packed (not filled with 0s)

        (
            uint48 returnedValidUntil,
            uint48 returnedValidAfter,
            address returnedVErc20Token,
            uint256 returnedVExchangeRate,
            bytes memory returnedSignature
        ) = openfortPaymaster.parsePaymasterAndData(paymasterAndData);
        assertEq(returnedValidUntil, VALIDUNTIL);
        assertEq(returnedValidAfter, VALIDAFTER);
        assertEq(returnedVErc20Token, address(testToken));
        assertEq(returnedVExchangeRate, EXCHANGERATE);
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
     * Deposit 2 ETH to the EntryPoint on Paymaster's behalf
     * 
     */
    function testEntryPointDepositToPaymaster() public {
        assert(entryPoint.balanceOf(address(openfortPaymaster)) == 50 ether);

        // Directly deposit 1 ETH to EntryPoint on behalf of paymaster
        entryPoint.depositTo{value: 1 ether}(address(openfortPaymaster));
        assert(entryPoint.balanceOf(address(openfortPaymaster)) == 51 ether);
        
        // Paymaster deposits 1 ETH to EntryPoint
        openfortPaymaster.deposit{value: 1 ether}();
        assert(openfortPaymaster.getDeposit() == 52 ether);
    }

    /*
     * Test sending a userOp with an invalid paymasterAndData (valid paymaster, but invalid sig length)
     * Should revert
     */
    function testPaymasterUserOpWrongSigLength() public {
        // Create an static account wallet and get its address
        address account = staticOpenfortAccountFactory.createAccount(accountAdmin, "");

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        bytes memory dataEncoded = mockedPaymasterDataERC20();

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, "0x1234"); // This part was packed (not filled with 0s)

        UserOperation[] memory userOp = _setupUserOpExecute(
            account,
            accountAdminPKey,
            bytes(""),
            address(testCounter),
            0,
            abi.encodeWithSignature("count()"),
            paymasterAndData
        );

        // "VerifyingPaymaster: invalid signature length in paymasterAndData"
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);

        // Verifiy that the counter has not increased
        assertEq(testCounter.counters(account), 0);
    }

    /*
     * Test sending a userOp with an invalid paymasterAndData (valid paymaster, but invalid sig)
     * Should revert
     */
    function testPaymasterUserOpWrongSig() public {
        // Create an static account wallet and get its address
        address account = staticOpenfortAccountFactory.createAccount(accountAdmin, "");

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        bytes memory dataEncoded = mockedPaymasterDataERC20();

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG); // MOCKSIG, "1", MOCKSIG to make sure we send 65 bytes as sig
        console.logBytes(paymasterAndData);
        UserOperation[] memory userOp = _setupUserOpExecute(
            account,
            accountAdminPKey,
            bytes(""),
            address(testCounter),
            0,
            abi.encodeWithSignature("count()"),
            paymasterAndData
        );

        // "AA33 reverted: ECDSA: invalid signature"
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);

        // Verifiy that the counter has not increased
        assertEq(testCounter.counters(account), 0);
    }

    /*
     * Test sending a userOp with an valid paymasterAndData (valid paymaster, valid sig)
     * Should work
     */
    function testPaymasterUserOpNativeValidSig() public {
        // Create an static account wallet and get its address
        address account = staticOpenfortAccountFactory.createAccount(accountAdmin, "");

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);

        bytes memory dataEncoded = mockedPaymasterDataNative();

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG);

        UserOperation[] memory userOps = _setupUserOpExecute(
            account,
            accountAdminPKey,
            bytes(""),
            address(testCounter),
            0,
            abi.encodeWithSignature("count()"),
            paymasterAndData
        );
        bytes32 hash;
        {
            // Simulating that the Paymaster gets the userOp and signs it
            hash = ECDSA.toEthSignedMessageHash(
                openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, address(0), EXCHANGERATE)
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(factoryAdminPKey, hash);
            bytes memory signature = abi.encodePacked(r, s, v);
            bytes memory paymasterAndDataSigned = abi.encodePacked(address(openfortPaymaster), dataEncoded, signature); // This part was packed (not filled with 0s)
            assertEq(openfortPaymaster.owner(), ECDSA.recover(hash, signature));
            userOps[0].paymasterAndData = paymasterAndDataSigned;
        }

        // Back to the user. Sign the userOp
        bytes memory userOpSignature;
        bytes32 hash2;
        {
            bytes32 opHash = EntryPoint(entryPoint).getUserOpHash(userOps[0]);
            bytes32 msgHash = ECDSA.toEthSignedMessageHash(opHash);

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(accountAdminPKey, msgHash);
            userOpSignature = abi.encodePacked(r, s, v);

            // Verifications below commented to avoid "Stack too deep" error
            assertEq(ECDSA.recover(msgHash, v, r, s), vm.addr(accountAdminPKey));
            // Should return account admin
            console.log(ECDSA.recover(msgHash, userOpSignature));
            hash2 = ECDSA.toEthSignedMessageHash(
                openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, address(0), EXCHANGERATE)
            );
        }

        // The hash of the userOp should not have changed after the inclusion of the sig
        assertEq(hash, hash2);
        userOps[0].signature = userOpSignature;

        // Get the paymaster deposit before handling the userOp
        uint256 paymasterDepositBefore = openfortPaymaster.getDeposit();

        entryPoint.handleOps(userOps, beneficiary);
        // entryPoint.simulateValidation(userOp);

        // Verify that the paymaster has less deposit now
        assert(paymasterDepositBefore > openfortPaymaster.getDeposit());
        //Verifiy that the counter has increased
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Test sending a userOp with an valid paymasterAndData (valid paymaster, valid sig)
     * Using ERC20. Should work
     */
    function testPaymasterUserOpERC20ValidSig() public {
        // Create an static account wallet and get its address
        address account = staticOpenfortAccountFactory.createAccount(accountAdmin, "");

        // Verifiy that the counter is stil set to 0
        assertEq(testCounter.counters(account), 0);
        assertEq(testToken.balanceOf(account), 0);
        testToken.mint(account, 100_000);
        assertEq(testToken.balanceOf(account), 100_000);

        bytes memory dataEncoded = mockedPaymasterDataERC20();

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG);

        // Create a userOp to let the paymaster use our testTokens
        UserOperation[] memory userOps = _setupUserOpExecute(
            account,
            accountAdminPKey,
            bytes(""),
            address(testToken),
            0,
            abi.encodeWithSignature("approve(address,uint256)", address(openfortPaymaster), 2 ** 256 - 1),
            paymasterAndData
        );

        bytes32 hash;
        {
            // Simulating that the Paymaster gets the userOp and signs it
            hash = ECDSA.toEthSignedMessageHash(
                openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, address(testToken), EXCHANGERATE)
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(factoryAdminPKey, hash);
            bytes memory signature = abi.encodePacked(r, s, v);
            bytes memory paymasterAndDataSigned = abi.encodePacked(address(openfortPaymaster), dataEncoded, signature); // This part was packed (not filled with 0s)
            assertEq(openfortPaymaster.owner(), ECDSA.recover(hash, signature));
            userOps[0].paymasterAndData = paymasterAndDataSigned;
        }

        // Back to the user. Sign the userOp
        bytes memory userOpSignature;
        bytes32 hash2;
        {
            bytes32 opHash = EntryPoint(entryPoint).getUserOpHash(userOps[0]);
            bytes32 msgHash = ECDSA.toEthSignedMessageHash(opHash);

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(accountAdminPKey, msgHash);
            userOpSignature = abi.encodePacked(r, s, v);

            // Verifications below commented to avoid "Stack too deep" error
            assertEq(ECDSA.recover(msgHash, v, r, s), vm.addr(accountAdminPKey));
            // Should return account admin
            console.log(ECDSA.recover(msgHash, userOpSignature));
            hash2 = ECDSA.toEthSignedMessageHash(
                openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, address(testToken), EXCHANGERATE)
            );
        }

        // The hash of the userOp should not have changed after the inclusion of the sig
        assertEq(hash, hash2);
        userOps[0].signature = userOpSignature;

        // Get the paymaster deposit before handling the userOp
        uint256 paymasterDepositBefore = openfortPaymaster.getDeposit();

        entryPoint.handleOps(userOps, beneficiary);
        // entryPoint.simulateValidation(userOp);
        console.log(testToken.balanceOf(account));
        console.log(testToken.allowance(account, address(openfortPaymaster)));
        console.log(testToken.balanceOf(factoryAdmin));
        // Verify that the paymaster has less deposit now
        assert(paymasterDepositBefore > openfortPaymaster.getDeposit());
        //Verifiy that the counter has increased
        assert(testToken.balanceOf(account) < 100_000);
    }
}
