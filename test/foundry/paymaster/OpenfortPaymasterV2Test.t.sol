// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Test, console} from "lib/forge-std/src/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint, UserOperation, IEntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";
import {TestToken} from "account-abstraction/test/TestToken.sol";
import {IPaymaster} from "account-abstraction/interfaces/IPaymaster.sol";

import {StaticOpenfortFactory} from "contracts/core/static/StaticOpenfortFactory.sol";
import {StaticOpenfortAccount} from "contracts/core/static/StaticOpenfortAccount.sol";
import {OpenfortPaymasterV2} from "contracts/paymaster/OpenfortPaymasterV2.sol";

contract OpenfortPaymasterV2Test is Test {
    using ECDSA for bytes32;

    EntryPoint public entryPoint;
    StaticOpenfortAccount public staticOpenfortAccount;
    StaticOpenfortFactory public staticOpenfortFactory;
    OpenfortPaymasterV2 public openfortPaymaster;
    address public account;
    TestCounter public testCounter;
    TestToken public testToken;

    // Testing addresses
    address private factoryAdmin;
    uint256 private factoryAdminPKey;

    address private paymasterAdmin;
    uint256 private paymasterAdminPKey;

    address private accountAdmin;
    uint256 private accountAdminPKey;

    address payable private beneficiary = payable(makeAddr("beneficiary"));

    uint48 internal constant VALIDUNTIL = 2 ** 48 - 1;
    uint48 internal constant VALIDAFTER = 0;
    uint256 internal constant EXCHANGERATE = 10 ** 3;
    uint256 internal constant MOCKSIG = 2 ** 256 - 1;
    uint256 internal TESTTOKEN_ACCOUNT_PREFUND = 100 * 10 ** 18;

    error InvalidTokenRecipient();

    event PostOpGasUpdated(uint256 oldPostOpGas, uint256 _newPostOpGas);

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

    function mockedPaymasterDataNative(address _depositor) internal pure returns (bytes memory dataEncoded) {
        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.PayForUser;
        strategy.depositor = _depositor;
        strategy.erc20Token = address(0);
        strategy.exchangeRate = 0;
        // Looking at the source code, I've found this part was not Packed (filled with 0s)
        dataEncoded = abi.encode(VALIDUNTIL, VALIDAFTER, strategy);
    }

    function mockedPaymasterDataERC20Dynamic(address _depositor) internal view returns (bytes memory dataEncoded) {
        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.DynamicRate;
        strategy.depositor = _depositor;
        strategy.erc20Token = address(testToken);
        strategy.exchangeRate = EXCHANGERATE;
        // Looking at the source code, I've found this part was not Packed (filled with 0s)
        dataEncoded = abi.encode(VALIDUNTIL, VALIDAFTER, strategy);
    }

    function mockedPaymasterDataERC20Fixed(address _depositor, uint256 _pricePerTransaction)
        internal
        view
        returns (bytes memory dataEncoded)
    {
        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.FixedRate;
        strategy.depositor = _depositor;
        strategy.erc20Token = address(testToken);
        strategy.exchangeRate = _pricePerTransaction;
        // Looking at the source code, I've found this part was not Packed (filled with 0s)
        dataEncoded = abi.encode(VALIDUNTIL, VALIDAFTER, strategy);
    }

    /**
     * @notice Initialize the StaticOpenfortAccount testing contract.
     * Scenario:
     * - factoryAdmin is the deployer (and owner) of the StaticOpenfortFactory
     * - paymasterAdmin is the deployer (and owner) of the OpenfortPaymaster
     * - accountAdmin is the account used to deploy new static accounts
     * - entryPoint is the singleton EntryPoint
     * - testCounter is the counter used to test userOps
     */
    function setUp() public {
        // Setup and fund signers
        (factoryAdmin, factoryAdminPKey) = makeAddrAndKey("factoryAdmin");
        vm.deal(factoryAdmin, 100 ether);
        (accountAdmin, accountAdminPKey) = makeAddrAndKey("accountAdmin");
        vm.deal(accountAdmin, 100 ether);
        (paymasterAdmin, paymasterAdminPKey) = makeAddrAndKey("paymasterAdmin");
        vm.deal(paymasterAdmin, 100 ether);

        // If we are in a fork
        if (vm.envAddress("ENTRY_POINT_ADDRESS").code.length > 0) {
            entryPoint = EntryPoint(payable(vm.envAddress("ENTRY_POINT_ADDRESS")));
        }
        // If not a fork, deploy entryPoint (at correct address)
        else {
            EntryPoint entryPoint_aux = new EntryPoint();
            bytes memory code = address(entryPoint_aux).code;
            address targetAddr = address(vm.envAddress("ENTRY_POINT_ADDRESS"));
            vm.etch(targetAddr, code);
            entryPoint = EntryPoint(payable(targetAddr));
        }
        vm.prank(paymasterAdmin);
        openfortPaymaster = new OpenfortPaymasterV2(IEntryPoint(payable(address(entryPoint))), paymasterAdmin);
        // Paymaster deposits 50 ETH to EntryPoint
        vm.prank(paymasterAdmin);
        openfortPaymaster.deposit{value: 50 ether}();
        // Paymaster stakes 25 ETH
        vm.prank(paymasterAdmin);
        openfortPaymaster.addStake{value: 25 ether}(1);

        // deploy account factory
        vm.prank(factoryAdmin);
        staticOpenfortAccount = new StaticOpenfortAccount();
        vm.prank(factoryAdmin);
        staticOpenfortFactory =
            new StaticOpenfortFactory((payable(vm.envAddress("ENTRY_POINT_ADDRESS"))), address(staticOpenfortAccount));
        // deploy a new TestCounter
        testCounter = new TestCounter();
        // deploy a new TestToken (ERC20) and mint 1000
        testToken = new TestToken();
        testToken.mint(address(this), 1_000 * 10 ** 18);

        // Create an static account wallet and get its address
        vm.prank(factoryAdmin);
        account = staticOpenfortFactory.createAccountWithNonce(accountAdmin, "1");
    }

    /*
     * Test initial parameters
     * 
     */
    function testInitialParameters() public {
        assertEq(address(openfortPaymaster.entryPoint()), vm.envAddress("ENTRY_POINT_ADDRESS"));
        assertEq(address(openfortPaymaster.owner()), paymasterAdmin);
    }

    /**
     * Deposit should fail if not the owner
     */
    function testFailDeposit() public {
        vm.prank(factoryAdmin);
        openfortPaymaster.deposit{value: 50 ether}();
    }

    /*
     * Test parsePaymasterAndData() when using the native token
     * 
     */
    function testParsePaymasterDataNative() public {
        // Encode the paymaster data
        bytes memory dataEncoded = mockedPaymasterDataNative(paymasterAdmin);

        // Get the related paymaster data signature
        bytes32 hash = keccak256(dataEncoded);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Create the paymasterAndData info
        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, signature); // This part was packed (not filled with 0s)

        (
            uint48 returnedValidUntil,
            uint48 returnedValidAfter,
            OpenfortPaymasterV2.PolicyStrategy memory strategy,
            bytes memory returnedSignature
        ) = openfortPaymaster.parsePaymasterAndData(paymasterAndData);

        assertEq(returnedValidUntil, VALIDUNTIL);
        assertEq(returnedValidAfter, VALIDAFTER);
        assertEq(strategy.erc20Token, address(0));
        assertEq(strategy.exchangeRate, 0);
        assertEq(signature, returnedSignature);
    }

    /*
     * Test parsePaymasterAndData() with an ERC20 dynamic
     * 
     */
    function testParsePaymasterDataERC20() public {
        // Encode the paymaster data
        bytes memory dataEncoded = mockedPaymasterDataERC20Dynamic(paymasterAdmin);

        // Get the related paymaster data signature
        bytes32 hash = keccak256(dataEncoded);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Create the paymasterAndData info
        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, signature); // This part was packed (not filled with 0s)
        console.logBytes(paymasterAndData);

        (
            uint48 returnedValidUntil,
            uint48 returnedValidAfter,
            OpenfortPaymasterV2.PolicyStrategy memory strategy,
            bytes memory returnedSignature
        ) = openfortPaymaster.parsePaymasterAndData(paymasterAndData);
        assertEq(returnedValidUntil, VALIDUNTIL);
        assertEq(returnedValidAfter, VALIDAFTER);
        assertEq(strategy.erc20Token, address(testToken));
        assertEq(strategy.exchangeRate, EXCHANGERATE);
        assertEq(signature, returnedSignature);
    }

    /*
     * The owner (paymasterAdmin) can add and withdraw stake.
     * Others cannot.
     */
    function testPaymasterStake() public {
        assertEq(paymasterAdmin.balance, 25 ether);

        // The owner can add stake
        vm.prank(paymasterAdmin);
        openfortPaymaster.addStake{value: 2 ether}(10);
        assertEq(paymasterAdmin.balance, 23 ether);

        // Others cannot add stake
        vm.expectRevert("Ownable: caller is not the owner");
        openfortPaymaster.addStake{value: 2}(10);

        // The owner trying to withdraw stake fails because it has not unlocked
        // The owner can withdraw stake
        vm.prank(paymasterAdmin);
        vm.expectRevert();
        openfortPaymaster.withdrawStake(payable(paymasterAdmin));

        // The owner unlocks the stake
        vm.prank(paymasterAdmin);
        openfortPaymaster.unlockStake();

        // The owner trying to unlock fails because it has not passed enought time
        vm.prank(paymasterAdmin);
        vm.expectRevert();
        openfortPaymaster.withdrawStake(payable(paymasterAdmin));

        // Passes 20 blocks...
        skip(20);

        // The owner can now withdraw stake (the 2 ethers recently staked + the 25 from the SetUp)
        vm.prank(paymasterAdmin);
        openfortPaymaster.withdrawStake(payable(paymasterAdmin));
        assertEq(paymasterAdmin.balance, 50 ether);
    }

    /*
     * Complete deposit walkthrough test
     */
    function testDepositsToPaymaster() public {
        // Initially, the Paymaster has 50 ether deposited
        assertEq(entryPoint.balanceOf(address(openfortPaymaster)), 50 ether);

        // Directly deposit 1 ETH to EntryPoint on behalf of the Paymaster
        entryPoint.depositTo{value: 1 ether}(address(openfortPaymaster));
        assertEq(entryPoint.balanceOf(address(openfortPaymaster)), 51 ether);

        // Cannot deposit to address 0
        vm.expectRevert();
        openfortPaymaster.depositFor{value: 0 ether}(address(0));

        // Cannot deposit 0 ether
        vm.expectRevert();
        openfortPaymaster.depositFor{value: 0 ether}(factoryAdmin);

        // Cannot depositFor using owner
        vm.prank(paymasterAdmin);
        vm.expectRevert();
        openfortPaymaster.depositFor{value: 1 ether}(paymasterAdmin);

        // Paymaster deposits 1 ETH to EntryPoint
        openfortPaymaster.depositFor{value: 1 ether}(factoryAdmin);
        assertEq(openfortPaymaster.getDepositFor(factoryAdmin), 1 ether);

        // Get the WHOLE deposited amount so far
        assertEq(openfortPaymaster.getDeposit(), 52 ether);
        // Notice that, even though the deposit was made to the EntryPoint for the openfortPaymaster, the deposit is 0:
        assertEq(openfortPaymaster.getDepositFor(address(openfortPaymaster)), 0 ether);

        // All deposit not made using "depositFor" goes to owner (paymasterAdmin)
        assertEq(openfortPaymaster.getDepositFor(paymasterAdmin), 51 ether);

        vm.expectRevert("Not Owner: use depositFor() instead");
        openfortPaymaster.deposit{value: 1 ether}();
        // Get the WHOLE deposited amount so far
        assertEq(openfortPaymaster.getDeposit(), 52 ether);

        vm.prank(paymasterAdmin);
        openfortPaymaster.deposit{value: 1 ether}();
        // Get the WHOLE deposited amount so far
        assertEq(openfortPaymaster.getDeposit(), 53 ether);

        vm.expectRevert();
        openfortPaymaster.withdrawTo(payable(paymasterAdmin), 1 ether);
        assertEq(openfortPaymaster.getDeposit(), 53 ether);

        vm.prank(paymasterAdmin);
        openfortPaymaster.withdrawTo(payable(paymasterAdmin), 1 ether);
        // Get the WHOLE deposited amount so far
        assertEq(openfortPaymaster.getDeposit(), 52 ether);

        vm.expectRevert();
        vm.prank(paymasterAdmin);
        openfortPaymaster.withdrawTo(payable(paymasterAdmin), 10000 ether);
        // Get the WHOLE deposited amount so far
        assertEq(openfortPaymaster.getDeposit(), 52 ether);

        // Let's now use withdrawDepositorTo
        // Owner cannot call it
        vm.expectRevert();
        vm.prank(paymasterAdmin);
        openfortPaymaster.withdrawDepositorTo(payable(paymasterAdmin), 1 ether);

        // factoryAdmin can call it
        assertEq(openfortPaymaster.getDepositFor(factoryAdmin), 1 ether);
        assertEq(factoryAdmin.balance, 100 ether);
        // but not too much!
        vm.expectRevert();
        vm.prank(factoryAdmin);
        openfortPaymaster.withdrawDepositorTo(payable(factoryAdmin), 1000 ether);
        // not using address 0!
        vm.expectRevert();
        vm.prank(factoryAdmin);
        openfortPaymaster.withdrawDepositorTo(payable(address(0)), 1 ether);
        vm.prank(factoryAdmin);
        openfortPaymaster.withdrawDepositorTo(payable(factoryAdmin), 1 ether);
        assertEq(openfortPaymaster.getDepositFor(factoryAdmin), 0 ether);
        assertEq(factoryAdmin.balance, 101 ether);
        // Deposit of the owner is still 51
        assertEq(openfortPaymaster.getDepositFor(paymasterAdmin), 51 ether);

        // Finally, let's test withdrawFromDepositor
        // deposit again using factoryAdmin
        openfortPaymaster.depositFor{value: 1 ether}(factoryAdmin);
        assertEq(openfortPaymaster.getDepositFor(factoryAdmin), 1 ether);
        // Only owner cannot call it
        vm.expectRevert();
        openfortPaymaster.withdrawFromDepositor(factoryAdmin, payable(factoryAdmin), 1 ether);
        assertEq(openfortPaymaster.getDepositFor(factoryAdmin), 1 ether);

        vm.expectRevert();
        vm.prank(paymasterAdmin);
        openfortPaymaster.withdrawFromDepositor(factoryAdmin, payable(factoryAdmin), 100 ether);
        assertEq(openfortPaymaster.getDepositFor(factoryAdmin), 1 ether);

        vm.prank(paymasterAdmin);
        openfortPaymaster.withdrawFromDepositor(factoryAdmin, payable(factoryAdmin), 1 ether);
        assertEq(openfortPaymaster.getDepositFor(factoryAdmin), 0 ether);
    }

    /*
     * Test sending a userOp with an invalid paymasterAndData (valid paymaster, but invalid sig length)
     * Should revert
     */
    function testPaymasterUserOpWrongSigLength() public {
        bytes memory dataEncoded = mockedPaymasterDataERC20Dynamic(paymasterAdmin);

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

        // "ECDSA: invalid signature length"
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
        bytes memory dataEncoded = mockedPaymasterDataERC20Dynamic(paymasterAdmin);

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG); // MOCKSIG, "1", MOCKSIG to make sure we send 65 bytes as sig
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
        bytes memory dataEncoded = mockedPaymasterDataNative(paymasterAdmin);

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
        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.PayForUser;
        strategy.depositor = paymasterAdmin;
        strategy.erc20Token = address(0);
        strategy.exchangeRate = 0;
        bytes32 hash;
        {
            // Simulating that the Paymaster gets the userOp and signs it
            hash = ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
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
            hash2 =
                ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
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
     * Test sending a userOp with signature from a wrong address
     * Should not work
     */
    function testPaymasterUserOpNativeWrongUserSig() public {
        bytes memory dataEncoded = mockedPaymasterDataNative(paymasterAdmin);

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
        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.PayForUser;
        strategy.erc20Token = address(0);
        strategy.exchangeRate = EXCHANGERATE;
        bytes32 hash;
        {
            // Simulating that the factory admin gets the userOp and tries to sign it
            hash = ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(factoryAdminPKey, hash);
            bytes memory signature = abi.encodePacked(r, s, v);
            bytes memory paymasterAndDataSigned = abi.encodePacked(address(openfortPaymaster), dataEncoded, signature); // This part was packed (not filled with 0s)
            assertEq(factoryAdmin, ECDSA.recover(hash, signature));
            userOps[0].paymasterAndData = paymasterAndDataSigned;
        }

        // Back to the user. Sign the userOp
        bytes memory userOpSignature;
        bytes32 hash2;
        {
            bytes32 opHash = EntryPoint(entryPoint).getUserOpHash(userOps[0]);
            bytes32 msgHash = ECDSA.toEthSignedMessageHash(opHash);

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(factoryAdminPKey, msgHash);
            userOpSignature = abi.encodePacked(r, s, v);

            // Verifications below commented to avoid "Stack too deep" error
            assertEq(ECDSA.recover(msgHash, v, r, s), vm.addr(factoryAdminPKey));

            // Should return account admin
            hash2 =
                ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
        }

        // The hash of the userOp should not have changed after the inclusion of the sig
        assertEq(hash, hash2);
        userOps[0].signature = userOpSignature;

        // Get the paymaster deposit before handling the userOp
        uint256 paymasterDepositBefore = openfortPaymaster.getDeposit();

        vm.expectRevert();
        entryPoint.handleOps(userOps, beneficiary);
        // entryPoint.simulateValidation(userOp);

        // Verify that the paymaster has less deposit now
        assert(paymasterDepositBefore == openfortPaymaster.getDeposit());
        //Verifiy that the counter has not increased
        assertEq(testCounter.counters(account), 0);
    }

    /*
     * Test sending a userOp with an valid paymasterAndData (valid paymaster, valid sig)
     * Using ERC20. Should work
     */
    function testPaymasterUserOpERC20ValidSigDiffMaxPriorityFeePerGas() public {
        assertEq(testToken.balanceOf(account), 0);
        testToken.mint(account, TESTTOKEN_ACCOUNT_PREFUND);
        assertEq(testToken.balanceOf(account), TESTTOKEN_ACCOUNT_PREFUND);

        bytes memory dataEncoded = mockedPaymasterDataERC20Dynamic(paymasterAdmin);

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

        userOps[0].maxPriorityFeePerGas += 1;
        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.DynamicRate;
        strategy.depositor = paymasterAdmin;
        strategy.erc20Token = address(testToken);
        strategy.exchangeRate = EXCHANGERATE;

        // Simulating that the Paymaster gets the userOp and signs it
        bytes32 hash;
        {
            hash = ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
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
            hash2 =
                ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
        }

        // The hash of the userOp should not have changed after the inclusion of the sig
        assertEq(hash, hash2);
        userOps[0].signature = userOpSignature;

        // Get the paymaster deposit before handling the userOp
        uint256 paymasterDepositBefore = openfortPaymaster.getDeposit();

        entryPoint.handleOps(userOps, beneficiary);

        // Verify that the paymaster has less deposit now
        assert(paymasterDepositBefore > openfortPaymaster.getDeposit());
        // Verifiy that the balance of the smart account has decreased
        assert(testToken.balanceOf(account) < TESTTOKEN_ACCOUNT_PREFUND);
    }

    /*
     * Test sending a userOp with a valid paymasterAndData (valid paymaster, valid sig)
     * Using ERC20. Should work
     */
    function testPaymasterUserOpERC20ValidSig() public {
        assertEq(testToken.balanceOf(account), 0);
        testToken.mint(account, TESTTOKEN_ACCOUNT_PREFUND);
        assertEq(testToken.balanceOf(account), TESTTOKEN_ACCOUNT_PREFUND);

        bytes memory dataEncoded = mockedPaymasterDataERC20Dynamic(paymasterAdmin);

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

        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.DynamicRate;
        strategy.depositor = paymasterAdmin;
        strategy.erc20Token = address(testToken);
        strategy.exchangeRate = EXCHANGERATE;

        // Simulating that the Paymaster gets the userOp and signs it
        bytes32 hash;
        {
            hash = ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
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
            hash2 =
                ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
        }

        // The hash of the userOp should not have changed after the inclusion of the sig
        assertEq(hash, hash2);
        userOps[0].signature = userOpSignature;

        // Get the paymaster deposit before handling the userOp
        uint256 paymasterDepositBefore = openfortPaymaster.getDeposit();

        entryPoint.handleOps(userOps, beneficiary);

        // Verify that the paymaster has less deposit now
        assert(paymasterDepositBefore > openfortPaymaster.getDeposit());
        // Verifiy that the balance of the smart account has decreased
        assert(testToken.balanceOf(account) < TESTTOKEN_ACCOUNT_PREFUND);
    }

    /*
     * Test sending a userOp with an valid paymasterAndData (valid paymaster, valid sig)
     * Using FIXED ERC20. Should work
     */
    function testPaymasterUserOpERC20FixedValidSig() public {
        assertEq(testToken.balanceOf(account), 0);
        testToken.mint(account, TESTTOKEN_ACCOUNT_PREFUND);
        assertEq(testToken.balanceOf(account), TESTTOKEN_ACCOUNT_PREFUND);
        uint256 pricePerTransaction = 10 ** 18;

        bytes memory dataEncoded = mockedPaymasterDataERC20Fixed(paymasterAdmin, pricePerTransaction);

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

        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.FixedRate;
        strategy.depositor = paymasterAdmin;
        strategy.erc20Token = address(testToken);
        strategy.exchangeRate = pricePerTransaction;

        // Simulating that the Paymaster gets the userOp and signs it
        bytes32 hash;
        {
            hash = ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
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
            hash2 =
                ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
        }

        // The hash of the userOp should not have changed after the inclusion of the sig
        assertEq(hash, hash2);
        userOps[0].signature = userOpSignature;

        // Get the paymaster deposit before handling the userOp
        uint256 paymasterDepositBefore = openfortPaymaster.getDeposit();

        entryPoint.handleOps(userOps, beneficiary);

        // Verify that the paymaster has less deposit now
        assert(paymasterDepositBefore > openfortPaymaster.getDeposit());
        // Verifiy that the balance of the smart account has decreased
        assert(testToken.balanceOf(account) == TESTTOKEN_ACCOUNT_PREFUND - pricePerTransaction);
    }

    /*
     * Test sending a userOp with an valid paymasterAndData (valid paymaster, valid sig)
     * ExecBatch. Using dynamic ERC20. Should work
     */
    function testPaymasterUserOpERC20ValidSigExecBatch() public {
        assertEq(testToken.balanceOf(account), 0);
        testToken.mint(account, TESTTOKEN_ACCOUNT_PREFUND);
        assertEq(testToken.balanceOf(account), TESTTOKEN_ACCOUNT_PREFUND);

        assertEq(testCounter.counters(account), 0);

        bytes memory dataEncoded = mockedPaymasterDataERC20Dynamic(paymasterAdmin);

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG);

        uint256 count = 2;
        address[] memory targets = new address[](count);
        uint256[] memory values = new uint256[](count);
        bytes[] memory callData = new bytes[](count);

        targets[0] = address(testToken);
        values[0] = 0;
        callData[0] = abi.encodeWithSignature("approve(address,uint256)", address(openfortPaymaster), 2 ** 256 - 1);

        targets[1] = address(testCounter);
        values[1] = 0;
        callData[1] = abi.encodeWithSignature("count()");

        // Create a userOp to let the paymaster use our testTokens
        UserOperation[] memory userOps =
            _setupUserOpExecuteBatch(account, accountAdminPKey, bytes(""), targets, values, callData, paymasterAndData);

        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.DynamicRate;
        strategy.depositor = paymasterAdmin;
        strategy.erc20Token = address(testToken);
        strategy.exchangeRate = EXCHANGERATE;

        // Simulating that the Paymaster gets the userOp and signs it
        bytes32 hash;
        {
            hash = ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
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
            hash2 =
                ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
        }

        // The hash of the userOp should not have changed after the inclusion of the sig
        assertEq(hash, hash2);
        userOps[0].signature = userOpSignature;

        // Get the paymaster deposit before handling the userOp
        uint256 paymasterDepositBefore = openfortPaymaster.getDeposit();

        entryPoint.handleOps(userOps, beneficiary);

        // Verify that the paymaster has less deposit now
        assert(paymasterDepositBefore > openfortPaymaster.getDeposit());
        // Verifiy that the balance of the smart account has decreased
        assert(testToken.balanceOf(account) < TESTTOKEN_ACCOUNT_PREFUND);
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Test sending a userOp with an valid paymasterAndData (valid paymaster, valid sig)
     * ExecBatch. Using fixed ERC20. Should work
     */
    function testPaymasterUserOpERC20FixedValidSigExecBatch() public {
        assertEq(testToken.balanceOf(account), 0);
        testToken.mint(account, TESTTOKEN_ACCOUNT_PREFUND);
        assertEq(testToken.balanceOf(account), TESTTOKEN_ACCOUNT_PREFUND);

        assertEq(testCounter.counters(account), 0);

        uint256 pricePerTransaction = 10 ** 18;

        bytes memory dataEncoded = mockedPaymasterDataERC20Fixed(paymasterAdmin, pricePerTransaction);

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG);

        uint256 count = 2;
        address[] memory targets = new address[](count);
        uint256[] memory values = new uint256[](count);
        bytes[] memory callData = new bytes[](count);

        targets[0] = address(testToken);
        values[0] = 0;
        callData[0] = abi.encodeWithSignature("approve(address,uint256)", address(openfortPaymaster), 2 ** 256 - 1);

        targets[1] = address(testCounter);
        values[1] = 0;
        callData[1] = abi.encodeWithSignature("count()");

        // Create a userOp to let the paymaster use our testTokens
        UserOperation[] memory userOps =
            _setupUserOpExecuteBatch(account, accountAdminPKey, bytes(""), targets, values, callData, paymasterAndData);

        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.FixedRate;
        strategy.depositor = paymasterAdmin;
        strategy.erc20Token = address(testToken);
        strategy.exchangeRate = pricePerTransaction;

        // Simulating that the Paymaster gets the userOp and signs it
        bytes32 hash;
        {
            hash = ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
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
            hash2 =
                ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
        }

        // The hash of the userOp should not have changed after the inclusion of the sig
        assertEq(hash, hash2);
        userOps[0].signature = userOpSignature;

        // Get the paymaster deposit before handling the userOp
        uint256 paymasterDepositBefore = openfortPaymaster.getDeposit();

        entryPoint.handleOps(userOps, beneficiary);

        // Verify that the paymaster has less deposit now
        assert(paymasterDepositBefore > openfortPaymaster.getDeposit());
        // Verifiy that the balance of the smart account has decreased
        assert(testToken.balanceOf(account) == TESTTOKEN_ACCOUNT_PREFUND - pricePerTransaction);
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Test sending a userOp with an valid paymasterAndData (valid paymaster, valid sig)
     * ExecBatch. Using fixed ERC20 expensive. Should work
     */
    function testPaymasterUserOpERC20FixedExpensiveValidSigExecBatch() public {
        assertEq(testToken.balanceOf(account), 0);
        testToken.mint(account, TESTTOKEN_ACCOUNT_PREFUND);
        assertEq(testToken.balanceOf(account), TESTTOKEN_ACCOUNT_PREFUND);

        assertEq(testCounter.counters(account), 0);

        uint256 pricePerTransaction = 10;

        bytes memory dataEncoded = mockedPaymasterDataERC20Fixed(paymasterAdmin, pricePerTransaction);

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG);

        uint256 count = 2;
        address[] memory targets = new address[](count);
        uint256[] memory values = new uint256[](count);
        bytes[] memory callData = new bytes[](count);

        targets[0] = address(testToken);
        values[0] = 0;
        callData[0] = abi.encodeWithSignature("approve(address,uint256)", address(openfortPaymaster), 2 ** 256 - 1);

        targets[1] = address(testCounter);
        values[1] = 0;
        callData[1] = abi.encodeWithSignature("count()");

        // Create a userOp to let the paymaster use our testTokens
        UserOperation[] memory userOps =
            _setupUserOpExecuteBatch(account, accountAdminPKey, bytes(""), targets, values, callData, paymasterAndData);

        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.FixedRate;
        strategy.depositor = paymasterAdmin;
        strategy.erc20Token = address(testToken);
        strategy.exchangeRate = pricePerTransaction;

        // Simulating that the Paymaster gets the userOp and signs it
        bytes32 hash;
        {
            hash = ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
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
            hash2 =
                ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
        }

        // The hash of the userOp should not have changed after the inclusion of the sig
        assertEq(hash, hash2);
        userOps[0].signature = userOpSignature;

        // Get the paymaster deposit before handling the userOp
        uint256 paymasterDepositBefore = openfortPaymaster.getDeposit();

        entryPoint.handleOps(userOps, beneficiary);

        // Verify that the paymaster has less deposit now
        assert(paymasterDepositBefore > openfortPaymaster.getDeposit());
        // Verifiy that the balance of the smart account has decreased
        assert(testToken.balanceOf(account) == TESTTOKEN_ACCOUNT_PREFUND - pricePerTransaction);
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Test sending a userOp with an valid paymasterAndData (valid paymaster, valid sig)
     * ExecBatch. Should work
     */
    function testPaymasterUserOpNativeValidSigExecBatch() public {
        bytes memory dataEncoded = mockedPaymasterDataNative(paymasterAdmin);

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG);

        uint256 count = 2;
        address[] memory targets = new address[](count);
        uint256[] memory values = new uint256[](count);
        bytes[] memory callData = new bytes[](count);

        targets[0] = address(testToken);
        values[0] = 0;
        callData[0] = abi.encodeWithSignature("approve(address,uint256)", address(openfortPaymaster), 2 ** 256 - 1);

        targets[1] = address(testCounter);
        values[1] = 0;
        callData[1] = abi.encodeWithSignature("count()");

        // Create a userOp to let the paymaster use our testTokens
        UserOperation[] memory userOps =
            _setupUserOpExecuteBatch(account, accountAdminPKey, bytes(""), targets, values, callData, paymasterAndData);

        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.PayForUser;
        strategy.depositor = paymasterAdmin;
        strategy.erc20Token = address(0);
        strategy.exchangeRate = 0;

        bytes32 hash;
        {
            // Simulating that the Paymaster gets the userOp and signs it
            hash = ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
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
            hash2 =
                ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
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
     * ExecBatch. Using ERC20. Should work.
     * Test showing that failing to repay in ERC20 still spends some of Paymaster's deposit (DoS)
     */
    function testFailPaymasterUserOpERC20ValidSigExecBatchInsufficientERC20() public {
        assertEq(testToken.balanceOf(account), 0);
        testToken.mint(account, 100);
        assertEq(testToken.balanceOf(account), 100);

        assertEq(testCounter.counters(account), 0);

        bytes memory dataEncoded = mockedPaymasterDataERC20Dynamic(paymasterAdmin);

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG);

        uint256 count = 2;
        address[] memory targets = new address[](count);
        uint256[] memory values = new uint256[](count);
        bytes[] memory callData = new bytes[](count);

        targets[0] = address(testToken);
        values[0] = 0;
        callData[0] = abi.encodeWithSignature("approve(address,uint256)", address(openfortPaymaster), 2 ** 256 - 1);

        targets[1] = address(testCounter);
        values[1] = 0;
        callData[1] = abi.encodeWithSignature("count()");

        // Create a userOp to let the paymaster use our testTokens
        UserOperation[] memory userOps =
            _setupUserOpExecuteBatch(account, accountAdminPKey, bytes(""), targets, values, callData, paymasterAndData);

        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.DynamicRate;
        strategy.depositor = paymasterAdmin;
        strategy.erc20Token = address(testToken);
        strategy.exchangeRate = EXCHANGERATE;

        // Simulating that the Paymaster gets the userOp and signs it
        bytes32 hash;
        {
            hash = ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
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
            hash2 =
                ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
        }

        // The hash of the userOp should not have changed after the inclusion of the sig
        assertEq(hash, hash2);
        userOps[0].signature = userOpSignature;

        // Get the paymaster deposit before handling the userOp
        uint256 paymasterDepositBefore = openfortPaymaster.getDeposit();

        entryPoint.handleOps(userOps, beneficiary);

        // Verify that the paymaster has the same deposit
        assert(paymasterDepositBefore == openfortPaymaster.getDeposit());
        // Verify that the balance of the smart account has not decreased
        assertEq(testToken.balanceOf(account), 100);
        // Verify that the counter has not increased
        assertEq(testCounter.counters(account), 0);

        // If this fails, it would mean:
        // 1- That the paymaster has spent some of its deposit
        // 2- That the smart account could not perform the desired actions, but still has all testTokens
        // An attacker could DoS the paymaster to drain its deposit
    }

    /*
     * Test sending a userOp with an valid paymasterAndData (valid paymaster, valid sig)
     * Using ERC20. Should work.
     */
    function testFailPaymasterUserOpERC20ValidSigSmallApprove() public {
        assertEq(testToken.balanceOf(account), 0);
        testToken.mint(account, TESTTOKEN_ACCOUNT_PREFUND);
        assertEq(testToken.balanceOf(account), TESTTOKEN_ACCOUNT_PREFUND);

        bytes memory dataEncoded = mockedPaymasterDataERC20Dynamic(paymasterAdmin);

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG);

        // Create a userOp to let the paymaster use our testTokens
        UserOperation[] memory userOps = _setupUserOpExecute(
            account,
            accountAdminPKey,
            bytes(""),
            address(testToken),
            0,
            abi.encodeWithSignature("approve(address,uint256)", address(openfortPaymaster), 1),
            paymasterAndData
        );

        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.DynamicRate;
        strategy.depositor = paymasterAdmin;
        strategy.erc20Token = address(testToken);
        strategy.exchangeRate = EXCHANGERATE;

        // Simulating that the Paymaster gets the userOp and signs it
        bytes32 hash;
        {
            hash = ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
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
            hash2 =
                ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
        }

        // The hash of the userOp should not have changed after the inclusion of the sig
        assertEq(hash, hash2);
        userOps[0].signature = userOpSignature;

        // Get the paymaster deposit before handling the userOp
        uint256 paymasterDepositBefore = openfortPaymaster.getDeposit();

        entryPoint.handleOps(userOps, beneficiary);

        // Verify that the paymaster has the same deposit
        assert(paymasterDepositBefore == openfortPaymaster.getDeposit());
        // Verify that the balance of the smart account has not decreased
        assertEq(testToken.balanceOf(account), TESTTOKEN_ACCOUNT_PREFUND);
        // Verify that the counter has not increased
        assertEq(testCounter.counters(account), 0);

        // If this fails, it would mean:
        // 1- That the paymaster has spent some of its deposit
        // 2- That the smart account could not perform the desired actions, but still has all testTokens
        // An attacker could DoS the paymaster to drain its deposit
    }

    /*
     * Test sending a userOp with a valid paymasterAndData (valid paymaster, valid sig)
     * Using ERC20 and a 3rd party depositor. Should work
     */
    function testPaymasterUserOpERC20ValidSigDepositor() public {
        assertEq(testToken.balanceOf(account), 0);
        testToken.mint(account, TESTTOKEN_ACCOUNT_PREFUND);
        assertEq(testToken.balanceOf(account), TESTTOKEN_ACCOUNT_PREFUND);

        vm.prank(factoryAdmin);
        openfortPaymaster.depositFor{value: 50 ether}(factoryAdmin);
        assertEq(openfortPaymaster.getDeposit(), 100 ether);
        assertEq(openfortPaymaster.getDepositFor(factoryAdmin), 50 ether);
        assertEq(openfortPaymaster.getDepositFor(paymasterAdmin), 50 ether);

        bytes memory dataEncoded = mockedPaymasterDataERC20Dynamic(factoryAdmin);

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

        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.DynamicRate;
        strategy.depositor = factoryAdmin;
        strategy.erc20Token = address(testToken);
        strategy.exchangeRate = EXCHANGERATE;

        // Simulating that the Paymaster gets the userOp and signs it
        bytes32 hash;
        {
            hash = ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
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
            hash2 =
                ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
        }

        // The hash of the userOp should not have changed after the inclusion of the sig
        assertEq(hash, hash2);
        userOps[0].signature = userOpSignature;

        // Get the paymaster deposit before handling the userOp
        uint256 paymasterDepositBefore = openfortPaymaster.getDeposit();

        entryPoint.handleOps(userOps, beneficiary);

        // Verify that the paymaster has less deposit now
        assert(paymasterDepositBefore > openfortPaymaster.getDeposit());
        // Verifiy that the balance of the smart account has decreased
        assert(testToken.balanceOf(account) < TESTTOKEN_ACCOUNT_PREFUND);

        assert(openfortPaymaster.getDeposit() < 100 ether);
        assert(openfortPaymaster.getDepositFor(factoryAdmin) < 50 ether);
        assert(openfortPaymaster.getDepositFor(paymasterAdmin) > 50 ether); // deposit of the owner should have increased a bit because of the dust
    }

    /*
     * Test sending a userOp with a valid paymasterAndData (valid paymaster, valid sig)
     * Using ERC20 (fixed rate) and a 3rd party depositor. Should work
     */
    function testPaymasterUserOpERC20FixedValidSigDepositor() public {
        assertEq(testToken.balanceOf(account), 0);
        testToken.mint(account, TESTTOKEN_ACCOUNT_PREFUND);
        assertEq(testToken.balanceOf(account), TESTTOKEN_ACCOUNT_PREFUND);

        vm.prank(factoryAdmin);
        openfortPaymaster.depositFor{value: 50 ether}(factoryAdmin);
        assertEq(openfortPaymaster.getDeposit(), 100 ether);
        assertEq(openfortPaymaster.getDepositFor(factoryAdmin), 50 ether);
        assertEq(openfortPaymaster.getDepositFor(paymasterAdmin), 50 ether);

        uint256 pricePerTransaction = 10 ** 18;

        bytes memory dataEncoded = mockedPaymasterDataERC20Fixed(factoryAdmin, pricePerTransaction);

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

        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.FixedRate;
        strategy.depositor = factoryAdmin;
        strategy.erc20Token = address(testToken);
        strategy.exchangeRate = pricePerTransaction;

        // Simulating that the Paymaster gets the userOp and signs it
        bytes32 hash;
        {
            hash = ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
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
            hash2 =
                ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
        }

        // The hash of the userOp should not have changed after the inclusion of the sig
        assertEq(hash, hash2);
        userOps[0].signature = userOpSignature;

        // Get the paymaster deposit before handling the userOp
        uint256 paymasterDepositBefore = openfortPaymaster.getDeposit();

        entryPoint.handleOps(userOps, beneficiary);

        // Verify that the paymaster has less deposit now
        assert(paymasterDepositBefore > openfortPaymaster.getDeposit());
        // Verifiy that the balance of the smart account has decreased
        assert(testToken.balanceOf(account) < TESTTOKEN_ACCOUNT_PREFUND);

        assert(openfortPaymaster.getDeposit() < 100 ether);
        assert(openfortPaymaster.getDepositFor(factoryAdmin) < 50 ether);
        assert(openfortPaymaster.getDepositFor(paymasterAdmin) > 50 ether); // deposit of the owner should have increased a bit because of the dust
    }

    /*
     * Test setPostOpGas function
     */
    function testSetPostOpGas() public {
        vm.expectRevert("Ownable: caller is not the owner");
        openfortPaymaster.setPostOpGas(15_000);

        vm.prank(paymasterAdmin);
        vm.expectRevert();
        openfortPaymaster.setPostOpGas(0);

        // Expect that we will see a PostOpGasUpdated event
        vm.prank(paymasterAdmin);
        vm.expectEmit(true, true, false, false);
        emit PostOpGasUpdated(40_000, 15_000);
        openfortPaymaster.setPostOpGas(15_000);
    }

    /*
     * Trigger _requireFromEntryPoint() from BaseOpenfortPaymaster
     */
    function test_requireFromEntryPoint() public {
        UserOperation[] memory userOpAux = _setupUserOpExecute(
            account, accountAdminPKey, bytes(""), address(testCounter), 0, abi.encodeWithSignature("count()"), ""
        );

        vm.prank(paymasterAdmin);
        vm.expectRevert("Sender not EntryPoint");
        openfortPaymaster.validatePaymasterUserOp(userOpAux[0], bytes32(""), 0);

        vm.prank(paymasterAdmin);
        vm.expectRevert("Sender not EntryPoint");
        openfortPaymaster.postOp(IPaymaster.PostOpMode(0), bytes(""), 0);
    }

    /*
     * Test basic transfer ownership
     */
    function testAcceptOwnershipBasic() public {
        assertEq(openfortPaymaster.owner(), paymasterAdmin);

        vm.expectRevert("Ownable: caller is not the owner");
        openfortPaymaster.transferOwnership(factoryAdmin);

        vm.prank(paymasterAdmin);
        openfortPaymaster.transferOwnership(factoryAdmin);

        vm.expectRevert("Ownable2Step: caller is not the new owner");
        openfortPaymaster.acceptOwnership();

        vm.prank(factoryAdmin);
        openfortPaymaster.acceptOwnership();
        assertEq(openfortPaymaster.owner(), factoryAdmin);
    }

    /*
     * ToDo Test complex transfer ownership
     */
    function testAcceptOwnershipComplex() public {
        assertEq(openfortPaymaster.owner(), paymasterAdmin);

        // Play around with deposits
        assertEq(openfortPaymaster.getDeposit(), 50 ether);
        assertEq(openfortPaymaster.getDepositFor(paymasterAdmin), 50 ether);
        assertEq(openfortPaymaster.getDepositFor(factoryAdmin), 0 ether);

        openfortPaymaster.depositFor{value: 3 ether}(factoryAdmin);

        assertEq(openfortPaymaster.getDeposit(), 53 ether);
        assertEq(openfortPaymaster.getDepositFor(paymasterAdmin), 50 ether);
        assertEq(openfortPaymaster.getDepositFor(factoryAdmin), 3 ether);

        vm.prank(paymasterAdmin);
        openfortPaymaster.transferOwnership(factoryAdmin);

        assertEq(openfortPaymaster.getDeposit(), 53 ether);
        assertEq(openfortPaymaster.getDepositFor(paymasterAdmin), 50 ether);
        assertEq(openfortPaymaster.getDepositFor(factoryAdmin), 3 ether);
        // Play around with deposits

        vm.prank(factoryAdmin);
        openfortPaymaster.acceptOwnership();
        assertEq(openfortPaymaster.owner(), factoryAdmin);

        // After transferring the ownership, the old owner does not have any deposit
        // and the new one has all deposit from previous owner PLUS its old deposit

        assertEq(openfortPaymaster.getDeposit(), 53 ether);
        assertEq(openfortPaymaster.getDepositFor(paymasterAdmin), 0 ether);
        assertEq(openfortPaymaster.getDepositFor(factoryAdmin), 53 ether);
    }

    /*
     * Test using a new depositor (factoryAdmin)
     * Should work
     */
    function testPaymasterUserOpNativeValidSigDEPOSITOR() public {
        bytes memory dataEncoded = mockedPaymasterDataNative(factoryAdmin);

        assertEq(openfortPaymaster.getDeposit(), 50 ether);
        assertEq(openfortPaymaster.getDepositFor(paymasterAdmin), 50 ether);
        assertEq(openfortPaymaster.getDepositFor(factoryAdmin), 0 ether);

        openfortPaymaster.depositFor{value: 3 ether}(factoryAdmin);

        assertEq(openfortPaymaster.getDeposit(), 53 ether);
        assertEq(openfortPaymaster.getDepositFor(paymasterAdmin), 50 ether);
        assertEq(openfortPaymaster.getDepositFor(factoryAdmin), 3 ether);

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG);
        console.log("paymasterAndData");
        console.log("paymasterAndData");
        console.logBytes(paymasterAndData);

        UserOperation[] memory userOps = _setupUserOpExecute(
            account,
            accountAdminPKey,
            bytes(""),
            address(testCounter),
            0,
            abi.encodeWithSignature("count()"),
            paymasterAndData
        );
        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.PayForUser;
        strategy.depositor = factoryAdmin;
        strategy.erc20Token = address(0);
        strategy.exchangeRate = 0;
        bytes32 hash;
        {
            // Simulating that the Paymaster gets the userOp and signs it
            hash = ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
            bytes memory signature = abi.encodePacked(r, s, v);
            bytes memory paymasterAndDataSigned = abi.encodePacked(address(openfortPaymaster), dataEncoded, signature); // This part was packed (not filled with 0s)
            assertEq(openfortPaymaster.owner(), ECDSA.recover(hash, signature));
            userOps[0].paymasterAndData = paymasterAndDataSigned;
        }

        console.log("userOps[0].paymasterAndData");
        console.log("userOps[0].paymasterAndData");
        console.logBytes(userOps[0].paymasterAndData);

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
            hash2 =
                ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
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

        assert(openfortPaymaster.getDeposit() < 53 ether); // less than 53 because the total cost have decreased
        assert(openfortPaymaster.getDepositFor(paymasterAdmin) > 50 ether); // more than 50 because the dust has gone to the owner deposit
        assert(openfortPaymaster.getDepositFor(factoryAdmin) < 3 ether); // less than 3 because the gas cost was paid using factoryAdmin's deposit
    }
}
