// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {console} from "lib/forge-std/src/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint, UserOperation, IEntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";
import {IPaymaster} from "account-abstraction/interfaces/IPaymaster.sol";
import {MockERC20} from "contracts/mock/MockERC20.sol";
import {UpgradeableOpenfortFactory} from "contracts/core/upgradeable/UpgradeableOpenfortFactory.sol";
import {UpgradeableOpenfortAccount} from "contracts/core/upgradeable/UpgradeableOpenfortAccount.sol";
import {OpenfortPaymasterV2} from "contracts/paymaster/OpenfortPaymasterV2.sol";
import {OpenfortBaseTest} from "../core/OpenfortBaseTest.t.sol";
import {OpenfortErrorsAndEvents} from "contracts/interfaces/OpenfortErrorsAndEvents.sol";
import {UpgradeableOpenfortDeploy} from "script/deployUpgradeableAccounts.s.sol";

contract OpenfortPaymasterV2Test is OpenfortBaseTest {
    using ECDSA for bytes32;

    OpenfortPaymasterV2 public openfortPaymaster;

    address private paymasterAdmin;
    uint256 private paymasterAdminPKey;

    UpgradeableOpenfortAccount public upgradeableOpenfortAccountImpl;
    UpgradeableOpenfortFactory public openfortFactory;

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
        bytes32 opHash = entryPoint.getUserOpHash(op);
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

    function mockPaymasterDataNative(address _depositor) internal pure returns (bytes memory dataEncoded) {
        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.PayForUser;
        strategy.depositor = _depositor;
        strategy.erc20Token = address(0);
        strategy.exchangeRate = 0;
        // Looking at the source code, I've found this part was not Packed (filled with 0s)
        dataEncoded = abi.encode(VALIDUNTIL, VALIDAFTER, strategy);
    }

    function mockPaymasterDataERC20Dynamic(address _depositor) internal view returns (bytes memory dataEncoded) {
        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.DynamicRate;
        strategy.depositor = _depositor;
        strategy.erc20Token = address(mockERC20);
        strategy.exchangeRate = EXCHANGERATE;
        // Looking at the source code, I've found this part was not Packed (filled with 0s)
        dataEncoded = abi.encode(VALIDUNTIL, VALIDAFTER, strategy);
    }

    function mockPaymasterDataERC20Fixed(address _depositor, uint256 _pricePerTransaction)
        internal
        view
        returns (bytes memory dataEncoded)
    {
        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.FixedRate;
        strategy.depositor = _depositor;
        strategy.erc20Token = address(mockERC20);
        strategy.exchangeRate = _pricePerTransaction;
        // Looking at the source code, I've found this part was not Packed (filled with 0s)
        dataEncoded = abi.encode(VALIDUNTIL, VALIDAFTER, strategy);
    }

    /**
     * @notice Initialize the UpgradeableOpenfortAccount testing contract.
     * Scenario:
     * - openfortAdmin is the deployer (and owner) of the UpgradeableOpenfortFactory
     * - paymasterAdmin is the deployer (and owner) of the OpenfortPaymaster
     * - openfortAdmin is the account used to deploy new static accounts
     * - entryPoint is the singleton EntryPoint
     * - testCounter is the counter used to test userOps
     */
    function setUp() public override {
        super.setUp();
        (paymasterAdmin, paymasterAdminPKey) = makeAddrAndKey("paymasterAdmin");
        vm.deal(paymasterAdmin, 100 ether);

        vm.prank(paymasterAdmin);
        openfortPaymaster =
            new OpenfortPaymasterV2{salt: versionSalt}(IEntryPoint(payable(address(entryPoint))), paymasterAdmin);
        // Paymaster deposits 50 ETH to EntryPoint
        vm.prank(paymasterAdmin);
        openfortPaymaster.deposit{value: 50 ether}();
        // Paymaster stakes 25 ETH
        vm.prank(paymasterAdmin);
        openfortPaymaster.addStake{value: 25 ether}(1);

        // deploy account factory
        UpgradeableOpenfortDeploy upgradeableOpenfortDeploy = new UpgradeableOpenfortDeploy();
        (upgradeableOpenfortAccountImpl, openfortFactory) = upgradeableOpenfortDeploy.run();

        // deploy a new TestCounter
        testCounter = new TestCounter();
        // mint 1000 mockERC20
        mockERC20.mint(address(this), 1_000 * 10 ** 18);

        // Create an Openfort account and get its address
        vm.prank(openfortAdmin);
        accountAddress = openfortFactory.createAccountWithNonce(openfortAdmin, "1", true);
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
        vm.prank(openfortAdmin);
        openfortPaymaster.deposit{value: 50 ether}();
    }

    /*
     * Test parsePaymasterAndData() when using the native token
     *
     */
    function testParsePaymasterDataNative() public {
        // Encode the paymaster data
        bytes memory dataEncoded = mockPaymasterDataNative(paymasterAdmin);

        // Get the related paymaster data signature
        bytes32 hash = keccak256(dataEncoded);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Create the paymasterAndData info
        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, signature);

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
        bytes memory dataEncoded = mockPaymasterDataERC20Dynamic(paymasterAdmin);

        // Get the related paymaster data signature
        bytes32 hash = keccak256(dataEncoded);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Create the paymasterAndData info
        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, signature);
        console.logBytes(paymasterAndData);

        (
            uint48 returnedValidUntil,
            uint48 returnedValidAfter,
            OpenfortPaymasterV2.PolicyStrategy memory strategy,
            bytes memory returnedSignature
        ) = openfortPaymaster.parsePaymasterAndData(paymasterAndData);
        assertEq(returnedValidUntil, VALIDUNTIL);
        assertEq(returnedValidAfter, VALIDAFTER);
        assertEq(strategy.erc20Token, address(mockERC20));
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

        // The owner trying to unlock fails because it has not passed enough time
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
        openfortPaymaster.depositFor{value: 0 ether}(openfortAdmin);

        // Cannot depositFor using owner
        vm.prank(paymasterAdmin);
        vm.expectRevert();
        openfortPaymaster.depositFor{value: 1 ether}(paymasterAdmin);

        assertEq(openfortPaymaster.getDepositFor(openfortAdmin), 0);

        // Paymaster deposits 1 ETH to EntryPoint
        openfortPaymaster.depositFor{value: 1 ether}(openfortAdmin);
        assertEq(openfortPaymaster.getDepositFor(openfortAdmin), 1 ether);

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

        // openfortAdmin can call it
        assertEq(openfortPaymaster.getDepositFor(openfortAdmin), 1 ether);
        assertEq(openfortAdmin.balance, 100 ether);
        // but not too much!
        vm.expectRevert();
        vm.prank(openfortAdmin);
        openfortPaymaster.withdrawDepositorTo(payable(openfortAdmin), 1000 ether);
        // not using address 0!
        vm.expectRevert();
        vm.prank(openfortAdmin);
        openfortPaymaster.withdrawDepositorTo(payable(address(0)), 1 ether);
        vm.prank(openfortAdmin);
        openfortPaymaster.withdrawDepositorTo(payable(openfortAdmin), 1 ether);
        assertEq(openfortPaymaster.getDepositFor(openfortAdmin), 0 ether);
        assertEq(openfortAdmin.balance, 101 ether);
        // Deposit of the owner is still 51
        assertEq(openfortPaymaster.getDepositFor(paymasterAdmin), 51 ether);

        // Finally, let's test withdrawFromDepositor
        // deposit again using openfortAdmin
        openfortPaymaster.depositFor{value: 1 ether}(openfortAdmin);
        assertEq(openfortPaymaster.getDepositFor(openfortAdmin), 1 ether);
        // Only owner cannot call it
        vm.expectRevert("Ownable: caller is not the owner");
        openfortPaymaster.withdrawFromDepositor(openfortAdmin, payable(openfortAdmin), 1 ether);
        assertEq(openfortPaymaster.getDepositFor(openfortAdmin), 1 ether);

        vm.expectRevert();
        vm.prank(paymasterAdmin);
        openfortPaymaster.withdrawFromDepositor(openfortAdmin, payable(openfortAdmin), 100 ether);
        assertEq(openfortPaymaster.getDepositFor(openfortAdmin), 1 ether);

        vm.expectRevert(OpenfortErrorsAndEvents.ZeroValueNotAllowed.selector);
        vm.prank(paymasterAdmin);
        openfortPaymaster.withdrawFromDepositor(address(0), payable(openfortAdmin), 1 ether);
        assertEq(openfortPaymaster.getDepositFor(openfortAdmin), 1 ether);

        vm.prank(paymasterAdmin);
        openfortPaymaster.withdrawFromDepositor(openfortAdmin, payable(openfortAdmin), 1 ether);
        assertEq(openfortPaymaster.getDepositFor(openfortAdmin), 0 ether);
    }

    /*
     * Test sending a userOp with an invalid paymasterAndData (valid paymaster, but invalid sig length)
     * Should revert
     */
    function testPaymasterUserOpWrongSigLength() public {
        bytes memory dataEncoded = mockPaymasterDataERC20Dynamic(paymasterAdmin);

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, "0x1234");

        UserOperation[] memory userOp = _setupUserOpExecute(
            accountAddress,
            openfortAdminPKey,
            bytes(""),
            address(testCounter),
            0,
            abi.encodeWithSignature("count()"),
            paymasterAndData
        );

        // "ECDSA: invalid signature length"
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);

        // Verify that the counter has not increased
        assertEq(testCounter.counters(accountAddress), 0);
    }

    /*
     * Test sending a userOp with an invalid paymasterAndData (valid paymaster, but invalid sig)
     * Should revert
     */
    function testPaymasterUserOpWrongSig() public {
        bytes memory dataEncoded = mockPaymasterDataERC20Dynamic(paymasterAdmin);

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG); // MOCKSIG, "1", MOCKSIG to make sure we send 65 bytes as sig
        UserOperation[] memory userOp = _setupUserOpExecute(
            accountAddress,
            openfortAdminPKey,
            bytes(""),
            address(testCounter),
            0,
            abi.encodeWithSignature("count()"),
            paymasterAndData
        );

        // "AA33 reverted: ECDSA: invalid signature"
        vm.expectRevert();
        entryPoint.simulateValidation(userOp[0]);

        // Verify that the counter has not increased
        assertEq(testCounter.counters(accountAddress), 0);
    }

    /*
     * Test sending a userOp with an valid paymasterAndData (valid paymaster, valid sig)
     * Should work
     */
    function testPaymasterUserOpNativeValidSig() public {
        bytes memory dataEncoded = mockPaymasterDataNative(paymasterAdmin);

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG);

        UserOperation[] memory userOps = _setupUserOpExecute(
            accountAddress,
            openfortAdminPKey,
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
            bytes memory paymasterAndDataSigned = abi.encodePacked(address(openfortPaymaster), dataEncoded, signature);
            assertEq(openfortPaymaster.owner(), ECDSA.recover(hash, signature));
            userOps[0].paymasterAndData = paymasterAndDataSigned;
        }

        // Back to the user. Sign the userOp
        bytes memory userOpSignature;
        bytes32 hash2;
        {
            bytes32 opHash = entryPoint.getUserOpHash(userOps[0]);
            bytes32 msgHash = ECDSA.toEthSignedMessageHash(opHash);

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(openfortAdminPKey, msgHash);
            userOpSignature = abi.encodePacked(r, s, v);

            // Verifications below commented to avoid "Stack too deep" error
            assertEq(ECDSA.recover(msgHash, v, r, s), vm.addr(openfortAdminPKey));

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
        //Verify that the counter has increased
        assertEq(testCounter.counters(accountAddress), 1);
    }

    /*
     * Test sending a userOp with signature from a wrong address
     * Should not work
     */
    function testPaymasterUserOpNativeWrongUserSig() public {
        bytes memory dataEncoded = mockPaymasterDataNative(paymasterAdmin);

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG);

        UserOperation[] memory userOps = _setupUserOpExecute(
            accountAddress,
            openfortAdminPKey,
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
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(openfortAdminPKey, hash);
            bytes memory signature = abi.encodePacked(r, s, v);
            bytes memory paymasterAndDataSigned = abi.encodePacked(address(openfortPaymaster), dataEncoded, signature);
            assertEq(openfortAdmin, ECDSA.recover(hash, signature));
            userOps[0].paymasterAndData = paymasterAndDataSigned;
        }

        // Back to the user. Sign the userOp
        bytes memory userOpSignature;
        bytes32 hash2;
        {
            bytes32 opHash = entryPoint.getUserOpHash(userOps[0]);
            bytes32 msgHash = ECDSA.toEthSignedMessageHash(opHash);

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(openfortAdminPKey, msgHash);
            userOpSignature = abi.encodePacked(r, s, v);

            // Verifications below commented to avoid "Stack too deep" error
            assertEq(ECDSA.recover(msgHash, v, r, s), vm.addr(openfortAdminPKey));

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
        //Verify that the counter has not increased
        assertEq(testCounter.counters(accountAddress), 0);
    }

    /*
     * Test sending a userOp with an valid paymasterAndData (valid paymaster, valid sig)
     * Using ERC20. Should work
     */
    function testPaymasterUserOpERC20ValidSigDiffMaxPriorityFeePerGas() public {
        assertEq(mockERC20.balanceOf(accountAddress), 0);
        mockERC20.mint(accountAddress, TESTTOKEN_ACCOUNT_PREFUND);
        assertEq(mockERC20.balanceOf(accountAddress), TESTTOKEN_ACCOUNT_PREFUND);

        bytes memory dataEncoded = mockPaymasterDataERC20Dynamic(paymasterAdmin);

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG);

        // Create a userOp to let the paymaster use our mockERC20s
        UserOperation[] memory userOps = _setupUserOpExecute(
            accountAddress,
            openfortAdminPKey,
            bytes(""),
            address(mockERC20),
            0,
            abi.encodeWithSignature("approve(address,uint256)", address(openfortPaymaster), 2 ** 256 - 1),
            paymasterAndData
        );

        userOps[0].maxPriorityFeePerGas += 1;
        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.DynamicRate;
        strategy.depositor = paymasterAdmin;
        strategy.erc20Token = address(mockERC20);
        strategy.exchangeRate = EXCHANGERATE;

        // Simulating that the Paymaster gets the userOp and signs it
        bytes32 hash;
        {
            hash = ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
            bytes memory signature = abi.encodePacked(r, s, v);
            bytes memory paymasterAndDataSigned = abi.encodePacked(address(openfortPaymaster), dataEncoded, signature);
            assertEq(openfortPaymaster.owner(), ECDSA.recover(hash, signature));
            userOps[0].paymasterAndData = paymasterAndDataSigned;
        }

        // Back to the user. Sign the userOp
        bytes memory userOpSignature;
        bytes32 hash2;
        {
            bytes32 opHash = entryPoint.getUserOpHash(userOps[0]);
            bytes32 msgHash = ECDSA.toEthSignedMessageHash(opHash);

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(openfortAdminPKey, msgHash);
            userOpSignature = abi.encodePacked(r, s, v);

            // Verifications below commented to avoid "Stack too deep" error
            assertEq(ECDSA.recover(msgHash, v, r, s), vm.addr(openfortAdminPKey));
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
        // Verify that the balance of the smart account has decreased
        assert(mockERC20.balanceOf(accountAddress) < TESTTOKEN_ACCOUNT_PREFUND);
    }

    /*
     * Test sending a userOp with a valid paymasterAndData (valid paymaster, valid sig)
     * Using ERC20. Should work
     */
    function testPaymasterUserOpERC20ValidSig() public {
        assertEq(mockERC20.balanceOf(accountAddress), 0);
        mockERC20.mint(accountAddress, TESTTOKEN_ACCOUNT_PREFUND);
        assertEq(mockERC20.balanceOf(accountAddress), TESTTOKEN_ACCOUNT_PREFUND);

        bytes memory dataEncoded = mockPaymasterDataERC20Dynamic(paymasterAdmin);

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG);

        // Create a userOp to let the paymaster use our mockERC20s
        UserOperation[] memory userOps = _setupUserOpExecute(
            accountAddress,
            openfortAdminPKey,
            bytes(""),
            address(mockERC20),
            0,
            abi.encodeWithSignature("approve(address,uint256)", address(openfortPaymaster), 2 ** 256 - 1),
            paymasterAndData
        );

        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.DynamicRate;
        strategy.depositor = paymasterAdmin;
        strategy.erc20Token = address(mockERC20);
        strategy.exchangeRate = EXCHANGERATE;

        // Simulating that the Paymaster gets the userOp and signs it
        bytes32 hash;
        {
            hash = ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
            bytes memory signature = abi.encodePacked(r, s, v);
            bytes memory paymasterAndDataSigned = abi.encodePacked(address(openfortPaymaster), dataEncoded, signature);
            assertEq(openfortPaymaster.owner(), ECDSA.recover(hash, signature));
            userOps[0].paymasterAndData = paymasterAndDataSigned;
        }

        // Back to the user. Sign the userOp
        bytes memory userOpSignature;
        bytes32 hash2;
        {
            bytes32 opHash = entryPoint.getUserOpHash(userOps[0]);
            bytes32 msgHash = ECDSA.toEthSignedMessageHash(opHash);

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(openfortAdminPKey, msgHash);
            userOpSignature = abi.encodePacked(r, s, v);

            // Verifications below commented to avoid "Stack too deep" error
            assertEq(ECDSA.recover(msgHash, v, r, s), vm.addr(openfortAdminPKey));
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
        // Verify that the balance of the smart account has decreased
        assert(mockERC20.balanceOf(accountAddress) < TESTTOKEN_ACCOUNT_PREFUND);
    }

    /*
     * Test sending a userOp with an valid paymasterAndData (valid paymaster, valid sig)
     * Using FIXED ERC20. Should work
     */
    function testPaymasterUserOpERC20FixedValidSig() public {
        assertEq(mockERC20.balanceOf(accountAddress), 0);
        mockERC20.mint(accountAddress, TESTTOKEN_ACCOUNT_PREFUND);
        assertEq(mockERC20.balanceOf(accountAddress), TESTTOKEN_ACCOUNT_PREFUND);
        uint256 pricePerTransaction = 10 ** 18;

        bytes memory dataEncoded = mockPaymasterDataERC20Fixed(paymasterAdmin, pricePerTransaction);

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG);

        // Create a userOp to let the paymaster use our mockERC20s
        UserOperation[] memory userOps = _setupUserOpExecute(
            accountAddress,
            openfortAdminPKey,
            bytes(""),
            address(mockERC20),
            0,
            abi.encodeWithSignature("approve(address,uint256)", address(openfortPaymaster), 2 ** 256 - 1),
            paymasterAndData
        );

        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.FixedRate;
        strategy.depositor = paymasterAdmin;
        strategy.erc20Token = address(mockERC20);
        strategy.exchangeRate = pricePerTransaction;

        // Simulating that the Paymaster gets the userOp and signs it
        bytes32 hash;
        {
            hash = ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
            bytes memory signature = abi.encodePacked(r, s, v);
            bytes memory paymasterAndDataSigned = abi.encodePacked(address(openfortPaymaster), dataEncoded, signature);
            assertEq(openfortPaymaster.owner(), ECDSA.recover(hash, signature));
            userOps[0].paymasterAndData = paymasterAndDataSigned;
        }

        // Back to the user. Sign the userOp
        bytes memory userOpSignature;
        bytes32 hash2;
        {
            bytes32 opHash = entryPoint.getUserOpHash(userOps[0]);
            bytes32 msgHash = ECDSA.toEthSignedMessageHash(opHash);

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(openfortAdminPKey, msgHash);
            userOpSignature = abi.encodePacked(r, s, v);

            // Verifications below commented to avoid "Stack too deep" error
            assertEq(ECDSA.recover(msgHash, v, r, s), vm.addr(openfortAdminPKey));
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
        // Verify that the balance of the smart account has decreased
        assert(mockERC20.balanceOf(accountAddress) == TESTTOKEN_ACCOUNT_PREFUND - pricePerTransaction);
    }

    /*
     * Test sending a userOp with an valid paymasterAndData (valid paymaster, valid sig)
     * ExecBatch. Using dynamic ERC20. Should work
     */
    function testPaymasterUserOpERC20ValidSigExecBatch() public {
        assertEq(mockERC20.balanceOf(accountAddress), 0);
        mockERC20.mint(accountAddress, TESTTOKEN_ACCOUNT_PREFUND);
        assertEq(mockERC20.balanceOf(accountAddress), TESTTOKEN_ACCOUNT_PREFUND);

        assertEq(testCounter.counters(accountAddress), 0);

        bytes memory dataEncoded = mockPaymasterDataERC20Dynamic(paymasterAdmin);

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG);

        uint256 count = 2;
        address[] memory targets = new address[](count);
        uint256[] memory values = new uint256[](count);
        bytes[] memory callData = new bytes[](count);

        targets[0] = address(mockERC20);
        values[0] = 0;
        callData[0] = abi.encodeWithSignature("approve(address,uint256)", address(openfortPaymaster), 2 ** 256 - 1);

        targets[1] = address(testCounter);
        values[1] = 0;
        callData[1] = abi.encodeWithSignature("count()");

        // Create a userOp to let the paymaster use our mockERC20s
        UserOperation[] memory userOps = _setupUserOpExecuteBatch(
            accountAddress, openfortAdminPKey, bytes(""), targets, values, callData, paymasterAndData
        );

        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.DynamicRate;
        strategy.depositor = paymasterAdmin;
        strategy.erc20Token = address(mockERC20);
        strategy.exchangeRate = EXCHANGERATE;

        // Simulating that the Paymaster gets the userOp and signs it
        bytes32 hash;
        {
            hash = ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
            bytes memory signature = abi.encodePacked(r, s, v);
            bytes memory paymasterAndDataSigned = abi.encodePacked(address(openfortPaymaster), dataEncoded, signature);
            assertEq(openfortPaymaster.owner(), ECDSA.recover(hash, signature));
            userOps[0].paymasterAndData = paymasterAndDataSigned;
        }

        // Back to the user. Sign the userOp
        bytes memory userOpSignature;
        bytes32 hash2;
        {
            bytes32 opHash = entryPoint.getUserOpHash(userOps[0]);
            bytes32 msgHash = ECDSA.toEthSignedMessageHash(opHash);

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(openfortAdminPKey, msgHash);
            userOpSignature = abi.encodePacked(r, s, v);

            // Verifications below commented to avoid "Stack too deep" error
            assertEq(ECDSA.recover(msgHash, v, r, s), vm.addr(openfortAdminPKey));
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
        // Verify that the balance of the smart account has decreased
        assert(mockERC20.balanceOf(accountAddress) < TESTTOKEN_ACCOUNT_PREFUND);
        assertEq(testCounter.counters(accountAddress), 1);
    }

    /*
     * Test sending a userOp with an valid paymasterAndData (valid paymaster, valid sig)
     * ExecBatch. Using fixed ERC20. Should work
     */
    function testPaymasterUserOpERC20FixedValidSigExecBatch() public {
        assertEq(mockERC20.balanceOf(accountAddress), 0);
        mockERC20.mint(accountAddress, TESTTOKEN_ACCOUNT_PREFUND);
        assertEq(mockERC20.balanceOf(accountAddress), TESTTOKEN_ACCOUNT_PREFUND);

        assertEq(testCounter.counters(accountAddress), 0);

        uint256 pricePerTransaction = 10 ** 18;

        bytes memory dataEncoded = mockPaymasterDataERC20Fixed(paymasterAdmin, pricePerTransaction);

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG);

        uint256 count = 2;
        address[] memory targets = new address[](count);
        uint256[] memory values = new uint256[](count);
        bytes[] memory callData = new bytes[](count);

        targets[0] = address(mockERC20);
        values[0] = 0;
        callData[0] = abi.encodeWithSignature("approve(address,uint256)", address(openfortPaymaster), 2 ** 256 - 1);

        targets[1] = address(testCounter);
        values[1] = 0;
        callData[1] = abi.encodeWithSignature("count()");

        // Create a userOp to let the paymaster use our mockERC20s
        UserOperation[] memory userOps = _setupUserOpExecuteBatch(
            accountAddress, openfortAdminPKey, bytes(""), targets, values, callData, paymasterAndData
        );

        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.FixedRate;
        strategy.depositor = paymasterAdmin;
        strategy.erc20Token = address(mockERC20);
        strategy.exchangeRate = pricePerTransaction;

        // Simulating that the Paymaster gets the userOp and signs it
        bytes32 hash;
        {
            hash = ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
            bytes memory signature = abi.encodePacked(r, s, v);
            bytes memory paymasterAndDataSigned = abi.encodePacked(address(openfortPaymaster), dataEncoded, signature);
            assertEq(openfortPaymaster.owner(), ECDSA.recover(hash, signature));
            userOps[0].paymasterAndData = paymasterAndDataSigned;
        }

        // Back to the user. Sign the userOp
        bytes memory userOpSignature;
        bytes32 hash2;
        {
            bytes32 opHash = entryPoint.getUserOpHash(userOps[0]);
            bytes32 msgHash = ECDSA.toEthSignedMessageHash(opHash);

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(openfortAdminPKey, msgHash);
            userOpSignature = abi.encodePacked(r, s, v);

            // Verifications below commented to avoid "Stack too deep" error
            assertEq(ECDSA.recover(msgHash, v, r, s), vm.addr(openfortAdminPKey));
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
        // Verify that the balance of the smart account has decreased
        assert(mockERC20.balanceOf(accountAddress) == TESTTOKEN_ACCOUNT_PREFUND - pricePerTransaction);
        assertEq(testCounter.counters(accountAddress), 1);
    }

    /*
     * Test sending a userOp with an valid paymasterAndData (valid paymaster, valid sig)
     * ExecBatch. Using fixed ERC20 expensive. Should work
     */
    function testPaymasterUserOpERC20FixedExpensiveValidSigExecBatch() public {
        assertEq(mockERC20.balanceOf(accountAddress), 0);
        mockERC20.mint(accountAddress, TESTTOKEN_ACCOUNT_PREFUND);
        assertEq(mockERC20.balanceOf(accountAddress), TESTTOKEN_ACCOUNT_PREFUND);

        assertEq(testCounter.counters(accountAddress), 0);

        uint256 pricePerTransaction = 10;

        bytes memory dataEncoded = mockPaymasterDataERC20Fixed(paymasterAdmin, pricePerTransaction);

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG);

        uint256 count = 2;
        address[] memory targets = new address[](count);
        uint256[] memory values = new uint256[](count);
        bytes[] memory callData = new bytes[](count);

        targets[0] = address(mockERC20);
        values[0] = 0;
        callData[0] = abi.encodeWithSignature("approve(address,uint256)", address(openfortPaymaster), 2 ** 256 - 1);

        targets[1] = address(testCounter);
        values[1] = 0;
        callData[1] = abi.encodeWithSignature("count()");

        // Create a userOp to let the paymaster use our mockERC20s
        UserOperation[] memory userOps = _setupUserOpExecuteBatch(
            accountAddress, openfortAdminPKey, bytes(""), targets, values, callData, paymasterAndData
        );

        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.FixedRate;
        strategy.depositor = paymasterAdmin;
        strategy.erc20Token = address(mockERC20);
        strategy.exchangeRate = pricePerTransaction;

        // Simulating that the Paymaster gets the userOp and signs it
        bytes32 hash;
        {
            hash = ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
            bytes memory signature = abi.encodePacked(r, s, v);
            bytes memory paymasterAndDataSigned = abi.encodePacked(address(openfortPaymaster), dataEncoded, signature);
            assertEq(openfortPaymaster.owner(), ECDSA.recover(hash, signature));
            userOps[0].paymasterAndData = paymasterAndDataSigned;
        }

        // Back to the user. Sign the userOp
        bytes memory userOpSignature;
        bytes32 hash2;
        {
            bytes32 opHash = entryPoint.getUserOpHash(userOps[0]);
            bytes32 msgHash = ECDSA.toEthSignedMessageHash(opHash);

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(openfortAdminPKey, msgHash);
            userOpSignature = abi.encodePacked(r, s, v);

            // Verifications below commented to avoid "Stack too deep" error
            assertEq(ECDSA.recover(msgHash, v, r, s), vm.addr(openfortAdminPKey));
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
        // Verify that the balance of the smart account has decreased
        assert(mockERC20.balanceOf(accountAddress) == TESTTOKEN_ACCOUNT_PREFUND - pricePerTransaction);
        assertEq(testCounter.counters(accountAddress), 1);
    }

    /*
     * Test sending a userOp with an valid paymasterAndData (valid paymaster, valid sig)
     * ExecBatch. Should work
     */
    function testPaymasterUserOpNativeValidSigExecBatch() public {
        bytes memory dataEncoded = mockPaymasterDataNative(paymasterAdmin);

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG);

        uint256 count = 2;
        address[] memory targets = new address[](count);
        uint256[] memory values = new uint256[](count);
        bytes[] memory callData = new bytes[](count);

        targets[0] = address(mockERC20);
        values[0] = 0;
        callData[0] = abi.encodeWithSignature("approve(address,uint256)", address(openfortPaymaster), 2 ** 256 - 1);

        targets[1] = address(testCounter);
        values[1] = 0;
        callData[1] = abi.encodeWithSignature("count()");

        // Create a userOp to let the paymaster use our mockERC20s
        UserOperation[] memory userOps = _setupUserOpExecuteBatch(
            accountAddress, openfortAdminPKey, bytes(""), targets, values, callData, paymasterAndData
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
            bytes memory paymasterAndDataSigned = abi.encodePacked(address(openfortPaymaster), dataEncoded, signature);
            assertEq(openfortPaymaster.owner(), ECDSA.recover(hash, signature));
            userOps[0].paymasterAndData = paymasterAndDataSigned;
        }

        // Back to the user. Sign the userOp
        bytes memory userOpSignature;
        bytes32 hash2;
        {
            bytes32 opHash = entryPoint.getUserOpHash(userOps[0]);
            bytes32 msgHash = ECDSA.toEthSignedMessageHash(opHash);

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(openfortAdminPKey, msgHash);
            userOpSignature = abi.encodePacked(r, s, v);

            // Verifications below commented to avoid "Stack too deep" error
            assertEq(ECDSA.recover(msgHash, v, r, s), vm.addr(openfortAdminPKey));
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
        //Verify that the counter has increased
        assertEq(testCounter.counters(accountAddress), 1);
    }

    /*
     * Test sending a userOp with an valid paymasterAndData (valid paymaster, valid sig)
     * ExecBatch. Using ERC20. Should work.
     * Test showing that failing to repay in ERC20 still spends some of Paymaster's deposit (DoS)
     */
    function testFailPaymasterUserOpERC20ValidSigExecBatchInsufficientERC20() public {
        assertEq(mockERC20.balanceOf(accountAddress), 0);
        mockERC20.mint(accountAddress, 100);
        assertEq(mockERC20.balanceOf(accountAddress), 100);

        assertEq(testCounter.counters(accountAddress), 0);

        bytes memory dataEncoded = mockPaymasterDataERC20Dynamic(paymasterAdmin);

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG);

        uint256 count = 2;
        address[] memory targets = new address[](count);
        uint256[] memory values = new uint256[](count);
        bytes[] memory callData = new bytes[](count);

        targets[0] = address(mockERC20);
        values[0] = 0;
        callData[0] = abi.encodeWithSignature("approve(address,uint256)", address(openfortPaymaster), 2 ** 256 - 1);

        targets[1] = address(testCounter);
        values[1] = 0;
        callData[1] = abi.encodeWithSignature("count()");

        // Create a userOp to let the paymaster use our mockERC20s
        UserOperation[] memory userOps = _setupUserOpExecuteBatch(
            accountAddress, openfortAdminPKey, bytes(""), targets, values, callData, paymasterAndData
        );

        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.DynamicRate;
        strategy.depositor = paymasterAdmin;
        strategy.erc20Token = address(mockERC20);
        strategy.exchangeRate = EXCHANGERATE;

        // Simulating that the Paymaster gets the userOp and signs it
        bytes32 hash;
        {
            hash = ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
            bytes memory signature = abi.encodePacked(r, s, v);
            bytes memory paymasterAndDataSigned = abi.encodePacked(address(openfortPaymaster), dataEncoded, signature);
            assertEq(openfortPaymaster.owner(), ECDSA.recover(hash, signature));
            userOps[0].paymasterAndData = paymasterAndDataSigned;
        }

        // Back to the user. Sign the userOp
        bytes memory userOpSignature;
        bytes32 hash2;
        {
            bytes32 opHash = entryPoint.getUserOpHash(userOps[0]);
            bytes32 msgHash = ECDSA.toEthSignedMessageHash(opHash);

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(openfortAdminPKey, msgHash);
            userOpSignature = abi.encodePacked(r, s, v);

            // Verifications below commented to avoid "Stack too deep" error
            assertEq(ECDSA.recover(msgHash, v, r, s), vm.addr(openfortAdminPKey));
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
        assertEq(mockERC20.balanceOf(accountAddress), 100);
        // Verify that the counter has not increased
        assertEq(testCounter.counters(accountAddress), 0);

        // If this fails, it would mean:
        // 1- That the paymaster has spent some of its deposit
        // 2- That the smart account could not perform the desired actions, but still has all mockERC20s
        // An attacker could DoS the paymaster to drain its deposit
    }

    /*
     * Test sending a userOp with an valid paymasterAndData (valid paymaster, valid sig)
     * Using ERC20. Should work.
     */
    function testFailPaymasterUserOpERC20ValidSigSmallApprove() public {
        assertEq(mockERC20.balanceOf(accountAddress), 0);
        mockERC20.mint(accountAddress, TESTTOKEN_ACCOUNT_PREFUND);
        assertEq(mockERC20.balanceOf(accountAddress), TESTTOKEN_ACCOUNT_PREFUND);

        bytes memory dataEncoded = mockPaymasterDataERC20Dynamic(paymasterAdmin);

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG);

        // Create a userOp to let the paymaster use our mockERC20s
        UserOperation[] memory userOps = _setupUserOpExecute(
            accountAddress,
            openfortAdminPKey,
            bytes(""),
            address(mockERC20),
            0,
            abi.encodeWithSignature("approve(address,uint256)", address(openfortPaymaster), 1),
            paymasterAndData
        );

        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.DynamicRate;
        strategy.depositor = paymasterAdmin;
        strategy.erc20Token = address(mockERC20);
        strategy.exchangeRate = EXCHANGERATE;

        // Simulating that the Paymaster gets the userOp and signs it
        bytes32 hash;
        {
            hash = ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
            bytes memory signature = abi.encodePacked(r, s, v);
            bytes memory paymasterAndDataSigned = abi.encodePacked(address(openfortPaymaster), dataEncoded, signature);
            assertEq(openfortPaymaster.owner(), ECDSA.recover(hash, signature));
            userOps[0].paymasterAndData = paymasterAndDataSigned;
        }

        // Back to the user. Sign the userOp
        bytes memory userOpSignature;
        bytes32 hash2;
        {
            bytes32 opHash = entryPoint.getUserOpHash(userOps[0]);
            bytes32 msgHash = ECDSA.toEthSignedMessageHash(opHash);

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(openfortAdminPKey, msgHash);
            userOpSignature = abi.encodePacked(r, s, v);

            // Verifications below commented to avoid "Stack too deep" error
            assertEq(ECDSA.recover(msgHash, v, r, s), vm.addr(openfortAdminPKey));
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
        assertEq(mockERC20.balanceOf(accountAddress), TESTTOKEN_ACCOUNT_PREFUND);
        // Verify that the counter has not increased
        assertEq(testCounter.counters(accountAddress), 0);

        // If this fails, it would mean:
        // 1- That the paymaster has spent some of its deposit
        // 2- That the smart account could not perform the desired actions, but still has all mockERC20s
        // An attacker could DoS the paymaster to drain its deposit
    }

    /*
     * Test sending a userOp with a valid paymasterAndData (valid paymaster, valid sig)
     * Using ERC20 and a 3rd party depositor. Should work
     */
    function testPaymasterUserOpERC20ValidSigDepositor() public {
        assertEq(mockERC20.balanceOf(accountAddress), 0);
        mockERC20.mint(accountAddress, TESTTOKEN_ACCOUNT_PREFUND);
        assertEq(mockERC20.balanceOf(accountAddress), TESTTOKEN_ACCOUNT_PREFUND);

        vm.prank(openfortAdmin);
        openfortPaymaster.depositFor{value: 50 ether}(openfortAdmin);
        assertEq(openfortPaymaster.getDeposit(), 100 ether);
        assertEq(openfortPaymaster.getDepositFor(openfortAdmin), 50 ether);
        assertEq(openfortPaymaster.getDepositFor(paymasterAdmin), 50 ether);

        bytes memory dataEncoded = mockPaymasterDataERC20Dynamic(openfortAdmin);

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG);

        // Create a userOp to let the paymaster use our mockERC20s
        UserOperation[] memory userOps = _setupUserOpExecute(
            accountAddress,
            openfortAdminPKey,
            bytes(""),
            address(mockERC20),
            0,
            abi.encodeWithSignature("approve(address,uint256)", address(openfortPaymaster), 2 ** 256 - 1),
            paymasterAndData
        );

        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.DynamicRate;
        strategy.depositor = openfortAdmin;
        strategy.erc20Token = address(mockERC20);
        strategy.exchangeRate = EXCHANGERATE;

        // Simulating that the Paymaster gets the userOp and signs it
        bytes32 hash;
        {
            hash = ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
            bytes memory signature = abi.encodePacked(r, s, v);
            bytes memory paymasterAndDataSigned = abi.encodePacked(address(openfortPaymaster), dataEncoded, signature);
            assertEq(openfortPaymaster.owner(), ECDSA.recover(hash, signature));
            userOps[0].paymasterAndData = paymasterAndDataSigned;
        }

        // Back to the user. Sign the userOp
        bytes memory userOpSignature;
        bytes32 hash2;
        {
            bytes32 opHash = entryPoint.getUserOpHash(userOps[0]);
            bytes32 msgHash = ECDSA.toEthSignedMessageHash(opHash);

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(openfortAdminPKey, msgHash);
            userOpSignature = abi.encodePacked(r, s, v);

            // Verifications below commented to avoid "Stack too deep" error
            assertEq(ECDSA.recover(msgHash, v, r, s), vm.addr(openfortAdminPKey));
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
        // Verify that the balance of the smart account has decreased
        assert(mockERC20.balanceOf(accountAddress) < TESTTOKEN_ACCOUNT_PREFUND);

        assert(openfortPaymaster.getDeposit() < 100 ether);
        assert(openfortPaymaster.getDepositFor(openfortAdmin) < 50 ether);
        // deposit of the owner should have increased a bit because of the dust
        assert(openfortPaymaster.getDepositFor(paymasterAdmin) > 50 ether);
    }

    /*
     * Test sending a userOp with a valid paymasterAndData (valid paymaster, valid sig)
     * Using ERC20 (fixed rate) and a 3rd party depositor. Should work
     */
    function testPaymasterUserOpERC20FixedValidSigDepositor() public {
        assertEq(mockERC20.balanceOf(accountAddress), 0);
        mockERC20.mint(accountAddress, TESTTOKEN_ACCOUNT_PREFUND);
        assertEq(mockERC20.balanceOf(accountAddress), TESTTOKEN_ACCOUNT_PREFUND);

        vm.prank(openfortAdmin);
        openfortPaymaster.depositFor{value: 50 ether}(openfortAdmin);
        assertEq(openfortPaymaster.getDeposit(), 100 ether);
        assertEq(openfortPaymaster.getDepositFor(openfortAdmin), 50 ether);
        assertEq(openfortPaymaster.getDepositFor(paymasterAdmin), 50 ether);

        uint256 pricePerTransaction = 10 ** 18;

        bytes memory dataEncoded = mockPaymasterDataERC20Fixed(openfortAdmin, pricePerTransaction);

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG);

        // Create a userOp to let the paymaster use our mockERC20s
        UserOperation[] memory userOps = _setupUserOpExecute(
            accountAddress,
            openfortAdminPKey,
            bytes(""),
            address(mockERC20),
            0,
            abi.encodeWithSignature("approve(address,uint256)", address(openfortPaymaster), 2 ** 256 - 1),
            paymasterAndData
        );

        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.FixedRate;
        strategy.depositor = openfortAdmin;
        strategy.erc20Token = address(mockERC20);
        strategy.exchangeRate = pricePerTransaction;

        // Simulating that the Paymaster gets the userOp and signs it
        bytes32 hash;
        {
            hash = ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
            bytes memory signature = abi.encodePacked(r, s, v);
            bytes memory paymasterAndDataSigned = abi.encodePacked(address(openfortPaymaster), dataEncoded, signature);
            assertEq(openfortPaymaster.owner(), ECDSA.recover(hash, signature));
            userOps[0].paymasterAndData = paymasterAndDataSigned;
        }

        // Back to the user. Sign the userOp
        bytes memory userOpSignature;
        bytes32 hash2;
        {
            bytes32 opHash = entryPoint.getUserOpHash(userOps[0]);
            bytes32 msgHash = ECDSA.toEthSignedMessageHash(opHash);

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(openfortAdminPKey, msgHash);
            userOpSignature = abi.encodePacked(r, s, v);

            // Verifications below commented to avoid "Stack too deep" error
            assertEq(ECDSA.recover(msgHash, v, r, s), vm.addr(openfortAdminPKey));
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
        // Verify that the balance of the smart account has decreased
        assert(mockERC20.balanceOf(accountAddress) < TESTTOKEN_ACCOUNT_PREFUND);

        assert(openfortPaymaster.getDeposit() < 100 ether);
        assert(openfortPaymaster.getDepositFor(openfortAdmin) < 50 ether);
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
            accountAddress,
            openfortAdminPKey,
            bytes(""),
            address(testCounter),
            0,
            abi.encodeWithSignature("count()"),
            ""
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
        openfortPaymaster.transferOwnership(openfortAdmin);

        vm.prank(paymasterAdmin);
        openfortPaymaster.transferOwnership(openfortAdmin);

        vm.expectRevert("Ownable2Step: caller is not the new owner");
        openfortPaymaster.acceptOwnership();

        vm.prank(openfortAdmin);
        openfortPaymaster.acceptOwnership();
        assertEq(openfortPaymaster.owner(), openfortAdmin);
    }

    /*
     * ToDo Test complex transfer ownership
     */
    function testAcceptOwnershipComplex() public {
        assertEq(openfortPaymaster.owner(), paymasterAdmin);

        // Play around with deposits
        assertEq(openfortPaymaster.getDeposit(), 50 ether);
        assertEq(openfortPaymaster.getDepositFor(paymasterAdmin), 50 ether);
        assertEq(openfortPaymaster.getDepositFor(openfortAdmin), 0 ether);

        openfortPaymaster.depositFor{value: 3 ether}(openfortAdmin);

        assertEq(openfortPaymaster.getDeposit(), 53 ether);
        assertEq(openfortPaymaster.getDepositFor(paymasterAdmin), 50 ether);
        assertEq(openfortPaymaster.getDepositFor(openfortAdmin), 3 ether);

        vm.prank(paymasterAdmin);
        openfortPaymaster.transferOwnership(openfortAdmin);

        assertEq(openfortPaymaster.getDeposit(), 53 ether);
        assertEq(openfortPaymaster.getDepositFor(paymasterAdmin), 50 ether);
        assertEq(openfortPaymaster.getDepositFor(openfortAdmin), 3 ether);
        // Play around with deposits

        vm.prank(openfortAdmin);
        openfortPaymaster.acceptOwnership();
        assertEq(openfortPaymaster.owner(), openfortAdmin);

        // After transferring the ownership, the old owner does not have any deposit
        // and the new one has all deposit from previous owner PLUS its old deposit

        assertEq(openfortPaymaster.getDeposit(), 53 ether);
        assertEq(openfortPaymaster.getDepositFor(paymasterAdmin), 0 ether);
        assertEq(openfortPaymaster.getDepositFor(openfortAdmin), 53 ether);
    }

    /*
     * Test using a new depositor (openfortAdmin)
     * Should work
     */
    function testPaymasterUserOpNativeValidSigDEPOSITOR() public {
        bytes memory dataEncoded = mockPaymasterDataNative(openfortAdmin);

        assertEq(openfortPaymaster.getDeposit(), 50 ether);
        assertEq(openfortPaymaster.getDepositFor(paymasterAdmin), 50 ether);
        assertEq(openfortPaymaster.getDepositFor(openfortAdmin), 0 ether);

        openfortPaymaster.depositFor{value: 3 ether}(openfortAdmin);

        assertEq(openfortPaymaster.getDeposit(), 53 ether);
        assertEq(openfortPaymaster.getDepositFor(paymasterAdmin), 50 ether);
        assertEq(openfortPaymaster.getDepositFor(openfortAdmin), 3 ether);

        bytes memory paymasterAndData = abi.encodePacked(address(openfortPaymaster), dataEncoded, MOCKSIG, "1", MOCKSIG);
        console.log("paymasterAndData");
        console.log("paymasterAndData");
        console.logBytes(paymasterAndData);

        UserOperation[] memory userOps = _setupUserOpExecute(
            accountAddress,
            openfortAdminPKey,
            bytes(""),
            address(testCounter),
            0,
            abi.encodeWithSignature("count()"),
            paymasterAndData
        );
        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.PayForUser;
        strategy.depositor = openfortAdmin;
        strategy.erc20Token = address(0);
        strategy.exchangeRate = 0;
        bytes32 hash;
        {
            // Simulating that the Paymaster gets the userOp and signs it
            hash = ECDSA.toEthSignedMessageHash(openfortPaymaster.getHash(userOps[0], VALIDUNTIL, VALIDAFTER, strategy));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(paymasterAdminPKey, hash);
            bytes memory signature = abi.encodePacked(r, s, v);
            bytes memory paymasterAndDataSigned = abi.encodePacked(address(openfortPaymaster), dataEncoded, signature);
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
            bytes32 opHash = entryPoint.getUserOpHash(userOps[0]);
            bytes32 msgHash = ECDSA.toEthSignedMessageHash(opHash);

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(openfortAdminPKey, msgHash);
            userOpSignature = abi.encodePacked(r, s, v);

            // Verifications below commented to avoid "Stack too deep" error
            assertEq(ECDSA.recover(msgHash, v, r, s), vm.addr(openfortAdminPKey));

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
        //Verify that the counter has increased
        assertEq(testCounter.counters(accountAddress), 1);

        assert(openfortPaymaster.getDeposit() < 53 ether); // less than 53 because the total cost have decreased
        assert(openfortPaymaster.getDepositFor(paymasterAdmin) > 50 ether); // more than 50 because the dust has gone to the owner deposit
        assert(openfortPaymaster.getDepositFor(openfortAdmin) < 3 ether); // less than 3 because the gas cost was paid using openfortAdmin's deposit
    }
}
