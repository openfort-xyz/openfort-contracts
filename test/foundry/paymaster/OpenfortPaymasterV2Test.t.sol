// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {Test, console} from "lib/forge-std/src/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint, UserOperation, IEntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";
import {TestToken} from "account-abstraction/test/TestToken.sol";
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

    function mockedPaymasterDataNative() internal view returns (bytes memory dataEncoded) {
        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.PayForUser;
        strategy.depositor = address(paymasterAdmin);
        strategy.erc20Token = address(0);
        strategy.exchangeRate = EXCHANGERATE;
        // Looking at the source code, I've found this part was not Packed (filled with 0s)
        dataEncoded = abi.encode(VALIDUNTIL, VALIDAFTER, strategy);
    }

    function mockedPaymasterDataERC20Dynamic() internal view returns (bytes memory dataEncoded) {
        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.DynamicRate;
        strategy.depositor = address(paymasterAdmin);
        strategy.erc20Token = address(testToken);
        strategy.exchangeRate = EXCHANGERATE;
        // Looking at the source code, I've found this part was not Packed (filled with 0s)
        dataEncoded = abi.encode(VALIDUNTIL, VALIDAFTER, strategy);
    }

    function mockedPaymasterDataERC20Fixed(uint256 pricePerTransaction)
        internal
        view
        returns (bytes memory dataEncoded)
    {
        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.FixedRate;
        strategy.depositor = address(paymasterAdmin);
        strategy.erc20Token = address(testToken);
        strategy.exchangeRate = pricePerTransaction;
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
        // Fund the paymaster with 100 ETH
        vm.deal(address(openfortPaymaster), 100 ether);
        // Paymaster deposits 50 ETH to EntryPoint
        openfortPaymaster.depositFor{value: 50 ether}(paymasterAdmin);
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
     * Deposit should fail
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
        bytes memory dataEncoded = mockedPaymasterDataNative();

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
        assertEq(strategy.exchangeRate, EXCHANGERATE);
        assertEq(signature, returnedSignature);
    }

    /*
     * Test parsePaymasterAndData() with an ERC20 dynamic
     * 
     */
    function testParsePaymasterDataERC20() public {
        // Encode the paymaster data
        bytes memory dataEncoded = mockedPaymasterDataERC20Dynamic();

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
     * The owner (paymasterAdmin) can add stake
     * Others cannot
     */
    function testPaymasterAddStake() public {
        // The owner can add stake
        vm.prank(paymasterAdmin);
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
        openfortPaymaster.depositFor{value: 1 ether}(address(factoryAdmin));
        assert(openfortPaymaster.getDeposit() == 52 ether);
        assert(openfortPaymaster.getDepositFor(address(openfortPaymaster)) == 0 ether);
        assert(openfortPaymaster.getDepositFor(address(factoryAdmin)) == 1 ether);
    }

    /*
     * Test sending a userOp with an invalid paymasterAndData (valid paymaster, but invalid sig length)
     * Should revert
     */
    function testPaymasterUserOpWrongSigLength() public {
        bytes memory dataEncoded = mockedPaymasterDataERC20Dynamic();

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
        bytes memory dataEncoded = mockedPaymasterDataERC20Dynamic();

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
        OpenfortPaymasterV2.PolicyStrategy memory strategy;
        strategy.paymasterMode = OpenfortPaymasterV2.Mode.PayForUser;
        strategy.erc20Token = address(0);
        strategy.exchangeRate = EXCHANGERATE;
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

        bytes memory dataEncoded = mockedPaymasterDataERC20Dynamic();

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
     * Using ERC20. Should work
     */
    function testPaymasterUserOpERC20ValidSig() public {
        assertEq(testToken.balanceOf(account), 0);
        testToken.mint(account, TESTTOKEN_ACCOUNT_PREFUND);
        assertEq(testToken.balanceOf(account), TESTTOKEN_ACCOUNT_PREFUND);

        bytes memory dataEncoded = mockedPaymasterDataERC20Dynamic();

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

        bytes memory dataEncoded = mockedPaymasterDataERC20Fixed(pricePerTransaction);

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
        strategy.depositor = address(paymasterAdmin);
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
        assert(testToken.balanceOf(account) == TESTTOKEN_ACCOUNT_PREFUND-pricePerTransaction);
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

        bytes memory dataEncoded = mockedPaymasterDataERC20Dynamic();

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
        strategy.depositor = address(paymasterAdmin);
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

        bytes memory dataEncoded = mockedPaymasterDataERC20Fixed(pricePerTransaction);

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
        strategy.depositor = address(paymasterAdmin);
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
        assert(testToken.balanceOf(account) == TESTTOKEN_ACCOUNT_PREFUND-pricePerTransaction);
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

        bytes memory dataEncoded = mockedPaymasterDataERC20Fixed(pricePerTransaction);

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
        strategy.depositor = address(paymasterAdmin);
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
        assert(testToken.balanceOf(account) == TESTTOKEN_ACCOUNT_PREFUND-pricePerTransaction);
        assertEq(testCounter.counters(account), 1);
    }

    /*
     * Test sending a userOp with an valid paymasterAndData (valid paymaster, valid sig)
     * ExecBatch. Should work
     */
    function testPaymasterUserOpNativeValidSigExecBatch() public {
        bytes memory dataEncoded = mockedPaymasterDataNative();

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
        strategy.depositor = address(paymasterAdmin);
        strategy.erc20Token = address(0);
        strategy.exchangeRate = EXCHANGERATE;

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

        bytes memory dataEncoded = mockedPaymasterDataERC20Dynamic();

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
        strategy.depositor = address(paymasterAdmin);
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

        bytes memory dataEncoded = mockedPaymasterDataERC20Dynamic();

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
        strategy.depositor = address(paymasterAdmin);
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
}
