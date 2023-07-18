// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test, console} from "lib/forge-std/src/Test.sol";
import {SigUtils} from "../../utils/SigUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint, IEntryPoint, UserOperation} from "account-abstraction/core/EntryPoint.sol";
import {VIPNFT} from "contracts/mock/VipNFT.sol";
import {ERC6551Registry} from "contracts/core/eip6551/ERC6551Registry.sol";
import {EIP6551OpenfortAccount} from "contracts/core/eip6551/EIP6551OpenfortAccount.sol";

contract EIP6551OpenfortAccountTest is Test {
    using ECDSA for bytes32;

    EntryPoint public entryPoint;
    ERC6551Registry public erc6551Registry;
    EIP6551OpenfortAccount public eip6551OpenfortAccount;
    EIP6551OpenfortAccount implEIP6551OpenfortAccount;
    address public account;
    VIPNFT testToken;

    // Testing addresses
    address private factoryAdmin;
    uint256 private factoryAdminPKey;

    address private accountAdmin;
    uint256 private accountAdminPKey;

    address payable private beneficiary = payable(makeAddr("beneficiary"));

    event AccountCreated(
        address account, address implementation, uint256 chainId, address tokenContract, uint256 tokenId, uint256 salt
    );

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
     * - factoryAdmin is the deployer (and owner) of the StaticOpenfortFactory
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

        uint256 chainId;
        assembly {
            chainId := chainid()
        }

        vm.startPrank(factoryAdmin);

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

        // deploy a new VIPNFT collection
        testToken = new VIPNFT();

        implEIP6551OpenfortAccount = new EIP6551OpenfortAccount();

        erc6551Registry = new ERC6551Registry();

        address eip6551OpenfortAccountAddress =
            erc6551Registry.createAccount(address(implEIP6551OpenfortAccount), chainId, address(testToken), 1, 1, "");

        eip6551OpenfortAccount = EIP6551OpenfortAccount(payable(eip6551OpenfortAccountAddress));
        eip6551OpenfortAccount.initialize(address(entryPoint));

        testToken.mint(eip6551OpenfortAccountAddress, 1);

        vm.stopPrank();
    }

    /*
     * Test reinitialize. It should fail.
     * 
     */
    function testFailReinitialize() public {
        eip6551OpenfortAccount.initialize(address(entryPoint));
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
        address eip6551OpenfortAccountAddress2 =
            erc6551Registry.createAccount(address(implEIP6551OpenfortAccount), chainId, address(testToken), 1, 2, "");

        EIP6551OpenfortAccount eip6551OpenfortAccount2 = EIP6551OpenfortAccount(payable(eip6551OpenfortAccountAddress2));
        eip6551OpenfortAccount2.initialize(address(entryPoint));
        IEntryPoint e = eip6551OpenfortAccount2.entryPoint();
        assertEq(address(e), address(entryPoint));
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
            address(implEIP6551OpenfortAccount),
            chainId,
            address(testToken),
            1,
            2,
            abi.encodeWithSignature("initialize(address)", address(entryPoint))
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
            address(implEIP6551OpenfortAccount),
            chainId,
            address(testToken),
            1,
            2,
            abi.encodeWithSignature("initialize(address)", address(entryPoint))
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
        assertEq(eip6551OpenfortAccount.owner(), testToken.ownerOf(1));
        assertEq(eip6551OpenfortAccount.owner(), address(eip6551OpenfortAccount));
    }

    /*
     * Test owner() function.
     * Check that the owner of the eip6551 account is the owner of the NFT
     */
    function testNotOwner() public {
        // Burning the NFT
        vm.prank(address(eip6551OpenfortAccount));
        testToken.transferFrom(address(eip6551OpenfortAccount), address(1), 1);

        assertEq(eip6551OpenfortAccount.owner(), testToken.ownerOf(1));
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
            erc6551Registry.account(address(eip6551OpenfortAccount), chainId, address(testToken), 1, 2);

        // Expect that we will see an event containing the account and admin
        vm.expectEmit(true, true, false, true);
        emit AccountCreated(
            eip6551OpenfortAccountAddress2, address(eip6551OpenfortAccount), chainId, address(testToken), 1, 2
        );

        // Deploy a static account to the counterfactual address
        vm.prank(factoryAdmin);
        erc6551Registry.createAccount(address(eip6551OpenfortAccount), chainId, address(testToken), 1, 2, "");

        // Make sure the counterfactual address has not been altered
        vm.prank(factoryAdmin);
        assertEq(
            eip6551OpenfortAccountAddress2,
            erc6551Registry.account(address(eip6551OpenfortAccount), chainId, address(testToken), 1, 2)
        );
        assertNotEq(
            eip6551OpenfortAccountAddress2,
            erc6551Registry.account(address(eip6551OpenfortAccount), chainId, address(testToken), 1, 3)
        );
        assertNotEq(
            eip6551OpenfortAccountAddress2,
            erc6551Registry.account(address(eip6551OpenfortAccount), chainId + 1, address(testToken), 1, 2)
        );
        assertNotEq(
            eip6551OpenfortAccountAddress2,
            erc6551Registry.account(address(eip6551OpenfortAccount), chainId, address(0), 1, 2)
        );
    }
}
