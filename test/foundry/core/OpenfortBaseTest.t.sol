// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {Test, console} from "lib/forge-std/src/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {EntryPoint, IEntryPoint, UserOperation} from "account-abstraction/core/EntryPoint.sol";
import {TestCounter} from "account-abstraction/test/TestCounter.sol";
import {MockERC20} from "contracts/mock/MockERC20.sol";
import {MockV2UpgradeableOpenfortAccount} from "contracts/mock/MockV2UpgradeableOpenfortAccount.sol";

contract OpenfortBaseTest is Test {
    using ECDSA for bytes32;

    bytes32 public versionSalt;

    EntryPoint public entryPoint;

    address public accountAddress;
    TestCounter public testCounter;
    MockERC20 public mockERC20;

    // Testing addresses
    address public factoryAdmin;
    uint256 public factoryAdminPKey;

    address public accountAdmin;
    uint256 public accountAdminPKey;

    address payable public beneficiary = payable(makeAddr("beneficiary"));

    // bytes4(keccak256("isValidSignature(bytes32,bytes)")
    bytes4 public constant MAGICVALUE = 0x1626ba7e;
    // keccak256("OpenfortMessage(bytes32 hashedMessage)");
    bytes32 public constant OF_MSG_TYPEHASH = 0x57159f03b9efda178eab2037b2ec0b51ce11be0051b8a2a9992c29dc260e4a30;
    bytes32 public constant _TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    // keccak256("Recover(address recoveryAddress,uint64 executeAfter,uint32 guardiansRequired)");
    bytes32 public RECOVER_TYPEHASH = 0x9f7aca777caf11405930359f601a4db01fad1b2d79ef3f2f9e93c835e9feffa5;

    uint256 public constant RECOVERY_PERIOD = 2 days;
    uint256 public constant SECURITY_PERIOD = 1.5 days;
    uint256 public constant SECURITY_WINDOW = 0.5 days;
    uint256 public constant LOCK_PERIOD = 5 days;
    address public OPENFORT_GUARDIAN;
    uint256 public OPENFORT_GUARDIAN_PKEY;

    event AccountImplementationDeployed(address indexed creator);
    event AccountCreated(address indexed account, address indexed accountAdmin);
    event GuardianProposed(address indexed guardian, uint256 executeAfter);
    event GuardianProposalCancelled(address indexed guardian);
    event GuardianRevocationRequested(address indexed guardian, uint256 executeAfter);
    event GuardianRevocationCancelled(address indexed guardian);

    error ZeroAddressNotAllowed();
    error AccountLocked();
    error AccountNotLocked();
    error MustBeGuardian();
    error DuplicatedGuardian();
    error UnknownProposal();
    error PendingProposalNotOver();
    error PendingProposalExpired();
    error DuplicatedRevoke();
    error UnknownRevoke();
    error PendingRevokeNotOver();
    error PendingRevokeExpired();
    error GuardianCannotBeOwner();
    error NoOngoingRecovery();
    error OngoingRecovery();
    error InvalidRecoverySignatures();
    error InvalidSignatureAmount();

    /*
     * Auxiliary function to generate a userOP
     */
    function _setupUserOp(
        address sender,
        uint256 _signerPKey,
        bytes memory _initCode,
        bytes memory _callDataForEntrypoint
    ) public returns (UserOperation[] memory ops) {
        uint256 nonce = entryPoint.getNonce(sender, 0);

        // Get user op fields
        UserOperation memory op = UserOperation({
            sender: sender,
            nonce: nonce,
            initCode: _initCode,
            callData: _callDataForEntrypoint,
            callGasLimit: 1_000_000,
            verificationGasLimit: 1_000_000,
            preVerificationGas: 50_000,
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
    ) public returns (UserOperation[] memory) {
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
    ) public returns (UserOperation[] memory) {
        bytes memory callDataForEntrypoint =
            abi.encodeWithSignature("executeBatch(address[],uint256[],bytes[])", _target, _value, _callData);

        return _setupUserOp(sender, _signerPKey, _initCode, callDataForEntrypoint);
    }
}
