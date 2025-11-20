// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC777Recipient} from "@openzeppelin/contracts/token/ERC777/IERC777Recipient.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {MessageHashUtils} from "lib/oz-v5.4.0/contracts/utils/cryptography/MessageHashUtils.sol";
import {BaseOpenfortAccount} from "contracts/coreV9/base/BaseOpenfortAccount.sol";
import {UpgradeableOpenfortProxy} from "contracts/coreV9/upgradeable/UpgradeableOpenfortProxy.sol";
import {PackedUserOperation} from "lib/account-abstraction-v09/contracts/interfaces/PackedUserOperation.sol";
import {SocialRecoveryHelper} from "test/foundry/UpgradeToEPv9/helpers/SocialRecoveryHelper.t.sol";
import {
    UpgradeableOpenfortAccount as UpgradeableOpenfortAccountV9
} from "contracts/coreV9/upgradeable/UpgradeableOpenfortAccount.sol";

contract GettersTest is SocialRecoveryHelper {
    address internal _RandomOwner;
    uint256 internal _RandomOwnerPK;
    bytes32 internal _RandomOwnerSalt;
    UpgradeableOpenfortAccountV9 internal _RandomOwnerSC;

    address internal _NewOwner;
    uint256 internal _NewOwnerPK;

    address internal SK;
    uint256 internal SK_PK;

    uint48 private constant VALID_AFTER = 0;
    uint48 private VALID_UNTIL;
    uint48 private constant LIMIT = 10;

    RandomOwner internal randomOwner;

    function setUp() public override {
        super.setUp();
        VALID_UNTIL = uint48(block.timestamp + 10 days);
        (_RandomOwner, _RandomOwnerPK) = makeAddrAndKey("_RandomOwner");
        (_NewOwner, _NewOwnerPK) = makeAddrAndKey("_NewOwner");
        (SK, SK_PK) = makeAddrAndKey("sessionKey");
        (_RecoveryOwner, _RecoveryOwnerPK) = makeAddrAndKey("_RecoveryOwner");
        _deal(_RandomOwner, 5 ether);
        _RandomOwnerSalt = keccak256(abi.encodePacked("0xbebe_0001"));
        _createAccountV9();
        _deal(address(_RandomOwnerSC), 5 ether);
        randomOwner = RandomOwner(_RandomOwner, _RandomOwnerSC);
    }

    function test_GetOwner() external {
        assertEq(_RandomOwnerSC.owner(), _RandomOwner);
    }

    function test_GetOwnerAfterTransferOwnership() external {
        vm.prank(_RandomOwner);
        _RandomOwnerSC.transferOwnership(_NewOwner);

        assertEq(_RandomOwnerSC.owner(), _RandomOwner);
        assertEq(_RandomOwnerSC.pendingOwner(), _NewOwner);

        vm.prank(_NewOwner);
        _RandomOwnerSC.acceptOwnership();

        assertEq(_RandomOwnerSC.owner(), _NewOwner);
        assertEq(_RandomOwnerSC.pendingOwner(), address(0));
    }

    function test_GetPendingOwnerNoPending() external {
        assertEq(_RandomOwnerSC.pendingOwner(), address(0));
    }

    function test_GetPendingOwnerDuringTransfer() external {
        vm.prank(_RandomOwner);
        _RandomOwnerSC.transferOwnership(_NewOwner);

        assertEq(_RandomOwnerSC.pendingOwner(), _NewOwner);
    }

    function test_GetPendingOwnerAfterAccept() external {
        vm.prank(_RandomOwner);
        _RandomOwnerSC.transferOwnership(_NewOwner);

        vm.prank(_NewOwner);
        _RandomOwnerSC.acceptOwnership();

        assertEq(_RandomOwnerSC.pendingOwner(), address(0));
    }

    function test_GetEntryPoint() external {
        assertEq(address(_RandomOwnerSC.entryPoint()), address(entryPointV9));
    }

    function test_GetDepositAfterDeposit() external {
        uint256 deposit = _RandomOwnerSC.getDeposit();
        assertTrue(deposit > 0);
    }

    function test_GetDepositReturnsValue() external {
        uint256 deposit = _RandomOwnerSC.getDeposit();
        assertTrue(deposit >= 0);
    }

    function test_GetNonceInitial() external {
        uint256 nonce = _RandomOwnerSC.getNonce();
        assertEq(nonce, 1);
    }

    function test_GetNonceAfterUserOp() external {
        uint256 nonceBefore = _RandomOwnerSC.getNonce();

        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomOwnerSC));

        bytes memory callData = hex"";
        userOp = _populateUserOpV9(
            userOp, callData, _packAccountGasLimits(400_000, 600_000), 800_000, _packGasFees(15 gwei, 80 gwei), hex""
        );

        bytes32 userOpHash = _getUserOpHashV9(userOp);
        userOp.signature = _signUserOp(userOpHash, _RandomOwnerPK);

        _relayUserOpV9(userOp);

        uint256 nonceAfter = _RandomOwnerSC.getNonce();
        assertEq(nonceAfter, nonceBefore + 1);
    }

    function test_IsLockedWhenUnlocked() external {
        assertFalse(_RandomOwnerSC.isLocked());
    }

    function test_IsLockedWhenLocked() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        vm.prank(_Guardians[0]);
        _RandomOwnerSC.lock();

        assertTrue(_RandomOwnerSC.isLocked());
    }

    function test_IsLockedAfterExpiry() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        vm.prank(_Guardians[0]);
        _RandomOwnerSC.lock();

        assertTrue(_RandomOwnerSC.isLocked());

        vm.warp(block.timestamp + LOCK_PERIOD + 1);

        assertFalse(_RandomOwnerSC.isLocked());
    }

    function test_GetLockWhenUnlocked() external {
        assertEq(_RandomOwnerSC.getLock(), 0);
    }

    function test_GetLockWhenLocked() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        uint256 lockTime = block.timestamp;
        vm.prank(_Guardians[0]);
        _RandomOwnerSC.lock();

        uint256 expectedLockRelease = lockTime + LOCK_PERIOD;
        assertEq(_RandomOwnerSC.getLock(), expectedLockRelease);
    }

    function test_GetLockAfterExpiry() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        vm.prank(_Guardians[0]);
        _RandomOwnerSC.lock();

        vm.warp(block.timestamp + LOCK_PERIOD + 1);

        assertEq(_RandomOwnerSC.getLock(), 0);
    }

    function test_GetLockAfterManualUnlock() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        vm.prank(_Guardians[0]);
        _RandomOwnerSC.lock();

        assertTrue(_RandomOwnerSC.isLocked());

        vm.prank(_Guardians[0]);
        _RandomOwnerSC.unlock();

        assertEq(_RandomOwnerSC.getLock(), 0);
    }

    function test_GetGuardianCountZero() external {
        assertEq(_RandomOwnerSC.guardianCount(), 0);
    }

    function test_GetGuardianCountAfterAdd() external createGuardians(3) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 3);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 3);

        assertEq(_RandomOwnerSC.guardianCount(), 3);
    }

    function test_GetGuardianCountAfterRevoke() external createGuardians(3) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 3);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 3);

        assertEq(_RandomOwnerSC.guardianCount(), 3);

        _executeGuardianAction(randomOwner, GuardianAction.REVOKE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_REVOCATION, 1);

        assertEq(_RandomOwnerSC.guardianCount(), 2);
    }

    function test_GetGuardiansEmpty() external {
        address[] memory guardians = _RandomOwnerSC.getGuardians();
        assertEq(guardians.length, 0);
    }

    function test_GetGuardiansWithGuardians() external createGuardians(3) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 3);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 3);

        address[] memory guardians = _RandomOwnerSC.getGuardians();
        assertEq(guardians.length, 3);
        assertEq(guardians[0], _Guardians[0]);
        assertEq(guardians[1], _Guardians[1]);
        assertEq(guardians[2], _Guardians[2]);
    }

    function test_GetGuardiansAfterRemoval() external createGuardians(3) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 3);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 3);

        _executeGuardianAction(randomOwner, GuardianAction.REVOKE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_REVOCATION, 1);

        address[] memory guardians = _RandomOwnerSC.getGuardians();
        assertEq(guardians.length, 2);
    }

    function test_IsGuardianNotGuardian() external {
        assertFalse(_RandomOwnerSC.isGuardian(address(0xdead)));
    }

    function test_IsGuardianActiveGuardian() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        assertTrue(_RandomOwnerSC.isGuardian(_Guardians[0]));
    }

    function test_IsGuardianAfterRevocation() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        assertTrue(_RandomOwnerSC.isGuardian(_Guardians[0]));

        _executeGuardianAction(randomOwner, GuardianAction.REVOKE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_REVOCATION, 1);

        assertFalse(_RandomOwnerSC.isGuardian(_Guardians[0]));
    }

    function test_GetRecoveryDetailsNoRecovery() external {
        (address recoveryAddress, uint64 executeAfter, uint32 guardiansRequired) = _RandomOwnerSC.recoveryDetails();

        assertEq(recoveryAddress, address(0));
        assertEq(executeAfter, 0);
        assertEq(guardiansRequired, 0);
    }

    function test_GetRecoveryDetailsDuringRecovery() external createGuardians(3) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 3);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 3);

        vm.warp(block.timestamp + 1);

        vm.prank(_Guardians[0]);
        _RandomOwnerSC.startRecovery(_RecoveryOwner);

        (address recoveryAddress, uint64 executeAfter, uint32 guardiansRequired) = _RandomOwnerSC.recoveryDetails();

        assertEq(recoveryAddress, _RecoveryOwner);
        assertEq(executeAfter, uint64(block.timestamp + RECOVERY_PERIOD));
        assertEq(guardiansRequired, uint32(Math.ceilDiv(3, 2)));
    }

    function test_GetRecoveryDetailsAfterCompletion() external createGuardians(3) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 3);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 3);
        _executeGuardianAction(randomOwner, GuardianAction.START_RECOVERY, 1);

        _signGuardians(randomOwner, 2);
        _executeConfirmRecovery(randomOwner);

        (address recoveryAddress, uint64 executeAfter, uint32 guardiansRequired) = _RandomOwnerSC.recoveryDetails();

        assertEq(recoveryAddress, address(0));
        assertEq(executeAfter, 0);
        assertEq(guardiansRequired, 0);
    }

    function test_GetRecoveryDetailsAfterCancellation() external createGuardians(3) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 3);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 3);
        _executeGuardianAction(randomOwner, GuardianAction.START_RECOVERY, 1);

        _executeGuardianAction(randomOwner, GuardianAction.CANCEL_RECOVERY, 0);

        (address recoveryAddress, uint64 executeAfter, uint32 guardiansRequired) = _RandomOwnerSC.recoveryDetails();

        assertEq(recoveryAddress, address(0));
        assertEq(executeAfter, 0);
        assertEq(guardiansRequired, 0);
    }

    function test_GetSessionKeysNonExistent() external {
        (
            uint48 validAfter,
            uint48 validUntil,
            uint48 limit,
            bool masterSessionKey,
            bool whitelisting,
            address registrarAddress
        ) = _RandomOwnerSC.sessionKeys(address(0xdead));

        assertEq(validAfter, 0);
        assertEq(validUntil, 0);
        assertEq(limit, 0);
        assertFalse(masterSessionKey);
        assertFalse(whitelisting);
        assertEq(registrarAddress, address(0));
    }

    function test_GetSessionKeysMasterKey() external {
        _registerMasterSessionKey();

        (
            uint48 validAfter,
            uint48 validUntil,
            uint48 limit,
            bool masterSessionKey,
            bool whitelisting,
            address registrarAddress
        ) = _RandomOwnerSC.sessionKeys(SK);

        assertEq(validAfter, VALID_AFTER);
        assertEq(validUntil, VALID_UNTIL);
        assertEq(limit, type(uint48).max);
        assertTrue(masterSessionKey);
        assertFalse(whitelisting);
        assertEq(registrarAddress, _RandomOwner);
    }

    function test_GetSessionKeysLimitedKey() external {
        _registerLimitedSessionKey();

        (
            uint48 validAfter,
            uint48 validUntil,
            uint48 limit,
            bool masterSessionKey,
            bool whitelisting,
            address registrarAddress
        ) = _RandomOwnerSC.sessionKeys(SK);

        assertEq(validAfter, VALID_AFTER);
        assertEq(validUntil, VALID_UNTIL);
        assertEq(limit, LIMIT);
        assertFalse(masterSessionKey);
        assertTrue(whitelisting);
        assertEq(registrarAddress, _RandomOwner);
    }

    function test_GetSessionKeysAfterRevocation() external {
        _registerMasterSessionKey();

        vm.prank(_RandomOwner);
        _RandomOwnerSC.revokeSessionKey(SK);

        (
            uint48 validAfter,
            uint48 validUntil,
            uint48 limit,
            bool masterSessionKey,
            bool whitelisting,
            address registrarAddress
        ) = _RandomOwnerSC.sessionKeys(SK);

        assertEq(validAfter, 0);
        assertEq(validUntil, 0);
        assertEq(limit, 0);
        assertFalse(masterSessionKey);
        assertFalse(whitelisting);
        assertEq(registrarAddress, address(0));
    }

    function test_SupportsInterfaceERC165() external {
        assertTrue(_RandomOwnerSC.supportsInterface(type(IERC165).interfaceId));
    }

    function test_SupportsInterfaceERC721() external {
        assertTrue(_RandomOwnerSC.supportsInterface(type(IERC721Receiver).interfaceId));
    }

    function test_SupportsInterfaceERC777() external {
        assertTrue(_RandomOwnerSC.supportsInterface(type(IERC777Recipient).interfaceId));
    }

    function test_SupportsInterfaceERC1155() external {
        assertTrue(_RandomOwnerSC.supportsInterface(type(IERC1155Receiver).interfaceId));
    }

    function test_SupportsInterfaceInvalid() external {
        assertFalse(_RandomOwnerSC.supportsInterface(bytes4(0x00000000)));
        assertFalse(_RandomOwnerSC.supportsInterface(bytes4(0xdeadbeef)));
    }

    function test_IsValidSignatureOwner() external {
        bytes32 hash = keccak256("test message");
        bytes memory signature = _signMessage(hash, _RandomOwnerPK);

        bytes4 result = _RandomOwnerSC.isValidSignature(hash, signature);
        assertEq(result, bytes4(0x1626ba7e));
    }

    function test_IsValidSignatureMasterSessionKey() external {
        _registerMasterSessionKey();

        bytes32 hash = keccak256("test message");
        bytes memory signature = _signMessage(hash, SK_PK);

        bytes4 result = _RandomOwnerSC.isValidSignature(hash, signature);
        assertEq(result, bytes4(0x1626ba7e));
    }

    function test_IsValidSignatureInvalid() external {
        bytes32 hash = keccak256("test message");
        bytes memory wrongSignature = _signMessage(hash, _NewOwnerPK);

        bytes4 result = _RandomOwnerSC.isValidSignature(hash, wrongSignature);
        assertEq(result, bytes4(0xffffffff));
    }

    function test_IsValidSignatureExpiredSessionKey() external {
        vm.prank(_RandomOwner);
        address[] memory whitelist = new address[](1);
        whitelist[0] = address(erc20);
        _RandomOwnerSC.registerSessionKey(SK, VALID_AFTER, uint48(block.timestamp + 1 days), LIMIT, whitelist);

        vm.warp(block.timestamp + 2 days);

        bytes32 hash = keccak256("test message");
        bytes memory signature = _signMessage(hash, SK_PK);

        bytes4 result = _RandomOwnerSC.isValidSignature(hash, signature);
        assertEq(result, bytes4(0xffffffff));
    }

    function test_EIP712Domain() external {
        (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        ) = _RandomOwnerSC.eip712Domain();

        assertEq(name, "Openfort");
        assertEq(version, "0.9");
        assertEq(chainId, block.chainid);
        assertEq(verifyingContract, address(_RandomOwnerSC));
        assertEq(fields, hex"0f");
        assertEq(salt, bytes32(0));
        assertEq(extensions.length, 0);
    }
    
    function _createAccountV9() internal {
        address _RandomOwnerSCAddr = openfortFactoryV9.getAddressWithNonce(_RandomOwner, _RandomOwnerSalt);
        _RandomOwnerSC = UpgradeableOpenfortAccountV9(payable(_RandomOwnerSCAddr));
        _depositTo(_RandomOwner, address(_RandomOwnerSC), EP_Version.V9);
        _sendAssetsToSC(_RandomOwner, address(_RandomOwnerSC));

        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomOwnerSC));

        bytes memory callData = hex"";
        userOp = _populateUserOpV9(
            userOp, callData, _packAccountGasLimits(400_000, 600_000), 800_000, _packGasFees(15 gwei, 80 gwei), hex""
        );

        bytes memory initCode = abi.encodeWithSignature(
            "createAccountWithNonce(address,bytes32,bool)", _RandomOwner, _RandomOwnerSalt, false
        );
        userOp.initCode = abi.encodePacked(address(openfortFactoryV9), initCode);

        bytes32 userOpHash = _getUserOpHashV9(userOp);

        userOp.signature = _signUserOp(userOpHash, _RandomOwnerPK);

        _relayUserOpV9(userOp);
    }

    function _relayUserOpV9(PackedUserOperation memory _userOp) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _userOp;

        vm.prank(_OpenfortAdmin, _OpenfortAdmin);
        entryPointV9.handleOps(ops, payable(_OpenfortAdmin));
    }

    function _registerMasterSessionKey() internal {
        vm.prank(_RandomOwner);
        address[] memory emptyWhitelist = new address[](0);
        _RandomOwnerSC.registerSessionKey(SK, VALID_AFTER, VALID_UNTIL, type(uint48).max, emptyWhitelist);
    }

    function _registerLimitedSessionKey() internal {
        vm.prank(_RandomOwner);
        address[] memory whitelist = new address[](1);
        whitelist[0] = address(erc20);
        _RandomOwnerSC.registerSessionKey(SK, VALID_AFTER, VALID_UNTIL, LIMIT, whitelist);
    }

    function _signMessage(bytes32 _hash, uint256 _privateKey) internal view returns (bytes memory) {
        bytes32 OF_MSG_TYPEHASH = 0x57159f03b9efda178eab2037b2ec0b51ce11be0051b8a2a9992c29dc260e4a30;
        bytes32 structHash = keccak256(abi.encode(OF_MSG_TYPEHASH, _hash));

        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("Openfort")),
                keccak256(bytes("0.9")),
                block.chainid,
                address(_RandomOwnerSC)
            )
        );

        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
