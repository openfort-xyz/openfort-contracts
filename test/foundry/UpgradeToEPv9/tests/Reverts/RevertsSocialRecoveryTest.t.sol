// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {PackedUserOperation} from "lib/account-abstraction-v09/contracts/interfaces/PackedUserOperation.sol";
import {SocialRecoveryHelper} from "test/foundry/UpgradeToEPv9/helpers/SocialRecoveryHelper.t.sol";
import {
    UpgradeableOpenfortAccount as UpgradeableOpenfortAccountV9
} from "contracts/coreV9/upgradeable/UpgradeableOpenfortAccount.sol";

contract RevertsSocialRecoveryTest is SocialRecoveryHelper {
    address internal _RandomOwner;
    uint256 internal _RandomOwnerPK;
    bytes32 internal _RandomOwnerSalt;
    UpgradeableOpenfortAccountV9 internal _RandomOwnerSC;

    address internal _NewOwner;
    address internal _Attacker;

    RandomOwner internal randomOwner;

    error NotOwnerOrEntrypoint();
    error ZeroAddressNotAllowed();
    error DuplicatedGuardian();
    error DuplicatedProposal();
    error GuardianCannotBeOwner();
    error UnknownProposal();
    error PendingProposalNotOver();
    error PendingProposalExpired();
    error MustBeGuardian();
    error DuplicatedRevoke();
    error UnknownRevoke();
    error PendingRevokeNotOver();
    error PendingRevokeExpired();
    error AccountLocked();
    error AccountNotLocked();
    error OngoingRecovery();
    error NoOngoingRecovery();
    error InvalidRecoverySignatures();
    error InvalidSignatureAmount();

    function setUp() public override {
        super.setUp();
        (_RandomOwner, _RandomOwnerPK) = makeAddrAndKey("_RandomOwner");
        _NewOwner = makeAddr("_NewOwner");
        _Attacker = makeAddr("_Attacker");
        (_RecoveryOwner, _RecoveryOwnerPK) = makeAddrAndKey("_RecoveryOwner");
        _deal(_RandomOwner, 5 ether);
        _RandomOwnerSalt = keccak256(abi.encodePacked("0xbebe_0001"));
        _createAccountV9();
        _deal(address(_RandomOwnerSC), 5 ether);
        randomOwner = RandomOwner(_RandomOwner, _RandomOwnerSC);
    }

    function test_revert_proposeGuardian_notOwner() external {
        vm.prank(_Attacker);
        vm.expectRevert(NotOwnerOrEntrypoint.selector);
        _RandomOwnerSC.proposeGuardian(_NewOwner);
    }

    function test_revert_proposeGuardian_accountLocked() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        vm.prank(_Guardians[0]);
        _RandomOwnerSC.lock();

        vm.prank(_RandomOwner);
        vm.expectRevert(AccountLocked.selector);
        _RandomOwnerSC.proposeGuardian(_NewOwner);
    }

    function test_revert_proposeGuardian_guardianCannotBeOwner() external {
        vm.prank(_RandomOwner);
        vm.expectRevert(GuardianCannotBeOwner.selector);
        _RandomOwnerSC.proposeGuardian(_RandomOwner);
    }

    function test_revert_proposeGuardian_guardianCannotBePendingOwner() external {
        vm.prank(_RandomOwner);
        _RandomOwnerSC.transferOwnership(_NewOwner);

        vm.prank(_RandomOwner);
        vm.expectRevert(GuardianCannotBeOwner.selector);
        _RandomOwnerSC.proposeGuardian(_NewOwner);
    }

    function test_revert_proposeGuardian_alreadyGuardian() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        vm.prank(_RandomOwner);
        vm.expectRevert(DuplicatedGuardian.selector);
        _RandomOwnerSC.proposeGuardian(_Guardians[0]);
    }

    function test_revert_proposeGuardian_zeroAddress() external {
        vm.prank(_RandomOwner);
        vm.expectRevert(GuardianCannotBeOwner.selector);
        _RandomOwnerSC.proposeGuardian(address(0));
    }

    function test_revert_proposeGuardian_alreadyPendingProposal() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);

        vm.prank(_RandomOwner);
        vm.expectRevert(DuplicatedProposal.selector);
        _RandomOwnerSC.proposeGuardian(_Guardians[0]);
    }

    function test_revert_confirmGuardianProposal_accountLocked() external createGuardians(2) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 2);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        vm.prank(_Guardians[0]);
        _RandomOwnerSC.lock();

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);

        vm.prank(_Attacker);
        vm.expectRevert(AccountLocked.selector);
        _RandomOwnerSC.confirmGuardianProposal(_Guardians[1]);
    }

    function test_revert_confirmGuardianProposal_noProposal() external createGuardians(1) {
        vm.prank(_Attacker);
        vm.expectRevert(UnknownProposal.selector);
        _RandomOwnerSC.confirmGuardianProposal(_Guardians[0]);
    }

    function test_revert_confirmGuardianProposal_notReady() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);

        vm.prank(_Attacker);
        vm.expectRevert(PendingProposalNotOver.selector);
        _RandomOwnerSC.confirmGuardianProposal(_Guardians[0]);
    }


    function test_revert_confirmGuardianProposal_expired() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);

        vm.warp(block.timestamp + SECURITY_PERIOD + SECURITY_WINDOW + 1);

        vm.prank(_Attacker);
        vm.expectRevert(PendingProposalExpired.selector);
        _RandomOwnerSC.confirmGuardianProposal(_Guardians[0]);
    }

    function test_revert_confirmGuardianProposal_ongoingRecovery() external createGuardians(2) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 2);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        vm.prank(_Guardians[0]);
        _RandomOwnerSC.startRecovery(_RecoveryOwner);

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);

        vm.prank(_Attacker);
        vm.expectRevert(OngoingRecovery.selector);
        _RandomOwnerSC.confirmGuardianProposal(_Guardians[1]);
    }


    function test_revert_cancelGuardianProposal_notOwner() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);

        vm.prank(_Attacker);
        vm.expectRevert(NotOwnerOrEntrypoint.selector);
        _RandomOwnerSC.cancelGuardianProposal(_Guardians[0]);
    }

    function test_revert_cancelGuardianProposal_accountLocked() external createGuardians(2) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 2);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        vm.prank(_Guardians[0]);
        _RandomOwnerSC.lock();

        vm.prank(_RandomOwner);
        vm.expectRevert(AccountLocked.selector);
        _RandomOwnerSC.cancelGuardianProposal(_Guardians[1]);
    }

    function test_revert_cancelGuardianProposal_noProposal() external createGuardians(1) {
        vm.prank(_RandomOwner);
        vm.expectRevert(UnknownProposal.selector);
        _RandomOwnerSC.cancelGuardianProposal(_Guardians[0]);
    }

    function test_revert_cancelGuardianProposal_alreadyConfirmed() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        vm.prank(_RandomOwner);
        vm.expectRevert(UnknownProposal.selector);
        _RandomOwnerSC.cancelGuardianProposal(_Guardians[0]);
    }

    function test_revert_revokeGuardian_notOwner() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        vm.prank(_Attacker);
        vm.expectRevert(NotOwnerOrEntrypoint.selector);
        _RandomOwnerSC.revokeGuardian(_Guardians[0]);
    }

    function test_revert_revokeGuardian_guardianNotActive() external createGuardians(1) {
        vm.prank(_RandomOwner);
        vm.expectRevert(MustBeGuardian.selector);
        _RandomOwnerSC.revokeGuardian(_Guardians[0]);
    }


    function test_revert_revokeGuardian_accountLocked() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        vm.prank(_Guardians[0]);
        _RandomOwnerSC.lock();

        vm.prank(_RandomOwner);
        vm.expectRevert(AccountLocked.selector);
        _RandomOwnerSC.revokeGuardian(_Guardians[0]);
    }

    function test_revert_revokeGuardian_alreadyPendingRevocation() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        _executeGuardianAction(randomOwner, GuardianAction.REVOKE, 1);

        vm.prank(_RandomOwner);
        vm.expectRevert(DuplicatedRevoke.selector);
        _RandomOwnerSC.revokeGuardian(_Guardians[0]);
    }

    function test_revert_confirmGuardianRevocation_noRevocation() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        vm.prank(_Attacker);
        vm.expectRevert(UnknownRevoke.selector);
        _RandomOwnerSC.confirmGuardianRevocation(_Guardians[0]);
    }

    function test_revert_confirmGuardianRevocation_accountLocked() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);
        _executeGuardianAction(randomOwner, GuardianAction.REVOKE, 1);

        vm.prank(_Guardians[0]);
        _RandomOwnerSC.lock();

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);

        vm.prank(_Attacker);
        vm.expectRevert(AccountLocked.selector);
        _RandomOwnerSC.confirmGuardianRevocation(_Guardians[0]);
    }

    function test_revert_confirmGuardianRevocation_notReady() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);
        _executeGuardianAction(randomOwner, GuardianAction.REVOKE, 1);

        vm.prank(_Attacker);
        vm.expectRevert(PendingRevokeNotOver.selector);
        _RandomOwnerSC.confirmGuardianRevocation(_Guardians[0]);
    }

    function test_revert_confirmGuardianRevocation_expired() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);
        _executeGuardianAction(randomOwner, GuardianAction.REVOKE, 1);

        vm.warp(block.timestamp + SECURITY_PERIOD + SECURITY_WINDOW + 1);

        vm.prank(_Attacker);
        vm.expectRevert(PendingRevokeExpired.selector);
        _RandomOwnerSC.confirmGuardianRevocation(_Guardians[0]);
    }

    function test_revert_cancelGuardianRevocation_notOwner() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);
        _executeGuardianAction(randomOwner, GuardianAction.REVOKE, 1);

        vm.prank(_Attacker);
        vm.expectRevert(NotOwnerOrEntrypoint.selector);
        _RandomOwnerSC.cancelGuardianRevocation(_Guardians[0]);
    }

    function test_revert_cancelGuardianRevocation_accountLocked() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);
        _executeGuardianAction(randomOwner, GuardianAction.REVOKE, 1);

        vm.prank(_Guardians[0]);
        _RandomOwnerSC.lock();

        vm.prank(_RandomOwner);
        vm.expectRevert(AccountLocked.selector);
        _RandomOwnerSC.cancelGuardianRevocation(_Guardians[0]);
    }

    function test_revert_cancelGuardianRevocation_noRevocation() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        vm.prank(_RandomOwner);
        vm.expectRevert(UnknownRevoke.selector);
        _RandomOwnerSC.cancelGuardianRevocation(_Guardians[0]);
    }

    function test_revert_lock_invalidCaller() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        vm.prank(_Attacker);
        vm.expectRevert(MustBeGuardian.selector);
        _RandomOwnerSC.lock();
    }

    function test_revert_lock_accountLocked() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        vm.prank(_Guardians[0]);
        _RandomOwnerSC.lock();

        vm.prank(_Guardians[0]);
        vm.expectRevert(AccountLocked.selector);
        _RandomOwnerSC.lock();
    }

    function test_revert_unlock_notGuardian() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        vm.prank(_Guardians[0]);
        _RandomOwnerSC.lock();

        vm.prank(_Attacker);
        vm.expectRevert(MustBeGuardian.selector);
        _RandomOwnerSC.unlock();
    }

    function test_revert_unlock_accountNotLocked() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        vm.prank(_Guardians[0]);
        vm.expectRevert(AccountNotLocked.selector);
        _RandomOwnerSC.unlock();
    }

    function test_revert_startRecovery_invalidCaller() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        vm.prank(_Attacker);
        vm.expectRevert(MustBeGuardian.selector);
        _RandomOwnerSC.startRecovery(_RecoveryOwner);
    }

    function test_revert_startRecovery_ongoingRecovery() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        vm.prank(_Guardians[0]);
        _RandomOwnerSC.startRecovery(_RecoveryOwner);

        vm.prank(_Guardians[0]);
        vm.expectRevert(OngoingRecovery.selector);
        _RandomOwnerSC.startRecovery(_RecoveryOwner);
    }

    function test_revert_startRecovery_guardianCannotBeOwner() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        vm.prank(_Guardians[0]);
        vm.expectRevert(GuardianCannotBeOwner.selector);
        _RandomOwnerSC.startRecovery(_Guardians[0]);
    }


    function test_revert_completeRecovery_noOngoingRecovery() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);

        bytes[] memory emptySigs = new bytes[](0);

        vm.prank(_Attacker);
        vm.expectRevert(NoOngoingRecovery.selector);
        _RandomOwnerSC.completeRecovery(emptySigs);
    }

    function test_revert_completeRecovery_notReady() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);
        _executeGuardianAction(randomOwner, GuardianAction.START_RECOVERY, 0);

        _signGuardians(randomOwner, 1);

        vm.prank(_Attacker);
        vm.expectRevert(OngoingRecovery.selector);
        _RandomOwnerSC.completeRecovery(_signatures);
    }

    function test_revert_completeRecovery_invalidSignatureCount() external createGuardians(3) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 3);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 3);
        _executeGuardianAction(randomOwner, GuardianAction.START_RECOVERY, 0);

        bytes[] memory insufficientSigs = new bytes[](1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_GuardiansPK[0], keccak256("dummy"));
        insufficientSigs[0] = abi.encodePacked(r, s, v);

        vm.warp(block.timestamp + RECOVERY_PERIOD + 1);

        vm.prank(_Attacker);
        vm.expectRevert(InvalidSignatureAmount.selector);
        _RandomOwnerSC.completeRecovery(insufficientSigs);
    }

    function test_revert_completeRecovery_invalidGuardianSignature() external createGuardians(1) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 1);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 1);
        _executeGuardianAction(randomOwner, GuardianAction.START_RECOVERY, 0);

        bytes[] memory invalidSigs = new bytes[](1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_RandomOwnerPK, keccak256("wrong"));
        invalidSigs[0] = abi.encodePacked(r, s, v);

        vm.warp(block.timestamp + RECOVERY_PERIOD + 1);

        vm.prank(_Attacker);
        vm.expectRevert(InvalidRecoverySignatures.selector);
        _RandomOwnerSC.completeRecovery(invalidSigs);
    }

    function test_revert_completeRecovery_signaturesNotInOrder() external createGuardians(3) {
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 3);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 3);
        _executeGuardianAction(randomOwner, GuardianAction.START_RECOVERY, 0);

        (address recoveryAddress, uint64 executeAfter, uint32 guardiansRequired) =
            _RandomOwnerSC.recoveryDetails();

        bytes32 structHash = keccak256(abi.encode(
            0x9f7aca777caf11405930359f601a4db01fad1b2d79ef3f2f9e93c835e9feffa5,
            recoveryAddress,
            executeAfter,
            guardiansRequired
        ));

        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("Openfort")),
                keccak256(bytes("0.9")),
                block.chainid,
                address(_RandomOwnerSC)
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

        bytes[] memory unorderedSigs = new bytes[](2);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(_GuardiansPK[2], digest);
        unorderedSigs[0] = abi.encodePacked(r1, s1, v1);

        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(_GuardiansPK[0], digest);
        unorderedSigs[1] = abi.encodePacked(r2, s2, v2);

        vm.warp(block.timestamp + RECOVERY_PERIOD + 1);

        vm.prank(_Attacker);
        vm.expectRevert(InvalidRecoverySignatures.selector);
        _RandomOwnerSC.completeRecovery(unorderedSigs);
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
}
