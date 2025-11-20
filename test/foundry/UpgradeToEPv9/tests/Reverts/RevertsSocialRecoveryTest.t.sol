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
