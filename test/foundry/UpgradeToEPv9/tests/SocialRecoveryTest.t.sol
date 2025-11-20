// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {console2 as console} from "lib/forge-std/src/console2.sol";
import {BaseOpenfortAccount} from "contracts/coreV9/base/BaseOpenfortAccount.sol";
import {BaseRecoverableAccount} from "contracts/coreV9/base/BaseRecoverableAccount.sol";
import {IBaseRecoverableAccount} from "contracts/interfaces/IBaseRecoverableAccount.sol";
import {SocialRecoveryHelper} from "test/foundry/UpgradeToEPv9/helpers/SocialRecoveryHelper.t.sol";
import {UpgradeableOpenfortProxy} from "contracts/coreV9/upgradeable/UpgradeableOpenfortProxy.sol";
import {PackedUserOperation} from "lib/account-abstraction-v09/contracts/interfaces/PackedUserOperation.sol";
import {
    UpgradeableOpenfortAccount as UpgradeableOpenfortAccountV9
} from "contracts/coreV9/upgradeable/UpgradeableOpenfortAccount.sol";

contract SocialRecoveryTest is SocialRecoveryHelper {
    address internal _RandomOwner;
    uint256 internal _RandomOwnerPK;
    bytes32 internal _RandomOwnerSalt;
    UpgradeableOpenfortAccountV9 internal _RandomOwnerSC;

    RandomOwner internal randomOwner;

    function setUp() public override {
        super.setUp();
        (_RandomOwner, _RandomOwnerPK) = makeAddrAndKey("_RandomOwner");
        (_RecoveryOwner, _RecoveryOwnerPK) = makeAddrAndKey("_RandomOwner");
        _deal(_RandomOwner, 5 ether);
        _RandomOwnerSalt = keccak256(abi.encodePacked("0xbebe_0001"));
        _createAccountV9();
        _deal(address(_RandomOwnerSC), 5 ether);
        randomOwner = RandomOwner(_RandomOwner, _RandomOwnerSC);
    }

    function test_proposeGuardianDirect() external createGuardians(3) {
        _assertGuardianCount(0);
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 3);
        _assertGuardianCount(0);
        _assertPendingGuardians(3, true);
    }

    function test_proposeGuardianAA() external createGuardians(3) {
        _assertGuardianCount(0);

        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomOwnerSC));

        for (uint256 i = 0; i < _Guardians.length;) {
            bytes memory callData = abi.encodeWithSelector(_RandomOwnerSC.proposeGuardian.selector, _Guardians[i]);

            userOp = _populateUserOpV9(
                userOp,
                callData,
                _packAccountGasLimits(400_000, 600_000),
                800_000,
                _packGasFees(15 gwei, 80 gwei),
                hex""
            );

            bytes32 userOpHash = _getUserOpHashV9(userOp);

            userOp.signature = _signUserOp(userOpHash, _RandomOwnerPK);

            _relayUserOpV9(userOp);
            unchecked {
                ++i;
            }
        }

        _assertGuardianCount(0);
        _assertPendingGuardians(3, true);
    }

    function test_confirmGuardianProposalDirect() external createGuardians(3) {
        _assertGuardianCount(0);
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 3);
        _assertGuardianCount(0);
        _assertPendingGuardians(3, true);
        _executeGuardianAction(randomOwner, GuardianAction.CONFIRM_PROPOSAL, 3);
        _assertGuardianCount(3);
        _assertPendingGuardians(3, false);
        _assertGuardians(3);
    }

    function test_confirmGuardianProposalAA() external createGuardians(3) {
        _assertGuardianCount(0);
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 3);
        _assertGuardianCount(0);
        _assertPendingGuardians(3, true);

        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomOwnerSC));

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);

        for (uint256 i = 0; i < _Guardians.length;) {
            bytes memory callData = abi.encodeWithSelector(_RandomOwnerSC.confirmGuardianProposal.selector, _Guardians[i]);

            userOp = _populateUserOpV9(
                userOp,
                callData,
                _packAccountGasLimits(400_000, 600_000),
                800_000,
                _packGasFees(15 gwei, 80 gwei),
                hex""
            );

            bytes32 userOpHash = _getUserOpHashV9(userOp);

            userOp.signature = _signUserOp(userOpHash, _RandomOwnerPK);

            _relayUserOpV9(userOp);
            unchecked {
                ++i;
            }
        }

        _assertGuardianCount(3);
        _assertPendingGuardians(3, false);
        _assertGuardians(3);
    }

    function test_cancelGuardianProposalDirect() external createGuardians(3) {
        _assertGuardianCount(0);
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 3);
        _assertGuardianCount(0);
        _assertPendingGuardians(3, true);
        _executeGuardianAction(randomOwner, GuardianAction.CANCEL_PROPOSAL, 3);
        _assertPendingGuardians(3, true);
        _assertGuardianCount(0);
    }

    function test_cancelGuardianProposalAA() external createGuardians(3) {
        _assertGuardianCount(0);
        _executeGuardianAction(randomOwner, GuardianAction.PROPOSE, 3);
        _assertGuardianCount(0);
        _assertPendingGuardians(3, true);

        PackedUserOperation memory userOp;
        (, userOp) = _getFreshUserOp(address(_RandomOwnerSC));

        vm.warp(block.timestamp + SECURITY_PERIOD + 1);

        for (uint256 i = 0; i < _Guardians.length;) {
            bytes memory callData = abi.encodeWithSelector(_RandomOwnerSC.cancelGuardianProposal.selector, _Guardians[i]);

            userOp = _populateUserOpV9(
                userOp,
                callData,
                _packAccountGasLimits(400_000, 600_000),
                800_000,
                _packGasFees(15 gwei, 80 gwei),
                hex""
            );

            bytes32 userOpHash = _getUserOpHashV9(userOp);

            userOp.signature = _signUserOp(userOpHash, _RandomOwnerPK);

            _relayUserOpV9(userOp);
            unchecked {
                ++i;
            }
        }

        _assertPendingGuardians(3, true);
        _assertGuardianCount(0);
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
        _assertAfterCreation();
    }

    function _relayUserOpV9(PackedUserOperation memory _userOp) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _userOp;

        vm.prank(_OpenfortAdmin, _OpenfortAdmin);
        entryPointV9.handleOps(ops, payable(_OpenfortAdmin));
    }

    function _assertAfterCreation() internal {
        UpgradeableOpenfortProxy proxy = UpgradeableOpenfortProxy(payable(address(_RandomOwnerSC)));
        assertEq(_RandomOwnerSC.owner(), _RandomOwner);
        assertEq(proxy.implementation(), address(upgradeableOpenfortAccountImplV9));
        assertEq(address(_RandomOwnerSC.entryPoint()), address(entryPointV9));
    }

    function _assertGuardianCount(uint256 _count) internal {
        uint256 guardianCount = _RandomOwnerSC.guardianCount();
        assertEq(guardianCount, _count);
    }

    function _assertPendingGuardians(uint256 _count, bool _isPending) internal {
        for (uint256 i = 0; i < _count;) {
            bool getPendingStatusGuardian = _RandomOwnerSC.isGuardian(_Guardians[i]);
            if (_isPending) {
                assertFalse(getPendingStatusGuardian);
            } else {
                assertTrue(getPendingStatusGuardian);
            }
            unchecked {
                ++i;
            }
        }
    }

    function _assertGuardians(uint256 _count) internal {
        for (uint256 i = 0; i < _count;) {
            address[] memory gS = _RandomOwnerSC.getGuardians();
            assertEq(gS[i], _Guardians[i]);
            unchecked {
                ++i;
            }
        }
    }
}
