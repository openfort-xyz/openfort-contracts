// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {Deploy} from "test/foundry/UpgradeToEPv9/Deploy.t.sol";
import {console2 as console} from "lib/forge-std/src/console2.sol";
import {BaseOpenfortAccount} from "contracts/coreV9/base/BaseOpenfortAccount.sol";
import {BaseRecoverableAccount} from "contracts/coreV9/base/BaseRecoverableAccount.sol";
import {IBaseRecoverableAccount} from "contracts/interfaces/IBaseRecoverableAccount.sol";
import {UpgradeableOpenfortProxy} from "contracts/coreV9/upgradeable/UpgradeableOpenfortProxy.sol";
import {PackedUserOperation} from "lib/account-abstraction-v09/contracts/interfaces/PackedUserOperation.sol";
import {
    UpgradeableOpenfortAccount as UpgradeableOpenfortAccountV9
} from "contracts/coreV9/upgradeable/UpgradeableOpenfortAccount.sol";

contract SocialRecoveryTest is Deploy {
    enum GuardianAction {
        PROPOSE,
        CONFIRM_PROPOSAL,
        CANCEL_PROPOSAL,
        REVOKE,
        CONFIRM_REVOCATION,
        CANCEL_REVOCATION,
        START_RECOVERY,
        CANCEL_RECOVERY
    }

    address internal _RandomOwner;
    uint256 internal _RandomOwnerPK;
    bytes32 internal _RandomOwnerSalt;
    UpgradeableOpenfortAccountV9 internal _RandomOwnerSC;

    address[] internal _Guardians;
    uint256[] internal _GuardiansPK;
    address internal _RecoveryOwner;
    uint256 internal _RecoveryOwnerPK;

    BaseRecoverableAccount.RecoveryConfig internal recoveryDetails;

    modifier createGuardians(uint256 _indx) {
        _createGuardians(_indx);
        _;
    }

    function setUp() public override {
        super.setUp();
        (_RandomOwner, _RandomOwnerPK) = makeAddrAndKey("_RandomOwner");
        (_RecoveryOwner, _RecoveryOwnerPK) = makeAddrAndKey("_RandomOwner");
        _deal(_RandomOwner, 5 ether);
        _RandomOwnerSalt = keccak256(abi.encodePacked("0xbebe_0001"));
        _createAccountV9();
        _deal(address(_RandomOwnerSC), 5 ether);
    }

    function test_proposeGuardianDirect() external createGuardians(3) {
        _assertGuardianCount(0);
        _executeGuardianAction(GuardianAction.PROPOSE, 3);
        _assertGuardianCount(0);
        _assertPendingGuardians(3, true);
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
            bool getPendingStatusGuardian =
                _RandomOwnerSC.isGuardian(_Guardians[i]);
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

    function _createGuardians(uint256 _index) internal {
        for (uint256 i = 0; i < _index; i++) {
            (address addr, uint256 pk) = makeAddrAndKey(string.concat("guardian", vm.toString(i)));
            _Guardians.push(addr);
            _GuardiansPK.push(pk);
            _deal(addr, 1e18);
        }
    }

    function _executeGuardianAction(GuardianAction action, uint256 _count) internal {
        if (
            action == GuardianAction.CONFIRM_PROPOSAL || action == GuardianAction.CONFIRM_REVOCATION
        ) {
            vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        }

        if (action == GuardianAction.START_RECOVERY) {
            vm.warp(block.timestamp + 1);
            vm.prank(_Guardians[_count]);
            _RandomOwnerSC.startRecovery(_RecoveryOwner);
            return;
        }

        if (action == GuardianAction.CANCEL_RECOVERY) {
            _cancelRecovery();
            return;
        }

        for (uint256 i = 0; i < _count;) {
            if (action == GuardianAction.PROPOSE) {
                _proposeGuardian(_Guardians[i]);
            } else if (action == GuardianAction.CONFIRM_PROPOSAL) {
                _confirmGuardian(_Guardians[i]);
            } else if (action == GuardianAction.CANCEL_PROPOSAL) {
                _cancelGuardianProposal(_Guardians[i]);
            } else if (action == GuardianAction.REVOKE) {
                _revokeGuardian(_Guardians[i]);
            } else if (action == GuardianAction.CONFIRM_REVOCATION) {
                _confirmGuardianRevocation(_Guardians[i]);
            } else if (action == GuardianAction.CANCEL_REVOCATION) {
                _cancelGuardianRevocation(_Guardians[i]);
            }
            unchecked {
                ++i;
            }
        }
    }

    function _proposeGuardian(address _guardian) internal {
        bytes memory data = abi.encodeWithSelector(
            _RandomOwnerSC.proposeGuardian.selector, _guardian
        );
        _executeDirectCall(data);
    }

    function _confirmGuardian(address _guardian) internal {
        bytes memory data = abi.encodeWithSelector(
            _RandomOwnerSC.confirmGuardianProposal.selector, _guardian
        );
        _executeDirectCall(data);
    }

    function _cancelGuardianProposal(address _guardian) internal {
        bytes memory data = abi.encodeWithSelector(
            _RandomOwnerSC.cancelGuardianProposal.selector, _guardian
        );
        _executeDirectCall(data);
    }

    function _revokeGuardian(address _guardian) internal {
        bytes memory data = abi.encodeWithSelector(
            _RandomOwnerSC.revokeGuardian.selector, _guardian
        );
        _executeDirectCall(data);
    }

    function _confirmGuardianRevocation(address _guardian) internal {
        bytes memory data = abi.encodeWithSelector(
            _RandomOwnerSC.confirmGuardianRevocation.selector, _guardian
        );
        _executeDirectCall(data);
    }

    function _cancelGuardianRevocation(address _guardian) internal {
        bytes memory data = abi.encodeWithSelector(
            _RandomOwnerSC.cancelGuardianRevocation.selector, _guardian
        );
        _executeDirectCall(data);
    }

    function _cancelRecovery() internal {
        bytes memory data =
            abi.encodeWithSelector(_RandomOwnerSC.cancelRecovery.selector);
        _executeDirectCall(data);
    }

    function _executeDirectCall(bytes memory _data) internal {
        vm.prank(_RandomOwner);
        (bool success, bytes memory res) = address(_RandomOwnerSC).call{value: 0}(_data);
        if (!success) console.log(vm.toString(res));
    }
}