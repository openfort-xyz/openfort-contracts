// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {Deploy} from "test/foundry/UpgradeToEPv9/Deploy.t.sol";
import {console2 as console} from "lib/forge-std/src/console2.sol";
import {BaseRecoverableAccount} from "contracts/coreV9/base/BaseRecoverableAccount.sol";
import {
    UpgradeableOpenfortAccount as UpgradeableOpenfortAccountV9
} from "contracts/coreV9/upgradeable/UpgradeableOpenfortAccount.sol";

contract SocialRecoveryHelper is Deploy {
    struct RandomOwner {
        address _RandomOwner;
        UpgradeableOpenfortAccountV9 _RandomOwnerSC;
    }
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

    address[] internal _Guardians;
    uint256[] internal _GuardiansPK;
    address internal _RecoveryOwner;
    uint256 internal _RecoveryOwnerPK;

    BaseRecoverableAccount.RecoveryConfig internal recoveryDetails;

    modifier createGuardians(uint256 _indx) {
        _createGuardians(_indx);
        _;
    }

    function _createGuardians(uint256 _index) internal {
        for (uint256 i = 0; i < _index; i++) {
            (address addr, uint256 pk) = makeAddrAndKey(string.concat("guardian", vm.toString(i)));
            _Guardians.push(addr);
            _GuardiansPK.push(pk);
            _deal(addr, 1e18);
        }
    }

    function _executeGuardianAction(RandomOwner storage _randomOwner, GuardianAction action, uint256 _count) internal {
        if (
            action == GuardianAction.CONFIRM_PROPOSAL || action == GuardianAction.CONFIRM_REVOCATION
        ) {
            vm.warp(block.timestamp + SECURITY_PERIOD + 1);
        }

        if (action == GuardianAction.START_RECOVERY) {
            vm.warp(block.timestamp + 1);
            vm.prank(_Guardians[_count]);
            _randomOwner._RandomOwnerSC.startRecovery(_RecoveryOwner);
            return;
        }

        if (action == GuardianAction.CANCEL_RECOVERY) {
            _cancelRecovery(_randomOwner);
            return;
        }

        for (uint256 i = 0; i < _count;) {
            if (action == GuardianAction.PROPOSE) {
                _proposeGuardian(_randomOwner, _Guardians[i]);
            } else if (action == GuardianAction.CONFIRM_PROPOSAL) {
                _confirmGuardian(_randomOwner, _Guardians[i]);
            } else if (action == GuardianAction.CANCEL_PROPOSAL) {
                _cancelGuardianProposal(_randomOwner, _Guardians[i]);
            } else if (action == GuardianAction.REVOKE) {
                _revokeGuardian(_randomOwner, _Guardians[i]);
            } else if (action == GuardianAction.CONFIRM_REVOCATION) {
                _confirmGuardianRevocation(_randomOwner, _Guardians[i]);
            } else if (action == GuardianAction.CANCEL_REVOCATION) {
                _cancelGuardianRevocation(_randomOwner, _Guardians[i]);
            }
            unchecked {
                ++i;
            }
        }
    }

    function _proposeGuardian(RandomOwner storage _randomOwner, address _guardian) internal {
        bytes memory data = abi.encodeWithSelector(
            _randomOwner._RandomOwnerSC.proposeGuardian.selector, _guardian
        );
        _executeDirectCall(_randomOwner, data);
    }

    function _confirmGuardian(RandomOwner storage _randomOwner, address _guardian) internal {
        bytes memory data = abi.encodeWithSelector(
            _randomOwner._RandomOwnerSC.confirmGuardianProposal.selector, _guardian
        );
        _executeDirectCall(_randomOwner, data);
    }

    function _cancelGuardianProposal(RandomOwner storage _randomOwner, address _guardian) internal {
        bytes memory data = abi.encodeWithSelector(
            _randomOwner._RandomOwnerSC.cancelGuardianProposal.selector, _guardian
        );
        _executeDirectCall(_randomOwner, data);
    }

    function _revokeGuardian(RandomOwner storage _randomOwner, address _guardian) internal {
        bytes memory data = abi.encodeWithSelector(
            _randomOwner._RandomOwnerSC.revokeGuardian.selector, _guardian
        );
        _executeDirectCall(_randomOwner, data);
    }

    function _confirmGuardianRevocation(RandomOwner storage _randomOwner, address _guardian) internal {
        bytes memory data = abi.encodeWithSelector(
            _randomOwner._RandomOwnerSC.confirmGuardianRevocation.selector, _guardian
        );
        _executeDirectCall(_randomOwner, data);
    }

    function _cancelGuardianRevocation(RandomOwner storage _randomOwner, address _guardian) internal {
        bytes memory data = abi.encodeWithSelector(
            _randomOwner._RandomOwnerSC.cancelGuardianRevocation.selector, _guardian
        );
        _executeDirectCall(_randomOwner, data);
    }

    function _cancelRecovery(RandomOwner storage _randomOwner) internal {
        bytes memory data =
            abi.encodeWithSelector(_randomOwner._RandomOwnerSC.cancelRecovery.selector);
        _executeDirectCall(_randomOwner, data);
    }

    function _executeDirectCall(RandomOwner storage _randomOwner, bytes memory _data) internal {
        vm.prank(_randomOwner._RandomOwner);
        (bool success, bytes memory res) = address(_randomOwner._RandomOwnerSC).call{value: 0}(_data);
        if (!success) console.log(vm.toString(res));
    }
}