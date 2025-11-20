// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {Deploy} from "test/foundry/UpgradeToEPv9/Deploy.t.sol";
import {BaseRecoverableAccount} from "contracts/coreV9/base/BaseRecoverableAccount.sol";

contract SocialRecoveryHelper is Deploy {
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
}