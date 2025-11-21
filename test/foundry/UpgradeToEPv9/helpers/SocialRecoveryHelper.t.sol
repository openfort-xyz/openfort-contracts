// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {Deploy} from "test/foundry/UpgradeToEPv9/Deploy.t.sol";
import {console2 as console} from "lib/forge-std/src/console2.sol";
import {BaseRecoverableAccount} from "contracts/coreV9/base/BaseRecoverableAccount.sol";
import {
    UpgradeableOpenfortAccount as UpgradeableOpenfortAccountV9
} from "contracts/coreV9/upgradeable/UpgradeableOpenfortAccount.sol";
import {MessageHashUtils} from "lib/oz-v5.4.0/contracts/utils/cryptography/MessageHashUtils.sol";

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

    bytes32 private constant RECOVER_TYPEHASH = 0x9f7aca777caf11405930359f601a4db01fad1b2d79ef3f2f9e93c835e9feffa5;
    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    string name = "Openfort";
    string version = "0.9";

    address[] internal _Guardians;
    uint256[] internal _GuardiansPK;
    address internal _RecoveryOwner;
    uint256 internal _RecoveryOwnerPK;
    bytes[] _signatures;

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
        if (action == GuardianAction.CONFIRM_PROPOSAL || action == GuardianAction.CONFIRM_REVOCATION) {
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
        bytes memory data = abi.encodeWithSelector(_randomOwner._RandomOwnerSC.proposeGuardian.selector, _guardian);
        _executeDirectCall(_randomOwner, data);
    }

    function _confirmGuardian(RandomOwner storage _randomOwner, address _guardian) internal {
        bytes memory data =
            abi.encodeWithSelector(_randomOwner._RandomOwnerSC.confirmGuardianProposal.selector, _guardian);
        _executeDirectCall(_randomOwner, data);
    }

    function _cancelGuardianProposal(RandomOwner storage _randomOwner, address _guardian) internal {
        bytes memory data =
            abi.encodeWithSelector(_randomOwner._RandomOwnerSC.cancelGuardianProposal.selector, _guardian);
        _executeDirectCall(_randomOwner, data);
    }

    function _revokeGuardian(RandomOwner storage _randomOwner, address _guardian) internal {
        bytes memory data = abi.encodeWithSelector(_randomOwner._RandomOwnerSC.revokeGuardian.selector, _guardian);
        _executeDirectCall(_randomOwner, data);
    }

    function _confirmGuardianRevocation(RandomOwner storage _randomOwner, address _guardian) internal {
        bytes memory data =
            abi.encodeWithSelector(_randomOwner._RandomOwnerSC.confirmGuardianRevocation.selector, _guardian);
        _executeDirectCall(_randomOwner, data);
    }

    function _cancelGuardianRevocation(RandomOwner storage _randomOwner, address _guardian) internal {
        bytes memory data =
            abi.encodeWithSelector(_randomOwner._RandomOwnerSC.cancelGuardianRevocation.selector, _guardian);
        _executeDirectCall(_randomOwner, data);
    }

    function _cancelRecovery(RandomOwner storage _randomOwner) internal {
        bytes memory data = abi.encodeWithSelector(_randomOwner._RandomOwnerSC.cancelRecovery.selector);
        _executeDirectCall(_randomOwner, data);
    }

    function _executeDirectCall(RandomOwner storage _randomOwner, bytes memory _data) internal {
        vm.prank(_randomOwner._RandomOwner);
        (bool success, bytes memory res) = address(_randomOwner._RandomOwnerSC).call{value: 0}(_data);
        if (!success) console.log(vm.toString(res));
    }

    function _executeConfirmRecovery(RandomOwner storage _randomOwner) internal {
        vm.warp(block.timestamp + RECOVERY_PERIOD + 1);
        vm.prank(_Guardians[0]);
        _randomOwner._RandomOwnerSC.completeRecovery(_signatures);
    }

    function _signGuardians(RandomOwner storage _randomOwner, uint32 _quorom) internal {
        (address recoveryAddress, uint64 executeAfter, uint32 guardiansRequired) =
            _randomOwner._RandomOwnerSC.recoveryDetails();
        if (_quorom < guardiansRequired) revert("Increase Quorom");

        bytes32 structHash = keccak256(abi.encode(RECOVER_TYPEHASH, recoveryAddress, executeAfter, guardiansRequired));

        bytes32 domainSeparator = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                block.chainid,
                address(_randomOwner._RandomOwnerSC)
            )
        );

        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);

        address[] memory sortedGuardians = new address[](_quorom);
        uint256[] memory sortedGuardiansPK = new uint256[](_quorom);

        for (uint256 i; i < _quorom;) {
            sortedGuardians[i] = _Guardians[i];
            sortedGuardiansPK[i] = _GuardiansPK[i];
            unchecked {
                ++i;
            }
        }

        for (uint256 i; i < sortedGuardians.length; ++i) {
            for (uint256 j = i + 1; j < sortedGuardians.length; ++j) {
                if (sortedGuardians[j] < sortedGuardians[i]) {
                    (sortedGuardians[i], sortedGuardians[j]) = (sortedGuardians[j], sortedGuardians[i]);
                    (sortedGuardiansPK[i], sortedGuardiansPK[j]) = (sortedGuardiansPK[j], sortedGuardiansPK[i]);
                }
            }
        }
        for (uint256 i; i < _quorom;) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(sortedGuardiansPK[i], digest);
            bytes memory sig = abi.encodePacked(r, s, v);
            _signatures.push(sig);

            unchecked {
                ++i;
            }
        }
    }
}
