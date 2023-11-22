// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {IBaseOpenfortAccount} from "./IBaseOpenfortAccount.sol";

interface IBaseRecoverableAccount is IBaseOpenfortAccount {
    error AccountLocked();
    error AccountNotLocked();
    error CannotUnlock();
    error DuplicatedGuardian();
    error DuplicatedProposal();
    error DuplicatedRevoke();
    error GuardianCannotBeOwner();
    error InsecurePeriod();
    error InvalidRecoverySignatures();
    error InvalidSignatureAmount();
    error MustBeGuardian();
    error NoOngoingRecovery();
    error OngoingRecovery();
    error PendingProposalExpired();
    error PendingProposalNotOver();
    error PendingRevokeExpired();
    error PendingRevokeNotOver();
    error UnknownProposal();
    error UnknownRevoke();

    event GuardianAdded(address indexed guardian);
    event GuardianProposalCancelled(address indexed guardian);
    event GuardianProposed(address indexed guardian, uint256 executeAfter);
    event GuardianRevocationCancelled(address indexed guardian);
    event GuardianRevocationRequested(address indexed guardian, uint256 executeAfter);
    event GuardianRevoked(address indexed guardian);
    event Locked(bool isLocked);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event RecoveryCancelled(address indexed recoveryAddress);
    event RecoveryCompleted(address indexed recoveryAddress);
    event RecoveryExecuted(address indexed recoveryAddress, uint64 executeAfter);

    receive() external payable;

    function acceptOwnership() external;
    function cancelGuardianProposal(address _guardian) external;
    function cancelGuardianRevocation(address _guardian) external;
    function cancelRecovery() external;
    function completeRecovery(bytes[] memory _signatures) external;
    function confirmGuardianProposal(address _guardian) external;
    function confirmGuardianRevocation(address _guardian) external;
    function getGuardians() external view returns (address[] memory);
    function getLock() external view returns (uint256 _releaseAfter);
    function guardianCount() external view returns (uint256);
    function isGuardian(address _guardian) external view returns (bool);
    function isGuardianOrGuardianSigner(address _guardian) external pure returns (bool _isGuardian);
    function isLocked() external view returns (bool);
    function lock() external;
    function proposeGuardian(address _guardian) external;
    function recoveryDetails()
        external
        view
        returns (address recoveryAddress, uint64 executeAfter, uint32 guardiansRequired);
    function renounceOwnership() external;
    function revokeGuardian(address _guardian) external;
    function startRecovery(address _recoveryAddress) external;
    function transferOwnership(address _newOwner) external;
    function unlock() external;
}
