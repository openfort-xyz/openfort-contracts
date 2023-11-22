// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

interface IBaseOpenfortFactory {
    /// @notice Emitted when a new Account is created.
    event AccountCreated(address indexed account, address indexed accountAdmin);

    /// @notice Error when an address parameter is 0.
    error ZeroAddressNotAllowed();

    /// @notice Deploys a new Account for admin.
    function createAccountWithNonce(address _admin, bytes32 _nonce) external returns (address account);

    /// @notice Returns the address of the Account implementation.
    function implementation() external view returns (address);

    /// @notice Returns the address of an Account that would be deployed with the given admin and nonce.
    function getAddressWithNonce(address _admin, bytes32 _nonce) external view returns (address);

    /**
     * Add to the factory's stake - amount and delay
     * any pending unstake is first cancelled.
     * @param _unstakeDelaySec the new lock duration before the deposit can be withdrawn.
     */
    function addStake(uint32 _unstakeDelaySec) external payable;

    /**
     * Attempt to unlock the stake.
     * the value can be withdrawn (using withdrawStake) after the unstake delay.
     */
    function unlockStake() external;

    /**
     * Withdraw from the (unlocked) stake.
     * must first call unlockStake and wait for the unstakeDelay to pass
     * @param withdrawAddress the address to send withdrawn value.
     */
    function withdrawStake(address payable withdrawAddress) external;
}
