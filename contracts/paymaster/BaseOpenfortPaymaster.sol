// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.19;

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IEntryPoint, UserOperation, UserOperationLib} from "account-abstraction/interfaces/IEntryPoint.sol";
import "account-abstraction/core/Helpers.sol";
import {IBaseOpenfortPaymaster} from "../interfaces/IBaseOpenfortPaymaster.sol";
import {OpenfortErrorsAndEvents} from "../interfaces/OpenfortErrorsAndEvents.sol";

/**
 * Helper class for creating an Openfort paymaster.
 * Provides helper methods for staking.
 * Validates that the postOp is called only by the EntryPoint.
 */
abstract contract BaseOpenfortPaymaster is IBaseOpenfortPaymaster, Ownable2Step {
    uint256 private constant INIT_POST_OP_GAS = 40_000; // Initial value for postOpGas
    uint256 internal constant ADDRESS_OFFSET = 20; // length of an address
    IEntryPoint public immutable entryPoint;
    uint256 internal postOpGas; // Reference value for gas used by the EntryPoint._handlePostOp() method.

    /// @notice When the paymaster is deployed
    event PaymasterInitialized(IEntryPoint _entryPoint, address _owner);
    /// @notice When the paymaster owner updates the postOpGas variable
    event PostOpGasUpdated(uint256 oldPostOpGas, uint256 _newPostOpGas);

    constructor(IEntryPoint _entryPoint, address _owner) {
        if (address(_entryPoint) == address(0)) revert OpenfortErrorsAndEvents.ZeroValueNotAllowed();
        entryPoint = _entryPoint;
        _transferOwnership(_owner);
        postOpGas = INIT_POST_OP_GAS;
        emit PaymasterInitialized(_entryPoint, _owner);
    }

    /**
     * @inheritdoc IBaseOpenfortPaymaster
     */
    function validatePaymasterUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        external
        override
        returns (bytes memory context, uint256 validationData)
    {
        _requireFromEntryPoint();
        return _validatePaymasterUserOp(userOp, userOpHash, maxCost);
    }

    function _validatePaymasterUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        internal
        virtual
        returns (bytes memory context, uint256 validationData);

    /**
     * @inheritdoc IBaseOpenfortPaymaster
     */
    function postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost) external override {
        _requireFromEntryPoint();
        _postOp(mode, context, actualGasCost);
    }

    /**
     * post-operation handler.
     * (verified to be called only through the entryPoint)
     * @dev if subclass returns a non-empty context from validatePaymasterUserOp, it must also implement this method.
     * @param mode enum with the following options:
     *      opSucceeded - user operation succeeded.
     *      opReverted  - user op reverted. still has to pay for gas.
     *      postOpReverted - user op succeeded, but caused postOp (in mode=opSucceeded) to revert.
     *                       Now this is the 2nd call, after user's op was deliberately reverted.
     * @param context - the context value returned by validatePaymasterUserOp
     * @param actualGasCost - actual gas used so far (without this postOp call).
     */
    function _postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost) internal virtual;

    /**
     * Add a deposit for this paymaster, used for paying for transaction fees
     */
    function deposit() public payable virtual;

    /**
     * Withdraw value from the deposit.
     * @param _withdrawAddress - Target to send to
     * @param _amount          - Amount to withdraw
     */
    function withdrawTo(address payable _withdrawAddress, uint256 _amount) public virtual;

    /**
     * Add stake for this paymaster.
     * This method can also carry eth value to add to the current stake.
     * @param unstakeDelaySec - the unstake delay for this paymaster. Can only be increased.
     */
    function addStake(uint32 unstakeDelaySec) external payable onlyOwner {
        entryPoint.addStake{value: msg.value}(unstakeDelaySec);
    }

    /**
     * Return current paymaster's deposit on the EntryPoint.
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint.balanceOf(address(this));
    }

    /**
     * Unlock the stake, in order to withdraw it.
     * The paymaster can't serve requests once unlocked, until it calls addStake again
     */
    function unlockStake() external onlyOwner {
        entryPoint.unlockStake();
    }

    /**
     * Withdraw the entire paymaster's stake.
     * Stake must be unlocked first (and then wait for the unstakeDelay to be over)
     * @param withdrawAddress the address to send withdrawn value.
     */
    function withdrawStake(address payable withdrawAddress) external onlyOwner {
        entryPoint.withdrawStake(withdrawAddress);
    }

    /**
     * Validate the call is made from a valid entrypoint
     */
    function _requireFromEntryPoint() internal virtual {
        require(msg.sender == address(entryPoint), "Sender not EntryPoint");
    }

    /**
     * @dev Updates the reference value for gas used by the EntryPoint._handlePostOp() method.
     * @param _newPostOpGas The new postOpGas value.
     */
    function setPostOpGas(uint256 _newPostOpGas) external onlyOwner {
        if (_newPostOpGas == 0) revert OpenfortErrorsAndEvents.ZeroValueNotAllowed();
        emit PostOpGasUpdated(postOpGas, _newPostOpGas);
        postOpGas = _newPostOpGas;
    }
}
