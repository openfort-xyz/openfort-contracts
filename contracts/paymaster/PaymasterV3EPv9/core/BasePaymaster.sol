// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

/* solhint-disable reason-string */

import { ManagerAccessControl } from "./ManagerAccessControl.sol";
import { IEntryPoint } from "lib/account-abstraction-v09/contracts/interfaces/IEntryPoint.sol";

/**
 * Helper class for creating a paymaster.
 * provides helper methods for staking.
 * Validates that the postOp is called only by the entryPoint.
 */
abstract contract BasePaymaster is ManagerAccessControl {
    error BasePaymaster__SenderNotEntryPointV8();

    address public immutable OWNER;
    address public MANAGER;
    IEntryPoint public constant ENTRY_POINT_V9 = IEntryPoint(0x43370900c8de573dB349BEd8DD53b4Ebd3Cce709);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        CONSTRUCTOR                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
    constructor(address _owner, address _manager) {
        _grantRole(DEFAULT_ADMIN_ROLE, _owner);
        _grantRole(MANAGER_ROLE, _manager);
        OWNER = _owner;
        MANAGER = _manager;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    PUBLIC/EXTERNAL FUNC.                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
    /**
     * Add a deposit for this paymaster, used for paying for transaction fees.
     */
    function deposit() public payable {
        ENTRY_POINT_V9.depositTo{ value: msg.value }(address(this));
    }

    /**
     * Withdraw value from the deposit.
     * @param withdrawAddress - Target to send to.
     * @param amount          - Amount to withdraw.
     */
    function withdrawTo(address payable withdrawAddress, uint256 amount) public onlyRole(DEFAULT_ADMIN_ROLE) {
        ENTRY_POINT_V9.withdrawTo(withdrawAddress, amount);
    }

    /**
     * Add stake for this paymaster.
     * This method can also carry eth value to add to the current stake.
     * @param unstakeDelaySec - The unstake delay for this paymaster. Can only be increased.
     */
    function addStake(uint32 unstakeDelaySec) external payable onlyAdminOrManager {
        ENTRY_POINT_V9.addStake{ value: msg.value }(unstakeDelaySec);
    }

    /**
     * Unlock the stake, in order to withdraw it.
     * The paymaster can't serve requests once unlocked, until it calls addStake again
     */
    function unlockStake() external onlyAdminOrManager {
        ENTRY_POINT_V9.unlockStake();
    }

    /**
     * Withdraw the entire paymaster's stake.
     * stake must be unlocked first (and then wait for the unstakeDelay to be over)
     * @param withdrawAddress - The address to send withdrawn value.
     */
    function withdrawStake(address payable withdrawAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
        ENTRY_POINT_V9.withdrawStake(withdrawAddress);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          PURE/VIEW                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
    /**
     * Return current paymaster's deposit on the entryPoint.
     */
    function getDeposit() public view returns (uint256) {
        return ENTRY_POINT_V9.balanceOf(address(this));
    }

    /**
     * Validate the call is made from a valid entrypoint
     */
    function _requireFromEntryPoint() internal view virtual {
        require(msg.sender == address(ENTRY_POINT_V9), BasePaymaster__SenderNotEntryPointV8());
    }
}
