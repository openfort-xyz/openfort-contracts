// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

interface OpenfortErrorsAndEvents {
    /// @notice Error when a parameter is 0.
    error ZeroValueNotAllowed();

    /// @notice Error when a function requires msg.value to be different than 0
    error MustSendNativeToken();

    /// @notice Error when a function requires msg.value to be different than owner()
    error OwnerNotAllowed();

    /// @notice Error when an address is not a contract.
    error NotAContract();

    error ZeroAddressNotAllowed();
    error NotOwnerOrEntrypoint();
    error NotOwner();
    error InvalidParameterLength();

    event AccountImplementationDeployed(address indexed creator);
    event SessionKeyRegistered(address indexed key);
    event SessionKeyRevoked(address indexed key);
    event EntryPointUpdated(address oldEntryPoint, address newEntryPoint);

    // Paymaster specifics

    /**
     * @notice Throws when trying to withdraw more than balance available
     * @param amountRequired required balance
     * @param currentBalance available balance
     */
    error InsufficientBalance(uint256 amountRequired, uint256 currentBalance);
}
