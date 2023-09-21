// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

interface OpenfortErrorsAndEvents {
    /// @notice Error when an address parameter is 0.
    error ZeroAddressNotAllowed();

    /// @notice Error when a function requires msg.value to be different than 0
    error MustSendNativeToken();
}
