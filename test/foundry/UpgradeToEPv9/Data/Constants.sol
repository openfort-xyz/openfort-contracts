// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

abstract contract Constants {
    address constant internal ENTRY_POINT_V6 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    address constant internal ENTRY_POINT_V9 = 0x43370900c8de573dB349BEd8DD53b4Ebd3Cce709;

    uint256 public constant RECOVERY_PERIOD = 2 days;
    uint256 public constant SECURITY_PERIOD = 1.5 days;
    uint256 public constant SECURITY_WINDOW = 0.5 days;
    uint256 public constant LOCK_PERIOD = 5 days;
}