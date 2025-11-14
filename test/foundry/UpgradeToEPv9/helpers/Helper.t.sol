// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import {Data} from "test/foundry/UpgradeToEPv9/Data/Data.t.sol";

abstract contract Helper is Data {
    function _deal(address _addr, uint256 _amount) internal {
        deal(_addr, _amount);
    }
}