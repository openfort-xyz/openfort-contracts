// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {IBaseRecoverableAccount} from "./IBaseRecoverableAccount.sol";

interface IUpgradeableOpenfortAccount is IBaseRecoverableAccount {
    function updateEntryPoint(address _newEntrypoint) external;
}
