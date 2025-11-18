// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.29;

import {ERC20} from "lib/oz-v5.4.0/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    constructor() ERC20("MockERC20", "MC20") {}

    function mint(address sender, uint256 amount) external {
        _mint(sender, amount);
    }
}
