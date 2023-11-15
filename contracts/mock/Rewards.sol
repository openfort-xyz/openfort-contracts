// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract Rewards is ERC20 {
    constructor() ERC20("GEMS", "GEMS") {}

    function claim(uint256 amount) external {
        _mint(msg.sender, amount);
    }
}
