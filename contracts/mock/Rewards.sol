// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract Rewards is ERC20 {
    constructor()
        // solhint-disable-next-line no-empty-blocks
        ERC20("GEMS", "GEMS")
    {}

    function claim() external {
        _mint(msg.sender, 10);
    }
}
