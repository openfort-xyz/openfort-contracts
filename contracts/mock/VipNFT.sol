// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";

contract VIPNFT is ERC721 {
    constructor() ERC721("VIP", "VIP") {}

    function mint(address to, uint256 amount) external {
        _safeMint(to, amount);
    }
}
