// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";

// A simple ERC721 contract
contract SimpleNFT is ERC721 {
    uint256 public tokenId;

    constructor() ERC721("SimpleNFT", "SNFT") {}

    // Anyone can mint an NFT for anyone
    function mint(address _to) public {
        _safeMint(_to, ++tokenId);
    }
}
