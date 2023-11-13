// SPDX-License-Identifier: UNLICENSED
pragma solidity =0.8.19;

/*
 * Based on Foundry's tutorial: https://book.getfoundry.sh/tutorials/testing-eip712
 * ToDo to clean the main testing contracts
 */
contract SigUtils {
    bytes32 private constant _TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    constructor() {}
}
