// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

// Base account contract to inherit from
import {BaseOpenfortAccount, IEntryPoint} from "../BaseOpenfortAccount.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

/**
  * @title UpgradeableOpenfortAccount
  * @author Eloi<eloi@openfort.xyz>
  * @notice Minimal smart contract wallet with session keys following the ERC-4337 standard.
  * It inherits from:
  *  - BaseOpenfortAccount
  */
contract UpgradeableOpenfortAccount is BaseOpenfortAccount, UUPSUpgradeable {
    constructor(IEntryPoint _entrypoint, address _factory) BaseOpenfortAccount(_entrypoint,  _factory){}
    
    function _authorizeUpgrade(address) internal override onlyOwner {}
}
