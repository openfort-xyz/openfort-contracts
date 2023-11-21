// SPDX-License-Identifier: GPL-3.0
pragma solidity =0.8.19;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

error InvalidImplementation();

/**
 * @title ERC6551OpenfortProxy (Non-upgradeable)
 * @notice Contract to create the ERC6551 proxies
 * It inherits from:
 *  - ERC1967Proxy
 */
contract ERC6551OpenfortProxy is ERC1967Proxy {
    address internal immutable defaultImplementation;

    constructor(address _logic, bytes memory _data) ERC1967Proxy(_logic, _data) {
        if (_logic == address(0)) revert InvalidImplementation();
        defaultImplementation = _logic;
    }

    // constructor(address _logic, bytes memory _data) ERC1967Proxy(_logic, _data) {}

    function implementation() external view returns (address) {
        return _implementation();
    }

    function _implementation() internal view virtual override returns (address implementationAddress) {
        implementationAddress = _getImplementation();
        if (implementationAddress == address(0)) return defaultImplementation;
    }

    function _beforeFallback() internal virtual override {
        super._beforeFallback();
        if (msg.data.length == 0) {
            if (_getImplementation() == address(0)) {
                _upgradeTo(defaultImplementation);
                _delegate(defaultImplementation);
            }
        }
    }
}
